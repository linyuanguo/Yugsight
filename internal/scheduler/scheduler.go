package scheduler

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// ===== 调度器主体 =====
//
// 数据流:
//
//	Submit(提交) -> 入队 -> 调度循环 -> 拿到执行槽位 -> ExecFunc(执行) -> 回调(落库/广播)
//	                            |                                        |
//	                            +---- 暂停/取消 <-------------------- 用户操作
//
// 并发模型: "事件驱动 + 单调度循环"。
//
//	不用"每任务一个 goroutine 抢信号量"的原因: 探针节点并发限制是**按节点**的,
//	用信号量表达需要每个节点一个 channel, 节点动态增删时极易出错; 而且无法
//	实现"跳过队头找可执行任务"。单循环 + 条件变量让全部分支都集中在一处,
//	可读性与可测性都更好(扫描任务调度是低频操作, 单循环不会有性能问题)。

// ExecFunc 任务执行回调, 由装配层注入(本地扫描 / 探针下发)。
//
// 契约:
//   - 阻塞直到任务结束(调度器在独立 goroutine 里调用, 不阻塞调度循环);
//   - 通过 progress 上报进度(可被调用多次; 每次都会推 SSE 并更新任务);
//   - 返回 (结果摘要, 失败原因); 返回 error 时任务置 failed;
//   - 必须尊重 ctx 取消(调度器用 ctx 实现取消与超时)。
type ExecFunc func(ctx context.Context, t *Task, progress func(string)) (summary string, err error)

// Hook 调度事件观测点(装配层用于落库 + SSE 广播)。
type Hook func(Event)

// Scheduler 扫描任务调度器。
type Scheduler struct {
	mu  sync.Mutex
	cfg Config

	q       *queue
	nodes   *nodeRegistry
	limiter *RateLimiter
	exec    ExecFunc

	// tasks 全量任务表(ID -> 任务)。快照返回副本, 避免调用方直接改内部状态。
	tasks map[string]*Task
	// cancel 运行中任务的取消函数(暂停/取消/超时共用)。
	cancel map[string]context.CancelFunc
	// execGen 每个任务的执行代号: startTask 每次真正启动执行都会 +1。
	//
	// 【为什么需要它】同一个任务可以被多次执行(暂停后恢复、失败后重试), 会产生多个
	// 先后存在的执行协程。后启动的会把任务状态置为 running, 于是**先启动、迟到退出**
	// 的那个协程只看"当前状态"根本分不清自己是不是还在任 —— 它会以为自己有效,
	// 把状态改成 failed, 污染用户的操作结果(详见 finishStaleOrCancelled)。
	//
	// 代号让每个协程能自证身份: 捕获启动那一刻的 gen, 收尾时与表中当前值比对,
	// 不等即说明"我已被后来者取代"。
	execGen map[string]uint64
	// preSlots 已由 dispatch 预占槽位、但尚未在 startTask 登记 cancel 的任务。
	//
	// 存在的意义: 从"dispatch 取出队列"到"startTask 置 running"之间有一个窗口,
	// 此期间任务既不占 cancel 也不在队列 —— 用户此时暂停/取消会找不到任何
	// 可归还的对象, 槽位就此泄漏。preSlots 就是这段窗口的凭据。
	preSlots map[string]bool

	// periodics 周期任务(与扫描任务队列隔离, 见 periodic.go)。
	// 只在主循环 tick 分支被调度, Stop 后不再触发。
	periodics map[string]*periodicJob

	// slots 全局并发计数(运行中的任务数)。
	slots int
	// wake 调度唤醒信号(容量 1: 多次通知合并为一次, 避免无意义空转)。
	wake chan struct{}

	hooks []Hook

	started  bool
	closed   bool
	stopCh   chan struct{}
	wg       sync.WaitGroup
	nowFn    func() time.Time
	statsAll struct {
		total     int
		success   int
		failed    int
		cancelled int
		rejected  int
		reassign  int
	}
}

// New 构造调度器(不启动调度循环; 由 Start 启动)。
func New(cfg Config, exec ExecFunc) *Scheduler {
	cfg.normalize()
	s := &Scheduler{
		cfg:     cfg,
		q:       newQueue(),
		nodes:   newNodeRegistry(),
		limiter: NewRateLimiter(cfg.DefaultRate, cfg.RateRules),
		exec:    exec,
		tasks:    make(map[string]*Task),
		cancel:   make(map[string]context.CancelFunc),
		execGen:  make(map[string]uint64),
		preSlots: make(map[string]bool),
		wake:    make(chan struct{}, 1),
		stopCh:  make(chan struct{}),
		nowFn:   time.Now,
	}
	// 中心本地节点始终存在且在线: 单机部署时调度器也必须能工作(无需任何探针)
	s.nodes.Reset(nil)
	if cfg.LocalConcurrency > 0 {
		s.nodes.Upsert(Node{ID: NodeLocal, Name: "中心本地", Kind: NodeLocal, Online: true,
			MaxConcurrency: cfg.LocalConcurrency})
	}
	return s
}

// SetExec 注入/替换执行函数(装配层晚于 New 提供时使用)。
func (s *Scheduler) SetExec(f ExecFunc) {
	s.mu.Lock()
	s.exec = f
	s.mu.Unlock()
	s.Wake()
}

// OnEvent 注册事件观测点。
func (s *Scheduler) OnEvent(h Hook) {
	if h == nil {
		return
	}
	s.mu.Lock()
	s.hooks = append(s.hooks, h)
	s.mu.Unlock()
}

// Config 当前配置副本。
func (s *Scheduler) Config() Config {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cfg
}

// UpdateConfig 热更新配置(并发数/限速/队列上限), 立即生效。
//
// 并发数调大时唤醒调度循环: 否则要等下一个任务完成才会开新槽位。
func (s *Scheduler) UpdateConfig(cfg Config) {
	cfg.normalize()
	s.mu.Lock()
	s.cfg = cfg
	s.mu.Unlock()
	// 把本地节点并发上限同步到注册表(0 = 只受全局约束)
	s.nodes.Upsert(Node{ID: NodeLocal, Name: "中心本地", Kind: NodeLocal, Online: true,
		MaxConcurrency: cfg.LocalConcurrency})
	s.limiter.Update(cfg.DefaultRate, cfg.RateRules)
	s.Wake()
}

// Start 启动调度循环(幂等)。
func (s *Scheduler) Start() {
	s.mu.Lock()
	if s.started || s.closed {
		s.mu.Unlock()
		return
	}
	s.started = true
	interval := 500 * time.Millisecond
	s.wg.Add(1)
	s.mu.Unlock()
	go s.loop(interval)
	logf("调度器已启动: 全局并发 %d, 单节点并发 %d, 默认限速 %d pps",
		s.Config().MaxConcurrency, s.Config().NodeConcurrency, s.Config().DefaultRate)
}

// Stop 停止调度循环并取消所有运行中任务(进程退出路径)。
//
// 关键: 被中断的任务**不置终态**, 而是标成暂停(→ 可由 Resume 或下次启动的
// AutoStart 续扫)。理由: 进程正常退出时任务其实"没跑完", 若置成 failed,
// 重启后它就彻底消失了 —— 用户会以为"这个任务已经失败过、不用管了",
// 而任务书要求"任务中断支持续扫"。只有用户显式取消/执行器真的报错才算终态。
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	close(s.stopCh)
	cancels := make([]context.CancelFunc, 0, len(s.cancel))
	for _, c := range s.cancel {
		cancels = append(cancels, c)
	}
	// 有意在解锁前就把状态改成 paused: 执行器收到 ctx 取消后会调 finish,
	// finish 见到非 running 状态即不改写(用户/系统操作优先于执行结果)。
	for _, t := range s.tasks {
		if t.Status == StatusRunning {
			t.Status = StatusPaused
			t.Progress = "进程停止, 已中断(重启后可续扫)"
		}
	}
	s.mu.Unlock()
	for _, c := range cancels {
		c()
	}
	s.wg.Wait()
}

// Wake 唤醒调度循环(提交/完成/配置变更时调用)。
func (s *Scheduler) Wake() {
	select {
	case s.wake <- struct{}{}:
	default: // 已有待处理信号, 无需重复
	}
}

// loop 调度主循环。
//
// 双触发: 事件唤醒(提交/完成/节点变化) + 定时兜底(节点负载下降、超时回收)。
// 定时兜底不可省: 探针 CPU 回落到阈值以下这件事不产生任何事件, 只能靠轮询发现。
func (s *Scheduler) loop(interval time.Duration) {
	defer s.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.stopCh:
			return
		case <-s.wake:
			s.dispatch()
		case <-t.C:
			s.dispatch()
			s.runPeriodics()
		}
	}
}

// dispatch 尝试把队列里的任务派发出去, 直到无槽位或无任务。
func (s *Scheduler) dispatch() {
	defer func() {
		// 调度循环绝不允许 panic 逃出(会带走整个进程): 单个任务异常只应影响该任务
		if p := recover(); p != nil {
			logf("调度循环异常(已恢复): %v", p)
		}
	}()
	for {
		s.mu.Lock()
		if s.closed || s.exec == nil {
			s.mu.Unlock()
			return
		}
		cfg := s.cfg
		// 全局并发闸门
		if cfg.MaxConcurrency > 0 && s.slots >= cfg.MaxConcurrency {
			s.mu.Unlock()
			return
		}
		acc := cfg.AcceptConfig()
		// 挑选"节点可接纳"的首个任务; 队头节点已满时继续找后面的任务, 避免队头阻塞
		t := s.q.Pick(func(t *Task) bool {
			return s.nodes.canAccept(t.Node, t.Kind, t.Params.Capture, acc)
		})
		if t == nil {
			s.mu.Unlock()
			return
		}
		s.slots++
		s.nodes.incRunning(t.Node)
		s.preSlots[t.ID] = true // 槽位预占凭据(见 preSlots 注释)
		s.mu.Unlock()

		s.startTask(t)
	}
}

// startTask 启动单个任务的执行 goroutine。
func (s *Scheduler) startTask(t *Task) {
	s.mu.Lock()
	// 取出到启动之间的窗口里, 任务可能已被用户暂停/取消(状态已变)或调度器已停止。
	// 必须复查状态: 否则会"启动一个已被取消的任务"(用户看到任务被取消了却还在跑),
	// 且它结束后会把已归还的槽位再回收一次, 导致并发计数错乱。
	if s.closed {
		delete(s.preSlots, t.ID)
		if s.slots > 0 {
			s.slots--
		}
		s.nodes.decRunning(t.Node)
		s.mu.Unlock()
		return
	}
	if t.Status != StatusQueued {
		delete(s.preSlots, t.ID)
		if s.slots > 0 {
			s.slots--
		}
		s.nodes.decRunning(t.Node)
		s.mu.Unlock()
		return
	}
	delete(s.preSlots, t.ID)
	timeout := time.Duration(s.cfg.TaskTimeoutSec) * time.Second
	exec := s.exec
	now := s.nowFn()
	t.Status = StatusRunning
	t.StartAt = now
	if !t.QueueAt.IsZero() {
		t.QueuedMs = now.Sub(t.QueueAt).Milliseconds()
	}
	t.Attempts++
	ctx, cancel := context.WithCancel(context.Background())
	if timeout > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeout(ctx, timeout)
		prev := cancel
		cancel = func() { cancelTimeout(); prev() }
	}
	s.cancel[t.ID] = cancel
	// 分配本次执行的代号: 让这个协程日后能自证"我还是不是当前那一个"
	s.execGen[t.ID]++
	gen := s.execGen[t.ID]
	s.mu.Unlock()

	s.emit(Event{Type: EventStarted, TaskID: t.ID, Kind: t.Kind, Target: t.Target, Node: nodeIDOf(t.Node)})
	go func() {
		defer func() {
			if p := recover(); p != nil {
				s.finish(t.ID, StatusFailed, "", fmt.Sprintf("执行异常: %v", p))
			}
		}()
		progress := func(msg string) { s.progress(t.ID, msg) }
		summary, err := exec(ctx, t, progress)
		cancel()
		if err != nil {
			// 【ctx 被取消 ≠ 任务失败; 且"过期的执行协程"不得改状态】
			//
			// 实测踩到的真实缺陷(全量并发跑测试时约 6-8% 概率复现, 单独跑从不复现):
			// 用户"暂停 -> 恢复 -> 取消"三步操作, 最终状态竟是 failed。
			//
			// 时序(pause 故意在解锁后才 cancel, 见 Pause 的 StatusRunning 分支):
			//
			//	1. Pause: 置 paused -> 归还槽位 -> 解锁 -> cancel() 触发旧协程退出
			//	2. Resume: 置 queued -> 重新入队(旧协程**可能还没跑到 finish**)
			//	3. 调度器重新领走 -> 置 running -> 起新协程
			//	4. 旧协程这时才返回: ctx.Err()=Canceled -> finish(failed)
			//	   此时状态已是 running, finish 的终态保护不生效 -> 被覆盖成 failed
			//
			// 关键认识: 旧协程与新协程共用同一个 task.ID, 靠"任务当前状态"无法区分
			// 自己是不是那一个"现在有效的"协程 —— 必须用 **ctx 身份**来判定。
			//
			// 判据: 拿当前 ctx 与 s.cancel[id] 里登记的比较, 不同说明自己已过期
			// (被 pause/cancel 换成了新的), 此时**放弃一切状态写入** ——
			// 槽位与状态都由新协程或控制操作负责。
			if ctx.Err() != nil {
				s.finishStaleOrCancelled(t.ID, gen, err, summary)
				return
			}
			s.finish(t.ID, StatusFailed, summary, err.Error())
			return
		}
		s.finish(t.ID, StatusSuccess, summary, "")
	}()
}

// finishStaleOrCancelled 处理"执行因 ctx 取消而中断"的收尾。
//
// 【判据: 执行代号, 而不是任务状态】这是本函数存在的全部理由。
//
// 旧版本用"任务当前状态是否仍是 running"来判断"有没有人来认领", 这在
// **暂停 -> 恢复 -> 取消**这种多轮操作下会失效: 旧协程与新协程共用同一个
// task.ID, 当旧协程迟到时看到的状态是"新协程刚置的 running", 于是它以为自己
// 是当前有效的执行者, 大方地把状态写成 failed —— 把用户的三步操作结果污染成"失败"。
//
// 实测复现率约 6-8%(仅在全量并发跑测试时, CPU 争抢把 pause 与 resume 之间的窗口
// 拉开才暴露; 单独跑 20 次一次不复现), 诊断信息是:
//
//	内部状态=failed err="context canceled" progress="已暂停(执行已中断, 恢复时将续扫)"
//
// progress 文案还停留在 Pause 设的那句, 而状态已是 failed —— 两个不同"世代"的
// 写入混在了一起, 这就是世代判定缺失的直接证据。
//
// 用法: startTask 每次真正启动执行都会 gen[id]++, 协程捕获自己的代号; 收尾时
// 代号不匹配即说明"我已被后来者取代", 直接退出。
//
// 【为什么用整数代号而不是比较 ctx/cancel func】Go 的函数值不可比较(只能与 nil),
// context 接口的底层类型是实现细节; 而整数比较无歧义、无锁外依赖, 也不怕将来
// 换掉 cancel 的实现方式。
//
// 三种情形:
//  1. 代号已过期(被 pause/cancel/retry 换掉): 完全退出, 不碰任何状态与槽位 ——
//     它们归新的执行者或那个控制操作管, 插手就是污染;
//  2. 代号仍是当前的, 但任务已被控制操作置为终态/暂停(如 Cancel 先改状态再触发
//     取消): 只做幂等的槽位回收, 不改状态;
//  3. 代号仍是当前的, 且任务仍 running: 无人认领, 属超时或内部取消 ——
//     记 failed 并保留原因(用户需要看到"超时"而不是永远转圈)。
func (s *Scheduler) finishStaleOrCancelled(id string, gen uint64, err error, summary string) {
	s.mu.Lock()
	t, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	// 情形 1: 过期协程, 立即退出(关键修复点)
	if s.execGen[id] != gen {
		s.mu.Unlock()
		return
	}
	// 情形 2: 已被控制操作认领 —— 状态已由对方设定, 只做幂等槽位回收。
	// releaseSlotLocked 是幂等的: Cancel/Pause 可能已经归还过, 重复调用无害。
	if Terminal(t.Status) || t.Status == StatusPaused {
		s.releaseSlotLocked(t)
		s.mu.Unlock()
		return
	}
	s.mu.Unlock()
	// 情形 3: 无人认领, 记失败并保留原因
	reason := "任务被中断"
	if err != nil {
		reason = err.Error()
	}
	s.finish(id, StatusFailed, summary, reason)
}

// progress 更新任务进度并广播。
func (s *Scheduler) progress(id, msg string) {
	if msg == "" {
		return
	}
	s.mu.Lock()
	t, ok := s.tasks[id]
	if !ok || t.Status != StatusRunning {
		s.mu.Unlock()
		return
	}
	t.Progress = msg
	kind, target, node := t.Kind, t.Target, t.Node
	s.mu.Unlock()
	s.emit(Event{Type: EventProgress, TaskID: id, Kind: kind, Target: target, Node: nodeIDOf(node), Msg: msg})
}

// finish 收尾: 释放槽位 + 置终态 + 广播(幂等, 重复调用无害)。
func (s *Scheduler) finish(id, status, summary, errMsg string) {
	s.mu.Lock()
	t, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return
	}
	// 已终态(用户取消/暂停)时不覆盖: 用户操作优先于执行结果
	if Terminal(t.Status) {
		s.mu.Unlock()
		return
	}
	// 暂停中收到的执行结果同样不覆盖 —— 暂停语义是"我主动中止了它"
	if t.Status == StatusPaused {
		s.mu.Unlock()
		return
	}
	s.releaseSlotLocked(t)
	t.Status = status
	t.EndAt = s.nowFn()
	if !t.StartAt.IsZero() {
		t.RunMs = t.EndAt.Sub(t.StartAt).Milliseconds()
	}
	if summary != "" {
		t.Result = summary
	}
	t.Err = errMsg
	switch status {
	case StatusSuccess:
		s.statsAll.success++
		t.Err = ""
	case StatusFailed:
		s.statsAll.failed++
		if t.Result == "" {
			t.Result = errMsg
		}
	}
	// 自动重分配(任务书: 支持任务重分配): 失败且允许重试、且还有剩余尝试次数
	// 时换一个节点重新入队。仅探针任务重分配 —— 本地任务失败通常是目标/参数问题,
	// 换节点无从谈起。
	reassign := false
	if status == StatusFailed && t.AutoRetry && t.Node != "" &&
		t.Attempts < s.maxAttemptsLocked() {
		if newNode, rej := s.nodes.RecommendNode(s.cfg.AcceptConfig(), t.Params.Capture,
			map[string]bool{t.Node: true}); rej == nil && newNode != "" && newNode != t.Node {
			t.Node = newNode
			t.Status = StatusQueued
			t.QueueAt = s.nowFn()
			t.Result = ""
			t.Err = ""
			s.statsAll.reassign++
			reassign = true
		}
	}
	if reassign {
		s.q.Push(t)
	}
	kind, target, node := t.Kind, t.Target, t.Node
	finalStatus := t.Status
	s.mu.Unlock()

	if reassign {
		s.emit(Event{Type: EventReassign, TaskID: id, Kind: kind, Target: target, Node: node,
			Msg: "任务失败, 已重新分配到节点 " + node + " (第 " + itoa(t.Attempts) + " 次尝试)"})
	} else {
		s.emit(Event{Type: EventDone, TaskID: id, Kind: kind, Target: target, Node: nodeIDOf(node),
			Msg: finalStatus + ": " + firstNonEmpty(summary, errMsg)})
	}
	s.Wake()
}

func (s *Scheduler) maxAttemptsLocked() int {
	if s.cfg.MaxAttempts <= 0 {
		return 1
	}
	return s.cfg.MaxAttempts
}

// emit 广播事件(单 hook 异常不影响其它 hook)。
func (s *Scheduler) emit(e Event) {
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	s.mu.Lock()
	hooks := make([]Hook, len(s.hooks))
	copy(hooks, s.hooks)
	s.mu.Unlock()
	for _, h := range hooks {
		func() {
			defer func() {
				if p := recover(); p != nil {
					logf("调度事件回调异常(已恢复): %v", p)
				}
			}()
			h(e)
		}()
	}
}

func nodeIDOf(id string) string {
	if id == "" {
		return NodeLocal
	}
	return id
}

func firstNonEmpty(a ...string) string {
	for _, s := range a {
		if s != "" {
			return s
		}
	}
	return ""
}
