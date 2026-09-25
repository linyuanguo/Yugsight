// engine.go 采集调度引擎: 秒级 tick 判定到期任务, 并发执行 + 限速 + 白名单,
// 产出统一 Round(入内存时序 + 注入落库), 并做异常事件判定。
//
// 与 scheduler(扫描队列)的边界: scheduler 是"一次性任务排队"(终态不重排),
// 本引擎是"周期轮询"(每 N 秒重复), 与 monitor 包同属轮询语义 —— 因此独立
// 循环, 不占用扫描并发槽位, 两者互不干扰。
//
// 循环形态: 单一 1s tick 统一判定所有任务到期(而不是每任务一个 timer) ——
// 任务增删/间隔修改都是配置热更新, 每任务 timer 需要频繁重建; 统一 tick
// 下"到期判定"只是一次时间比较, 增删任务零成本, 代码路径唯一。
package collect

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

// WriteHistory 一轮样本落库(装配层注入, 同 monitor 的 WriteHistory)。
type WriteHistory func(rounds []*Round)

// ReportSink 标准化输出的报告中心预留入口。
//
// 本阶段只预留不实现 AI/报告: 默认 NopSink 空转, 报告中心二期只需在装配层
// SetSink 注入实现, 采集链路零改动 —— 这就是"预留对接报告中心的入口"。
type ReportSink interface {
	OnRound(r *Round) // 一轮采集完成(全部任务, 成功与否都通知)
	OnEvent(e *Event) // 一条异常事件
}

// NopSink 默认空实现(阶段 1: 不生成任何报告)。
type NopSink struct{}

// OnRound 空实现。
func (NopSink) OnRound(*Round) {}

// OnEvent 空实现。
func (NopSink) OnEvent(*Event) {}

// Engine 采集引擎(并发安全)。
type Engine struct {
	mu       sync.RWMutex
	cfg      Config
	running  bool
	stopCh   chan struct{}
	store    *Store
	states   map[string]*eventState
	nextRun  map[string]time.Time
	limiter  *Limiter
	whitelist *Whitelist
	flows    *flowListener

	readCfg   func() Config
	write     WriteHistory
	sink      ReportSink
	eventHook func(*Event)
	logf      func(string)
}

// New 创建引擎(cfg 是启动快照, 之后以 readCfg 每 tick 重读为准)。
func New(cfg Config, readCfg func() Config, write WriteHistory) *Engine {
	return &Engine{
		cfg:       cfg.WithDefaults(),
		store:     NewStore(),
		states:    map[string]*eventState{},
		nextRun:   map[string]time.Time{},
		limiter:   NewLimiter(cfg.GlobalRate),
		whitelist: NewWhitelistEmpty(),
		flows:     newFlowListener(),
		readCfg:   readCfg,
		write:     write,
		sink:      NopSink{},
	}
}

// SetLogger 日志函数(不传则静默)。
func (e *Engine) SetLogger(f func(string)) { e.logf = f }

// SetSink 注入报告中心输出实现(阶段 1 保持 NopSink 默认即可)。
func (e *Engine) SetSink(s ReportSink) {
	if s == nil {
		s = NopSink{}
	}
	e.mu.Lock()
	e.sink = s
	e.mu.Unlock()
}

// SetEventHook 注入异常事件落地钩子(装配层: 落库 + SSE 广播)。
// 与 ReportSink 的区别: sink 是"标准化输出预留入口"(报告中心), eventHook
// 是"运维可见性"(落库可查 + 实时推送), 两者互不替代。
func (e *Engine) SetEventHook(f func(*Event)) {
	e.mu.Lock()
	e.eventHook = f
	e.mu.Unlock()
}

// emitEvent 一条事件的分发: 先报告预留入口, 再运维落地钩子(顺序无所谓,
// 各自 recover 由调用方注入的函数自保 —— 这里加顶层 recover 兜底, 防钩子
// panic 反噬采集循环, 与 probe taskRecorder 同口径)。
func (e *Engine) emitEvent(ev *Event) {
	e.mu.RLock()
	s := e.sink
	hook := e.eventHook
	e.mu.RUnlock()
	defer func() {
		if r := recover(); r != nil {
			e.logLine("事件分发异常(已隔离): " + fmt.Sprint(r))
		}
	}()
	s.OnEvent(ev)
	if hook != nil {
		hook(ev)
	}
}

// logLine 引擎内部日志(经注入函数, 未注入时静默)。
func (e *Engine) logLine(s string) {
	if e.logf != nil {
		e.logf(s)
	}
}

// SetConfig 内存更新配置(装配层在写盘成功后调用, 让下一 tick 立即生效)。
func (e *Engine) SetConfig(c Config) {
	e.mu.Lock()
	defer e.mu.Unlock()
	c = c.WithDefaults()
	e.applyConfigLocked(c)
}

// Config 当前配置副本。
func (e *Engine) Config() Config {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg
}

// Store 内存时序存储(装配层读最新值/历史用)。
func (e *Engine) Store() *Store { return e.store }

// FlowsListening 当前活跃的 NetFlow/IPFIX 监听地址(状态接口展示)。
func (e *Engine) FlowsListening() []string { return e.flows.listening() }

// Running 调度循环是否在跑。
func (e *Engine) Running() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.running
}

// Start 启动调度循环(幂等)。
func (e *Engine) Start() {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return
	}
	e.running = true
	e.stopCh = make(chan struct{})
	ch := e.stopCh
	e.mu.Unlock()
	go e.loop(ch)
	e.logLine("节点采集引擎已启动(1s tick 判定到期任务)")
}

// Stop 停止调度循环与全部监听(幂等)。
func (e *Engine) Stop() {
	e.mu.Lock()
	if !e.running {
		e.mu.Unlock()
		return
	}
	e.running = false
	close(e.stopCh)
	e.mu.Unlock()
	e.flows.stopAll()
	e.logLine("节点采集引擎已停止")
}

// applyConfigLocked 配置变更的落地: 限速器速率、白名单、netflow 监听对账。
func (e *Engine) applyConfigLocked(c Config) {
	e.cfg = c
	e.limiter.SetRate(c.GlobalRate)
	wl, bad := NewWhitelist(c.Whitelist)
	e.whitelist = wl
	if len(bad) > 0 {
		e.logLine("白名单存在无法解析的条目(已忽略): " + fmt.Sprint(bad))
	}
	// netflow 监听对账: 有启用的 netflow 任务就保证监听在, 没有就关。
	// 对账放在配置应用处而不是每 tick, 避免每 tick 都检查/操作 socket。
	e.reconcileNetFlowLocked(c)
}

// currentCfg 每 tick 重读配置(反映 UI 修改), 同时刷内存快照与应用副作用。
func (e *Engine) currentCfg() Config {
	var c Config
	if e.readCfg != nil {
		c = e.readCfg()
	} else {
		e.mu.RLock()
		c = e.cfg
		e.mu.RUnlock()
	}
	c = c.WithDefaults()
	e.mu.Lock()
	e.applyConfigLocked(c)
	e.mu.Unlock()
	return c
}

// loop 主循环: 1s tick, 到期任务并发执行。
func (e *Engine) loop(stopCh chan struct{}) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	for {
		select {
		case <-stopCh:
			return
		case <-tick.C:
			e.runDue()
		}
	}
}

// runDue 判定到期任务并执行。
func (e *Engine) runDue() {
	cfg := e.currentCfg()
	if !cfg.Enabled {
		return
	}
	now := time.Now()

	// 1) 收集到期任务(同时把删除的任务从状态里清掉, 防僵尸)
	e.mu.Lock()
	alive := map[string]bool{}
	var due []Task
	for i := range cfg.Tasks {
		t := cfg.Tasks[i]
		alive[t.ID] = true
		if !t.Enabled {
			continue
		}
		at, ok := e.nextRun[t.ID]
		if !ok {
			at = now // 首次到期: 立即跑一轮(与 monitor 启动即采同口径)
		}
		if !at.After(now) {
			due = append(due, t)
			e.nextRun[t.ID] = now.Add(cfg.TaskInterval(t))
		}
	}
	for id := range e.states {
		if !alive[id] {
			delete(e.states, id)
			delete(e.nextRun, id)
			e.store.Forget(id)
		}
	}
	e.mu.Unlock()

	if len(due) == 0 {
		return
	}

	// 2) 并发执行(信号量限并发; 白名单/限速在每任务执行前判)
	var wg sync.WaitGroup
	sem := make(chan struct{}, cfg.Concurrent)
	var mu sync.Mutex
	var rounds []*Round
	for _, t := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(t Task) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					e.logLine("任务 " + t.ID + " 采集异常(已隔离): " + fmt.Sprint(r))
					mu.Lock()
					rounds = append(rounds, &Round{
						ID: t.ID + "@" + fmt.Sprint(time.Now().UnixMilli()),
						TaskID: t.ID, Side: t.Side, Protocol: t.Protocol, Target: t.Target,
						At: time.Now(), OK: false, Err: "采集异常: " + fmt.Sprint(r),
					})
					mu.Unlock()
				}
			}()
			mu.Lock()
			rounds = append(rounds, e.runTask(context.Background(), cfg, t, false))
			mu.Unlock()
		}(t)
	}
	wg.Wait()

	// 3) 统一收尾: 事件判定 → 落库 → 报告预留 → 日志
	var events []Event
	for _, r := range rounds {
		e.mu.Lock()
		st := e.states[r.TaskID]
		if st == nil {
			st = &eventState{}
			e.states[r.TaskID] = st
		}
		e.mu.Unlock()
		events = append(events, DetectRound(st, cfg, r)...)
	}
	if len(rounds) > 0 && e.write != nil {
		e.write(rounds)
	}
	for _, ev := range events {
		e.emitEvent(&ev)
		e.logLine(fmt.Sprintf("[%s] %s %s: %s", ev.Level, ev.Type, ev.Target, ev.Msg))
	}
	// 只在有失败时打日志(与 monitor 同口径): 全成功的轮次每秒都可能出现,
	// 常态打日志会淹没真正需要看的事件。
	for _, r := range rounds {
		if !r.OK {
			e.logLine(fmt.Sprintf("采集失败 %s(%s %s): %s", r.TaskID, r.Protocol, r.Target, r.Err))
		}
	}
}

// runTask 执行单个任务(白名单 → 限速 → 采集)。
// manual = 手动"立即采集"(页面按钮): 显式用户动作, 低频, 不受全局限速
// 约束 —— 限速保护的是周期轮询对设备的压力, 用户点一下被静默跳过会让
// 页面显示"无数据"且查不到原因。单任务时限由 TaskTimeout 统一封顶(≤120s)。
func (e *Engine) runTask(ctx context.Context, cfg Config, t Task, manual bool) *Round {
	// 白名单: 只拦"发往目标"的协议; netflow 是被动接收, 目标(监听地址)不是
	// 采集对象, 不拦(否则配了白名单会让接收端永远不工作, 语义错位)。
	if ip, needCheck := targetIP(t); needCheck && !e.whitelistAllow(ip) {
		r := newRound(t, time.Now())
		r.OK = false
		r.Err = "目标不在采集白名单内"
		return r
	}
	// 限速: 取不到令牌 = 本轮跳过(下轮再试), 不算失败 —— 跳过的任务不产
	// 失败轮, 否则会触发离线误报。手动采集不受此约束。
	if !manual && !e.limiter.TryTake() {
		e.mu.Lock()
		e.nextRun[t.ID] = time.Now().Add(time.Second) // 下一秒再试
		e.mu.Unlock()
		e.logLine("全局限速生效, 任务 " + t.ID + " 本轮顺延")
		return nil
	}
	timeout := cfg.TaskTimeout(t)
	taskCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	t0 := time.Now()
	var r *Round
	e.mu.RLock()
	collector := collectors[t.Protocol]
	e.mu.RUnlock()
	if collector == nil {
		r = newRound(t, t0)
		r.OK = false
		r.Err = "未实现的采集协议: " + t.Protocol
	} else {
		r = collector(taskCtx, e, t)
		if r == nil {
			r = newRound(t, t0)
			r.OK = false
			r.Err = "采集器未返回结果"
		}
	}
	r.ElapsedMs = time.Since(t0).Milliseconds()
	e.store.Record(r)
	e.mu.Lock()
	s := e.sink
	e.mu.Unlock()
	s.OnRound(r)
	return r
}

// whitelistAllow 白名单判定(独立小函数便于测试)。
func (e *Engine) whitelistAllow(ip string) bool {
	e.mu.RLock()
	wl := e.whitelist
	e.mu.RUnlock()
	if wl == nil || wl.Empty() {
		return true
	}
	return wl.Allow(ip)
}

// targetIP 任务的"采集对象 IP"(需要白名单判定的); 第二返回值 = 是否需要判定。
// netflow 是监听型任务(不向外发), 不判定。
func targetIP(t Task) (string, bool) {
	if t.Protocol == ProtoNetFlow {
		return "", false
	}
	host := t.Target
	if i := strings.IndexByte(host, ':'); i > 0 {
		host = host[:i]
	}
	return host, true
}



// CollectNow 手动触发单个任务(页面"立即采集"), 不等 tick。
func (e *Engine) CollectNow(ctx context.Context, t Task) *Round {
	cfg := e.currentCfg()
	taskCtx, cancel := context.WithTimeout(ctx, cfg.TaskTimeout(t))
	defer cancel()
	r := e.runTask(taskCtx, cfg, t, true)
	if r != nil {
		e.mu.Lock()
		st := e.states[r.TaskID]
		if st == nil {
			st = &eventState{}
			e.states[r.TaskID] = st
		}
		events := DetectRound(st, cfg, r)
		e.mu.Unlock()
		for _, ev := range events {
			e.emitEvent(&ev)
		}
		if e.write != nil {
			e.write([]*Round{r})
		}
	}
	return r
}

// newRound 构造一轮的基础结构(采集器共用)。
func newRound(t Task, at time.Time) *Round {
	return &Round{
		ID:       t.ID + "@" + fmt.Sprint(at.UnixMilli()),
		TaskID:   t.ID,
		Side:     t.Side,
		Protocol: t.Protocol,
		Target:   t.Target,
		At:       at,
	}
}

// NewWhitelistEmpty 空白名单(放行一切), 供 New 初始化使用。
func NewWhitelistEmpty() *Whitelist {
	w, _ := NewWhitelist(nil)
	return w
}
