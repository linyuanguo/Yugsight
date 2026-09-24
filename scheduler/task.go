package scheduler

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"sync/atomic"
	"time"
)

// ===== 任务提交 =====

// SubmitRequest 提交一个扫描任务的请求(API 层直接映射)。
type SubmitRequest struct {
	Kind     string `json:"kind"`
	Target   string `json:"target"`
	Strategy string `json:"strategy"`
	Params   Params `json:"params"`
	// Node 执行节点: 空 = 中心本地(默认); "auto" = 由调度器挑最空闲探针;
	// 其它值 = 指定探针 ID。
	Node     string `json:"node"`
	Priority int    `json:"priority"`
	// AutoRetry 节点离线/执行失败时自动换节点重试(默认 true, 探针任务才有意义)。
	AutoRetry *bool `json:"autoRetry"`
}

// Submit 提交任务入队。
//
// 返回值 error 的语义:
//   - ErrQueueFull: 队列满, 调用方应提示用户稍后再试;
//   - 其它: 参数非法(无目标/未知类型)。
//
// 注意: 提交**不表示立即执行** —— 任务先入队, 由调度循环按并发/节点/限速
// 条件派发。API 层应把"已入队 (队列位置 N)"如实告知用户, 而不是假装已开始。
func (s *Scheduler) Submit(req SubmitRequest) (*Task, error) {
	kind := strings.ToLower(strings.TrimSpace(req.Kind))
	switch kind {
	case "ip", "alive":
		kind = "ip"
	case "port", "web", "host", "unified":
	default:
		return nil, fmt.Errorf("scheduler: 不支持的扫描类型 %q (可用: ip/port/web/host/unified)", req.Kind)
	}

	// 策略模板展开: 用户显式参数优先于模板默认值
	strategyID := strings.TrimSpace(req.Strategy)
	s.mu.Lock()
	if strategyID == "" {
		strategyID = s.cfg.DefaultStrategy
	}
	maxQueue := s.cfg.MaxQueue
	s.mu.Unlock()
	if StrategyByID(strategyID) == nil && strategyID != StrategyCustom {
		strategyID = StrategyCustom
	}

	p := Apply(strategyID, req.Params)
	p = normalizeTarget(kind, p, req.Target)
	target := displayTarget(kind, p)
	if target == "" {
		return nil, fmt.Errorf("scheduler: 扫描目标不能为空")
	}

	// 节点解析: auto -> 挑最空闲探针(无探针则回落本地)
	node := strings.TrimSpace(req.Node)
	if strings.EqualFold(node, "auto") {
		s.mu.Lock()
		acc := s.cfg.AcceptConfig()
		s.mu.Unlock()
		if id, rej := s.nodes.RecommendNode(acc, p.Capture, nil); rej == nil {
			node = id
		} else {
			// 无可用探针时不报错: 回落中心本地执行(单机部署是主场景)
			logf("无可用探针节点(原因: %s), 任务回落中心本地执行", rej.Msg)
			node = ""
		}
	}

	id := newTaskID()
	now := s.nowFn()
	autoRetry := node != ""
	if req.AutoRetry != nil {
		autoRetry = *req.AutoRetry
	}
	t := &Task{
		ID:        id,
		Kind:      kind,
		Target:    target,
		Strategy:  strategyID,
		Params:    p,
		Node:      node,
		Priority:  req.Priority,
		Status:    StatusQueued,
		CreatedAt: now,
		QueueAt:   now,
		AutoRetry: autoRetry,
	}

	// 队列上限判定与入队必须原子: 否则并发提交时可能都读到"未满"而一起入队。
	// 注意 emit 不能在持锁时调用 —— hook 由装配层实现(会落库/推 SSE), 存在
	// 再次获取调度器锁的可能, 持锁回调就是死锁。故此处内联校验并显式解锁。
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, fmt.Errorf("scheduler: 调度器已停止")
	}
	if maxQueue > 0 && s.q.Len() >= maxQueue {
		s.statsAll.rejected++
		s.mu.Unlock()
		return nil, ErrQueueFull
	}
	s.tasks[id] = t
	s.q.Push(t)
	pos := s.q.Len()
	s.statsAll.total++
	s.mu.Unlock()

	s.emit(Event{Type: EventQueued, TaskID: id, Kind: kind, Target: target,
		Node: nodeIDOf(node), Msg: fmt.Sprintf("已入队(队列位置 %d, 策略 %s)", pos, strategyID)})
	s.Wake()
	return t, nil
}

// normalizeTarget 按类型把用户给的 target 填到 Params 的对应字段。
//
// 为什么在这里做: API 层只传一个 target 字符串(用户视角), 而执行层需要
// 区分 CIDR/IP/URL(不同扫描器函数签名不同)。归一化集中在此, 避免每个
// 执行分支各写一遍判空逻辑。
func normalizeTarget(kind string, p Params, target string) Params {
	t := strings.TrimSpace(target)
	if t == "" {
		t = firstNonEmpty(p.Target, p.CIDR, p.IP, p.URL)
	}
	p.Target = t
	switch kind {
	case "ip", "unified":
		if p.CIDR == "" {
			p.CIDR = t
		}
	case "web":
		if p.URL == "" {
			p.URL = t
		}
	case "port", "host":
		if p.IP == "" {
			p.IP = t
		}
	}
	return p
}

// displayTarget 展示用目标串。
func displayTarget(kind string, p Params) string {
	switch kind {
	case "ip", "unified":
		return firstNonEmpty(p.CIDR, p.Target)
	case "web":
		return firstNonEmpty(p.URL, p.Target)
	default:
		return firstNonEmpty(p.IP, p.Target)
	}
}

// ===== 任务控制 =====

// Get 取任务副本。
func (s *Scheduler) Get(id string) (*Task, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return nil, false
	}
	cp := *t
	cp.Params.Skip = append([]string(nil), t.Params.Skip...)
	cp.ResumeDone = append([]string(nil), t.ResumeDone...)
	return &cp, true
}

// List 任务列表(倒序: 最新在前; status 非空时按状态过滤)。
//
// 列表口径 = **全量任务表**倒序。不能只遍历 order(提交顺序表): order 是
// "已产生终态的任务"补录表, 一个任务从提交到被调度器取出前都不在 order 里 ——
// 若以 order 为唯一来源, 排队中/运行中的任务会在列表里"消失"(前端看到
// "提交成功但列表里没有"), 这是最难排查的一类"数据不见了"缺陷。
// 因此这里以 tasks(map) 为唯一真相来源, 按提交时间倒序, 与 order 无关。
func (s *Scheduler) List(status string, page, size int) ([]*Task, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		if status != "" && t.Status != status {
			continue
		}
		all = append(all, copyTask(t))
	}
	// 倒序: 创建时间新者在前; 时间相同(同纳秒提交, 极罕见)按 ID 兜底保证稳定
	sort.Slice(all, func(i, j int) bool {
		if !all[i].CreatedAt.Equal(all[j].CreatedAt) {
			return all[i].CreatedAt.After(all[j].CreatedAt)
		}
		return all[i].ID > all[j].ID
	})
	total := len(all)
	if page > 0 && size > 0 {
		start := (page - 1) * size
		if start >= len(all) {
			return []*Task{}, total
		}
		end := start + size
		if end > len(all) {
			end = len(all)
		}
		all = all[start:end]
	}
	return all, total
}

func copyTask(t *Task) *Task {
	cp := *t
	cp.Params.Skip = append([]string(nil), t.Params.Skip...)
	cp.ResumeDone = append([]string(nil), t.ResumeDone...)
	return &cp
}

// Queued 队列快照(等待中的任务, 按调度顺序)。
func (s *Scheduler) Queued() []*Task {
	items := s.q.Snapshot()
	out := make([]*Task, len(items))
	for i, t := range items {
		out[i] = copyTask(t)
	}
	return out
}

// Pause 暂停任务。
//
// 语义: 三种情形都支持 ——
//
//	排队中: 直接摘出队列置暂停(不占槽位, 恢复时按当前时间重新排队)
//	运行中: 取消执行(ctx cancel)并置暂停, 已收集的部分结果由执行器决定是否回传
//	已暂停/终态: 幂等返回(不报错)
//
// 注意"暂停 = 释放执行槽位": 暂停的任务不应继续占用并发额度, 否则一个被暂停
// 的大任务会长期堵住后面的任务 —— 这是很多调度器实现里容易忽略的点。
func (s *Scheduler) Pause(id string) error {
	s.mu.Lock()
	t, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	switch t.Status {
	case StatusPaused:
		s.mu.Unlock()
		return nil
	case StatusQueued:
		// 队列里没有它 -> 说明 dispatch 已把它取出(槽位预占中), 这段窗口期必须
		// 把槽位还回去, 否则槽位永久泄漏, 表现为"暂停一次后队列再也不流动"。
		// 用任务状态而非 s.cancel 判定: 状态置为 paused 后, startTask 会自行
		// 识别并放弃启动(见 startTask 里的状态复查)。
		if s.q.Remove(id) {
			t.Progress = "已从队列暂停"
		} else {
			s.releaseSlotLocked(t)
			t.Progress = "已暂停(取出过程中中断)"
		}
		t.Status = StatusPaused
		s.mu.Unlock()
		s.emit(Event{Type: EventPaused, TaskID: id, Kind: t.Kind, Target: t.Target, Node: nodeIDOf(t.Node),
			Msg: "已从队列暂停"})
		s.Wake()
		return nil
	case StatusRunning:
		cancel := s.cancel[id]
		t.Status = StatusPaused
		t.Progress = "已暂停(执行已中断, 恢复时将续扫)"
		s.releaseSlotLocked(t)
		s.mu.Unlock()
		if cancel != nil {
			cancel() // 触发执行器 ctx 取消; 槽位已在此处归还, finish 不会再重复回收
		}
		s.emit(Event{Type: EventPaused, TaskID: id, Kind: t.Kind, Target: t.Target, Node: nodeIDOf(t.Node),
			Msg: "执行已暂停, 恢复后继续"})
		return nil
	default:
		s.mu.Unlock()
		return fmt.Errorf("%w: 任务已%s, 无法暂停", ErrUnknownStatus, statusName(t.Status))
	}
}

// Resume 恢复任务(重新入队)。
//
// 续扫: 把暂停时已知的已完成目标传入 Params.Skip, 执行器支持时会跳过它们
// (见 Params.Skip 注释)。队列中暂停的任务没有"已完成目标", Skip 为空。
func (s *Scheduler) Resume(id string) error {
	s.mu.Lock()
	t, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	if t.Status != StatusPaused {
		s.mu.Unlock()
		return fmt.Errorf("%w: 只有暂停中的任务可以恢复(当前%s)", ErrUnknownStatus, statusName(t.Status))
	}
	t.Status = StatusQueued
	t.QueueAt = s.nowFn()
	s.q.Push(t)
	s.mu.Unlock()
	s.emit(Event{Type: EventResumed, TaskID: id, Kind: t.Kind, Target: t.Target, Node: nodeIDOf(t.Node),
		Msg: "已恢复并重新排队"})
	s.Wake()
	return nil
}

// Cancel 取消任务(排队中/运行中/暂停中都可)。
func (s *Scheduler) Cancel(id string) error {
	s.mu.Lock()
	t, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	if Terminal(t.Status) {
		s.mu.Unlock()
		return nil // 幂等: 已结束的任务再取消无意义
	}
	wasRunning := t.Status == StatusRunning
	if t.Status == StatusQueued {
		s.q.Remove(id)
	}
	cancel := s.cancel[id]
	t.Status = StatusCancelled
	t.EndAt = s.nowFn()
	t.Progress = "用户取消"
	s.releaseSlotLocked(t)
	s.statsAll.cancelled++
	kind, target, node := t.Kind, t.Target, t.Node
	s.mu.Unlock()

	if cancel != nil {
		cancel()
	}
	msg := "已取消"
	if wasRunning {
		msg = "已取消(执行中的任务已中断)"
	}
	s.emit(Event{Type: EventCancelled, TaskID: id, Kind: kind, Target: target, Node: nodeIDOf(node), Msg: msg})
	s.Wake()
	return nil
}

// Delete 删除任务记录(仅终态可删, 避免误删运行中任务导致状态丢失)。
func (s *Scheduler) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tasks[id]
	if !ok {
		return ErrNotFound
	}
	if !Terminal(t.Status) && t.Status != StatusPaused {
		return fmt.Errorf("%w: 任务%s中, 请先取消再删除", ErrUnknownStatus, statusName(t.Status))
	}
	delete(s.tasks, id)
	return nil
}

// Retry 手动把失败/取消的任务重新入队(任务书: 支持任务重分配的手动路径)。
func (s *Scheduler) Retry(id string) error {
	s.mu.Lock()
	t, ok := s.tasks[id]
	if !ok {
		s.mu.Unlock()
		return ErrNotFound
	}
	switch t.Status {
	case StatusFailed, StatusCancelled:
	default:
		s.mu.Unlock()
		return fmt.Errorf("%w: 只有失败/已取消的任务可以重试(当前%s)", ErrUnknownStatus, statusName(t.Status))
	}
	// 重试时重新选节点: 原节点很可能就是失败原因(离线/过载)
	if t.Node != "" {
		if newNode, rej := s.nodes.RecommendNode(s.cfg.AcceptConfig(), t.Params.Capture, nil); rej == nil && newNode != "" {
			t.Node = newNode
		}
	}
	t.Status = StatusQueued
	t.QueueAt = s.nowFn()
	t.Result = ""
	t.Err = ""
	t.Progress = "已重新入队"
	t.EndAt = time.Time{}
	s.q.Push(t)
	s.statsAll.total++
	s.mu.Unlock()
	s.emit(Event{Type: EventQueued, TaskID: id, Kind: t.Kind, Target: t.Target, Node: nodeIDOf(t.Node),
		Msg: "重试: 已重新入队"})
	s.Wake()
	return nil
}

// ===== 节点管理(供装配层同步探针状态) =====

// SyncNodes 用探针中心端的实时视图整体刷新节点表。
func (s *Scheduler) SyncNodes(list []Node) {
	s.nodes.Reset(list)
	s.Wake()
}

// UpsertNode 更新单个节点(探针上线/心跳时调用)。
func (s *Scheduler) UpsertNode(n Node) {
	s.nodes.Upsert(n)
	s.Wake()
}

// RemoveNode 摘除节点(探针被删除时调用)。
func (s *Scheduler) RemoveNode(id string) {
	s.nodes.Remove(id)
	s.Wake()
}

// RecommendNode 挑一个可用探针(前端"自动选择节点"时预览用)。
func (s *Scheduler) RecommendNode(needCapture bool) (string, *RejectReason) {
	return s.nodes.RecommendNode(s.Config().AcceptConfig(), needCapture, nil)
}

// Nodes 节点视图快照(前端展示负载与槽位占用)。
func (s *Scheduler) Nodes() []NodeView {
	cfg := s.Config()
	views := s.nodes.Snapshot()
	for i := range views {
		views[i].Max = views[i].Node.effectiveMax(cfg.NodeConcurrency)
		// 本地节点未单独配置时, 实际约束是全局并发(见 nodeRegistry.Accept)
		if views[i].Kind == NodeLocal && views[i].Node.MaxConcurrency <= 0 {
			views[i].Max = cfg.MaxConcurrency
		}
	}
	return views
}

// CheckNode 判定某节点当前能否接纳任务(前端下发前预检, 也是 QueueOnly 模式的判定入口)。
func (s *Scheduler) CheckNode(id, kind string, needCapture bool) *RejectReason {
	return s.nodes.Accept(id, kind, needCapture, s.Config().AcceptConfig())
}

// RateLimiter 暴露限速器(装配层在执行器里调用 Wait)。
func (s *Scheduler) RateLimiter() *RateLimiter { return s.limiter }

// RateStats 网段限速快照。
func (s *Scheduler) RateStats() []RateStat { return s.limiter.Stats() }

// Strategies 内置策略模板列表。
func (s *Scheduler) Strategies() []Strategy { return BuiltinStrategies() }

// Stats 调度统计快照。
func (s *Scheduler) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	var running, queued, paused int
	for _, t := range s.tasks {
		switch t.Status {
		case StatusRunning:
			running++
		case StatusQueued:
			queued++
		case StatusPaused:
			paused++
		}
	}
	return Stats{
		Enabled:     s.cfg.Enabled,
		Total:       s.statsAll.total,
		Success:     s.statsAll.success,
		Failed:      s.statsAll.failed,
		Cancelled:   s.statsAll.cancelled,
		Rejected:    s.statsAll.rejected,
		Reassigned:  s.statsAll.reassign,
		Running:     running,
		Queued:      queued,
		Paused:      paused,
		Slots:       s.slots,
		MaxSlots:    s.cfg.MaxConcurrency,
		RateDefault: s.cfg.DefaultRate,
	}
}

// Stats 调度器统计快照。
type Stats struct {
	Enabled     bool `json:"enabled"`
	Total       int  `json:"total"`
	Success     int  `json:"success"`
	Failed      int  `json:"failed"`
	Cancelled   int  `json:"cancelled"`
	Rejected    int  `json:"rejected"`   // 因队列满/节点不可用被拒的次数
	Reassigned  int  `json:"reassigned"` // 自动重分配次数
	Running     int  `json:"running"`
	Queued      int  `json:"queued"`
	Paused      int  `json:"paused"`
	Slots       int  `json:"slots"`      // 已占用的全局并发槽位
	MaxSlots    int  `json:"maxSlots"`   // 全局并发上限
	RateDefault int  `json:"rateDefault"` // 默认限速(包/秒)
}

// ===== 槽位管理 =====

// releaseSlotLocked 归还任务占用的全局槽位与节点槽位(调用方须持锁)。
//
// 用 s.cancel[id] 是否存在作为"是否占着槽位"的判据, 并顺手删除取消函数:
//
//	dispatch 预占槽位 -> startTask 登记 cancel -> finish/Pause/Cancel 归还并删除
//
// 这样"归还"天然幂等 —— 重复调用时 cancel 已不存在, 直接返回(不会把
// s.slots 减成负数, 那会让并发限制永久放宽)。
func (s *Scheduler) releaseSlotLocked(t *Task) {
	if t == nil {
		return
	}
	if _, held := s.cancel[t.ID]; !held {
		// 未登记 cancel: 可能是 dispatch 预占但尚未 startTask 的窗口
		if s.preSlots[t.ID] {
			delete(s.preSlots, t.ID)
			if s.slots > 0 {
				s.slots--
			}
			s.nodes.decRunning(t.Node)
		}
		return
	}
	delete(s.cancel, t.ID)
	if s.slots > 0 {
		s.slots--
	}
	s.nodes.decRunning(t.Node)
}

// ===== 小工具 =====

// statusName 状态的中文说明(错误提示用)。
func statusName(s string) string {
	switch s {
	case StatusQueued:
		return "排队中"
	case StatusRunning:
		return "运行中"
	case StatusPaused:
		return "暂停中"
	case StatusCancelled:
		return "已取消"
	case StatusSuccess:
		return "已完成"
	case StatusFailed:
		return "已失败"
	}
	return s
}

// newTaskID 生成任务 ID。
//
// 实现要点(踩过的坑): 不能用"纳秒时间戳"单一项做 ID —— Windows 上 time.Now()
// 的时钟粒度约 0.5~15ms, 同一批循环里连续提交的任务会拿到**完全相同**的纳秒值。
// 后果极其隐蔽: Submit 把任务写进 map 时后一个覆盖前一个, 队列里则留下多个
// 相同 ID 的条目, 表现成"提交了 3 个任务, 列表里只有 1 个、其余永远不执行"。
//
// 因此 = 纳秒 + 进程内单调递增计数 + 随机后缀:
//   - 计数保证同进程内绝对不重复(即使时钟回拨);
//   - 随机后缀保证多进程/重启后不与历史 ID 冲突(任务表落库后需长期唯一)。
func newTaskID() string {
	seq := atomic.AddUint64(&taskSeq, 1)
	b := make([]byte, 3)
	_, _ = rand.Read(b)
	return fmt.Sprintf("sc%d-%d-%s", time.Now().UnixNano(), seq, hex.EncodeToString(b))
}

var taskSeq uint64

func itoa(n int) string { return fmt.Sprintf("%d", n) }

func ftoa(f float64) string {
	if f == float64(int64(f)) {
		return fmt.Sprintf("%d", int64(f))
	}
	return fmt.Sprintf("%.1f", f)
}
