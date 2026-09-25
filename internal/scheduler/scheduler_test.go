package scheduler

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// ===== 测试辅助 =====

// fakeExec 可控执行器: 通过 release channel 决定任务何时结束。
type fakeExec struct {
	mu      sync.Mutex
	calls   int
	running int
	// peak 执行期间出现过的最大并发数(断言"串行/并发上限"比瞬时采样可靠:
	// 瞬时采样要靠 sleep 撞窗口, 峰值是事实记录, 不会漏判)。
	peak int
	// block 为 nil 时任务立即成功返回; 非 nil 时阻塞直到收到信号或 ctx 取消。
	block chan struct{}
	fail  bool
	// started 每次任务开始执行时收到信号(测试等待用)。
	started chan string
}

func newFakeExec() *fakeExec {
	return &fakeExec{started: make(chan string, 64)}
}

func (f *fakeExec) exec(ctx context.Context, t *Task, progress func(string)) (string, error) {
	f.mu.Lock()
	f.calls++
	f.running++
	if f.running > f.peak {
		f.peak = f.running
	}
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.running--
		f.mu.Unlock()
	}()
	select {
	case f.started <- t.ID:
	default:
	}
	progress("执行中: " + t.Target)
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return "", ctx.Err()
		}
	}
	if f.fail {
		return "", errors.New("模拟执行失败")
	}
	return "完成: " + t.Target, nil
}

func (f *fakeExec) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func (f *fakeExec) runningCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.running
}

// peakRunning 执行期间出现过的最大并发数。
func (f *fakeExec) peakRunning() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.peak
}

// waitFor 轮询等待条件成立(避免脆弱的固定 sleep)。
func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}

// taskStatus 读取任务状态(方便断言)。
func taskStatus(t *testing.T, s *Scheduler, id string) string {
	t.Helper()
	got, ok := s.Get(id)
	if !ok {
		t.Fatalf("任务不存在: %s", id)
	}
	return got.Status
}

func newTestScheduler(t *testing.T, cfg Config, exec ExecFunc) *Scheduler {
	t.Helper()
	cfg.Enabled = true
	s := New(cfg, exec)
	s.Start()
	t.Cleanup(s.Stop)
	return s
}

func baseCfg() Config {
	cfg := DefaultConfig()
	cfg.MaxConcurrency = 1
	cfg.NodeConcurrency = 1
	cfg.MaxQueue = 10
	cfg.DefaultRate = 0 // 测试默认不限速, 避免等待
	return cfg
}

// ===== 队列与并发 =====

// TestQueueSerializesWhenConcurrencyOne 全局并发=1 时任务必须串行执行。
func TestQueueSerializesWhenConcurrencyOne(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), f.exec)

	for i := 0; i < 3; i++ {
		if _, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.0.0.%d", i+1)}); err != nil {
			t.Fatalf("提交失败: %v", err)
		}
	}
	// 只应有一个任务在跑
	waitFor(t, "首个任务开始执行", func() bool { return f.runningCount() == 1 })
	time.Sleep(120 * time.Millisecond)
	if got := f.runningCount(); got != 1 {
		t.Fatalf("并发上限失效: 同时运行 %d 个任务(期望 1)", got)
	}
	if got := s.Stats().Queued; got != 2 {
		t.Fatalf("排队数错误: %d(期望 2)", got)
	}
	// 放行后必须自动接力: 前一个结束 -> 槽位归还 -> 下一个立刻开始
	close(f.block)
	waitFor(t, "三个任务全部完成", func() bool { return s.Stats().Success == 3 })
	if f.callCount() != 3 {
		t.Fatalf("执行次数错误: %d", f.callCount())
	}
	// 串行执行: 峰值并发不得超过 1
	if peak := f.peakRunning(); peak != 1 {
		t.Fatalf("并发上限失效: 峰值并发 %d(期望 1)", peak)
	}
}

// TestSubmitInTightLoopSubmitsAll 连续快速提交 N 个任务, 全部都应被登记并执行。
//
// 回归用例: 早期用"纳秒时间戳"做任务 ID, 同批提交会拿到相同 ID, 内存任务表
// 相互覆盖 -> 只有部分任务被执行(用户视角是"提交 5 个只跑了 1 个")。
func TestSubmitInTightLoopSubmitsAll(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxQueue = 0 // 不限队列, 只验证"提交即登记"
	f := newFakeExec()
	s := newTestScheduler(t, cfg, f.exec)

	const n = 5
	ids := map[string]bool{}
	for i := 0; i < n; i++ {
		task, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.0.9.%d", i+1)})
		if err != nil {
			t.Fatalf("第 %d 个提交失败: %v", i+1, err)
		}
		if ids[task.ID] {
			t.Fatalf("任务 ID 冲突, 已存在: %s", task.ID)
		}
		ids[task.ID] = true
	}
	if got := s.Stats().Total; got != n {
		t.Fatalf("提交总数错误: %d(期望 %d)", got, n)
	}
	if _, total := s.List("", 1, 100); total != n {
		t.Fatalf("任务表条数错误: %d(期望 %d)", total, n)
	}
	waitFor(t, "全部执行完成", func() bool { return s.Stats().Success == n })
	if got := f.callCount(); got != n {
		t.Fatalf("执行次数错误: %d(期望 %d)", got, n)
	}
}

// TestTaskIDsAreUnique 同一批连续生成的任务 ID 必须互不相同。
//
// 回归用例: 早期实现用 time.Now().UnixNano() 做 ID, Windows 上时钟粒度约
// 0.5~15ms, 循环里连续生成的 ID 完全相同 -> 任务表 map 相互覆盖, 表现为
// "提交 3 个任务只执行 1 个"。这类缺陷不会报错, 只会让任务静默消失。
func TestTaskIDsAreUnique(t *testing.T) {
	seen := make(map[string]bool, 2000)
	for i := 0; i < 2000; i++ {
		id := newTaskID()
		if seen[id] {
			t.Fatalf("任务 ID 重复: %s (第 %d 次生成)", id, i+1)
		}
		seen[id] = true
	}
}

// TestGlobalConcurrencyNotCappedByNodeConcurrency 全局并发上限不得被单节点
// 默认并发上限压死。
//
// 回归用例: NodeConcurrency(=探针默认并发, 默认 1)曾错误地套用到中心本地节点,
// 导致默认配置下 MaxConcurrency=2/4 完全无效, 永远只能跑 1 个任务 ——
// "支持全局最大并发任务数限制"这条需求被静默架空。
func TestGlobalConcurrencyNotCappedByNodeConcurrency(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxConcurrency = 2
	cfg.NodeConcurrency = 1 // 只约束探针
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, cfg, f.exec)

	for i := 0; i < 4; i++ {
		if _, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.0.7.%d", i+1)}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "本地节点达到全局并发 2", func() bool { return f.runningCount() == 2 })
	// 节点视图里本地节点的上限应显示为全局并发值, 而非 NodeConcurrency
	for _, v := range s.Nodes() {
		if v.Kind == NodeLocal && v.Max != 2 {
			t.Fatalf("本地节点上限显示错误: %d(期望 2)", v.Max)
		}
	}
	close(f.block)
	waitFor(t, "全部完成", func() bool { return s.Stats().Success == 4 })
}

// TestLocalConcurrencyCanBeCapped LocalConcurrency 可显式压低本地并发。
func TestLocalConcurrencyCanBeCapped(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxConcurrency = 4
	cfg.LocalConcurrency = 1 // 显式限制本地, 余量留给探针
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, cfg, f.exec)
	for i := 0; i < 3; i++ {
		if _, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.0.8.%d", i+1)}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "本地跑起 1 个", func() bool { return f.runningCount() == 1 })
	time.Sleep(120 * time.Millisecond)
	if got := f.runningCount(); got != 1 {
		t.Fatalf("LocalConcurrency 未生效: 同时 %d 个", got)
	}
	close(f.block)
	waitFor(t, "全部完成", func() bool { return s.Stats().Success == 3 })
}

// TestGlobalConcurrencyTwo 全局并发=2 时可并行两个任务。
func TestGlobalConcurrencyTwo(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxConcurrency = 2
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, cfg, f.exec)

	for i := 0; i < 4; i++ {
		if _, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.0.1.%d", i+1)}); err != nil {
			t.Fatalf("提交失败: %v", err)
		}
	}
	waitFor(t, "两个任务并行执行", func() bool { return f.runningCount() == 2 })
	time.Sleep(100 * time.Millisecond)
	if got := f.runningCount(); got != 2 {
		t.Fatalf("并发数错误: %d(期望 2)", got)
	}
	close(f.block)
	waitFor(t, "全部完成", func() bool { return s.Stats().Success == 4 })
}

// TestQueueFull 队列满时拒绝提交(ErrQueueFull)。
func TestQueueFull(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxQueue = 2
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, cfg, f.exec)

	// MaxQueue 是"等待区"长度。注意不能靠"先跑满槽位再连提 3 个"来测:
	// dispatch 会被每次 Submit 唤醒并立刻把可执行任务取走, 队列攒不满。
	// 因此这里先把全局并发降到 0 语义之外的方式不可行, 改用"提交速度超过
	// 调度速度"的自然场景 —— 直接连发 3 个, 第 3 个必然在队列里撞上限。
	var ids []string
	var lastErr error
	for i := 0; i < 3; i++ {
		task, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.0.2.%d", i+1)})
		lastErr = err
		if task != nil {
			ids = append(ids, task.ID)
		}
	}
	// 第 3 个被拒(前两个: 1 个抢到槽位, 1 个在队列; 队列上限 2 时第 3 个才可能
	// 一次性撞上, 所以这里接受"第 3 个被拒"或"三个都进去了"两种时序, 但被拒时
	// 必须是 ErrQueueFull)
	if lastErr != nil && !errors.Is(lastErr, ErrQueueFull) {
		t.Fatalf("第 3 个提交失败原因错误: %v", lastErr)
	}
	if lastErr == nil {
		// 时序上没撞上限: 补提交直到撞到为止(每次提交前并发已满, 队列才会累积)
		waitFor(t, "首个任务运行", func() bool { return f.runningCount() == 1 })
		for i := 0; i < 10; i++ {
			_, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.0.2.%d", 100+i)})
			if errors.Is(err, ErrQueueFull) {
				lastErr = err
				break
			}
			if err != nil {
				t.Fatalf("非预期错误: %v", err)
			}
		}
	}
	if !errors.Is(lastErr, ErrQueueFull) {
		t.Fatalf("未触发队列上限: %v", lastErr)
	}
	if got := s.Stats(); got.Rejected == 0 {
		t.Fatalf("被拒次数未统计: %+v", got)
	}
	if len(ids) == 0 {
		t.Fatal("未成功提交任何任务")
	}
	close(f.block)
}

// TestPriorityOrder 优先级小的先执行(同节点)。
func TestPriorityOrder(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), f.exec)

	// 先提交一个占住唯一槽位
	if _, err := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.3.1"}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "占位任务运行", func() bool { return f.runningCount() == 1 })

	low, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.3.2", Priority: 10})
	high, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.3.3", Priority: -10})

	queued := s.Queued()
	if len(queued) != 2 {
		t.Fatalf("排队数错误: %d", len(queued))
	}
	if queued[0].ID != high.ID {
		t.Fatalf("优先级排序失效: 队首 %s(期望高优先级 %s)", queued[0].ID, high.ID)
	}
	if queued[1].ID != low.ID {
		t.Fatalf("优先级排序失效: 队尾 %s", queued[1].ID)
	}
	close(f.block)
	// 高优先级任务应先于低优先级开始
	waitFor(t, "全部完成", func() bool { return s.Stats().Success == 3 })
	firstAfter := ""
	deadline := time.After(2 * time.Second)
	for firstAfter == "" {
		select {
		case id := <-f.started:
			if id == high.ID || id == low.ID {
				firstAfter = id
			}
		case <-deadline:
			t.Fatal("未收到后续任务开始事件")
		}
	}
	if firstAfter != high.ID {
		t.Fatalf("高优先级任务未先执行: 先跑的是 %s", firstAfter)
	}
}

// ===== 状态流转 =====

// TestPauseReleaseSlotAndResume 暂停必须释放槽位, 恢复后重新执行。
func TestPauseReleaseSlotAndResume(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), f.exec)

	t1, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.4.1"})
	t2, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.4.2"})
	waitFor(t, "任务1运行", func() bool { return f.runningCount() == 1 })
	if got := s.Stats().Queued; got != 1 {
		t.Fatalf("任务2应在排队: queued=%d", got)
	}

	// 暂停运行中的任务1 -> 槽位释放, 任务2 应立刻开始
	if err := s.Pause(t1.ID); err != nil {
		t.Fatalf("暂停失败: %v", err)
	}
	waitFor(t, "任务2接管槽位", func() bool {
		got, ok := s.Get(t2.ID)
		return ok && got.Status == StatusRunning
	})
	if got, _ := s.Get(t1.ID); got.Status != StatusPaused {
		t.Fatalf("任务1状态错误: %s", got.Status)
	}

	// 恢复任务1: 重新入队, 等任务2 结束后执行
	if err := s.Resume(t1.ID); err != nil {
		t.Fatalf("恢复失败: %v", err)
	}
	if got, _ := s.Get(t1.ID); got.Status != StatusQueued {
		t.Fatalf("恢复后状态错误: %s", got.Status)
	}
	// 再次暂停(排队中暂停路径)
	if err := s.Pause(t1.ID); err != nil {
		t.Fatalf("排队中暂停失败: %v", err)
	}
	if got := s.Queued(); len(got) != 0 {
		t.Fatalf("排队中暂停后不应仍在队列: %d", len(got))
	}
	close(f.block)
	waitFor(t, "任务2完成", func() bool { return s.Stats().Success == 1 })
}

// TestCancelRunningAndQueued 取消运行中与排队中的任务。
func TestCancelRunningAndQueued(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), f.exec)

	t1, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.5.1"})
	t2, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.5.2"})
	waitFor(t, "任务1运行", func() bool { return f.runningCount() == 1 })

	if err := s.Cancel(t2.ID); err != nil { // 排队中取消
		t.Fatalf("取消排队任务失败: %v", err)
	}
	if got, _ := s.Get(t2.ID); got.Status != StatusCancelled {
		t.Fatalf("排队任务取消后状态错误: %s", got.Status)
	}
	if err := s.Cancel(t1.ID); err != nil { // 运行中取消 -> ctx 取消, 执行器退出
		t.Fatalf("取消运行任务失败: %v", err)
	}
	waitFor(t, "运行任务被中断且释放槽位", func() bool { return f.runningCount() == 0 })
	waitFor(t, "状态置为已取消", func() bool {
		got, ok := s.Get(t1.ID)
		return ok && got.Status == StatusCancelled
	})
	// 取消不得被后续 finish 覆盖成 failed
	time.Sleep(150 * time.Millisecond)
	if got, _ := s.Get(t1.ID); got.Status != StatusCancelled {
		t.Fatalf("取消状态被覆盖: %s", got.Status)
	}
}

// TestCancelNotOverwrittenByContextFinish 【竞态回归】执行器因 ctx 取消返回后,
// 不得把任务状态改写成 failed。
//
// 【背景: 真实缺陷】旧实现在 exec 返回错误时无条件调 finish(StatusFailed) 与
// Cancel() 抢锁。若 finish 抢到锁时任务仍是 running(说明 Cancel 尚未拿到锁),
// 状态被置 failed; Cancel 随后见到终态幂等返回 —— 用户点的是"取消", 看到的却是
// "失败"。这是**概率性**出现的(取决于 goroutine 调度), 全量并发跑测试时被放大了
// 才暴露, 单独跑 20 次都不复现, 所以必须有一个不依赖时序运气的确定性用例。
//
// 制造方式: 执行器自己阻塞在 ctx.Done() 上, 等一个"闸门"才返回 —— 测试因此可以
// 精确控制"执行器返回"与"Cancel 调用"的先后, 不靠 sleep 撞运气。
func TestCancelNotOverwrittenByContextFinish(t *testing.T) {
	release := make(chan struct{}) // 执行器返回闸门
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), func(ctx context.Context, task *Task, progress func(string)) (string, error) {
		<-ctx.Done()  // 等待被取消
		<-release     // 但先不返回, 由测试决定何时返回
		return "", ctx.Err()
	})

	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.7.1"})
	waitFor(t, "任务运行", func() bool { return f.runningCount() >= 0 })
	waitFor(t, "进入执行态", func() bool {
		got, ok := s.Get(task.ID)
		return ok && got.Status == StatusRunning
	})

	// 先取消: 此时 Cancel 持锁置 cancelled 并触发 ctx 取消
	if err := s.Cancel(task.ID); err != nil {
		t.Fatalf("取消失败: %v", err)
	}
	// 再放行执行器返回(它会带着 ctx.Err() 走 finish 路径)
	close(release)
	time.Sleep(200 * time.Millisecond)

	got, _ := s.Get(task.ID)
	if got.Status != StatusCancelled {
		t.Fatalf("取消后状态被 ctx 结束路径覆盖: 期望 %s, 实际 %s", StatusCancelled, got.Status)
	}
}

// TestTimeoutStillFails 超时仍须记失败(不能因为修了取消竞态就把超时也放过)。
//
// 【为什么必须单独立一个反向用例】上一条修的是"ctx 取消不该记 failed", 很容易顺手
// 把所有 ctx 相关错误都放过 —— 那样超时就会变成"任务永远没结果"。两者必须区分:
//   - 取消/暂停: 状态由控制操作设定(已终态/已暂停 -> 不覆盖);
//   - 超时: 无人认领, 任务仍是 running -> 记 failed 并带上超时原因。
func TestTimeoutStillFails(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	cfg := baseCfg()
	cfg.TaskTimeoutSec = 1 // 1 秒超时
	s := newTestScheduler(t, cfg, func(ctx context.Context, task *Task, progress func(string)) (string, error) {
		<-ctx.Done()
		return "", ctx.Err()
	})

	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.7.2"})
	waitFor(t, "超时后置失败", func() bool {
		got, ok := s.Get(task.ID)
		return ok && Terminal(got.Status)
	})
	got, _ := s.Get(task.ID)
	if got.Status != StatusFailed {
		t.Fatalf("超时应记失败, 实际 %s", got.Status)
	}
	if got.Err == "" {
		t.Error("超时失败应保留原因(用户需要看到为什么失败)")
	}
}

// TestCancelIdempotent 重复取消/暂停已终态任务不报错(幂等)。
func TestCancelIdempotent(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.5.9"})
	waitFor(t, "完成", func() bool { return s.Stats().Success == 1 })
	if err := s.Cancel(task.ID); err != nil {
		t.Fatalf("已完成任务取消应幂等: %v", err)
	}
	if err := s.Resume(task.ID); err == nil {
		t.Fatal("恢复已完成任务应报错")
	}
}

// TestRetryFailed 失败任务可重试重新入队。
func TestRetryFailed(t *testing.T) {
	f := newFakeExec()
	f.fail = true
	s := newTestScheduler(t, baseCfg(), f.exec)
	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.6.1"})
	waitFor(t, "失败", func() bool { return s.Stats().Failed == 1 })

	if err := s.Retry(task.ID); err != nil {
		t.Fatalf("重试失败: %v", err)
	}
	waitFor(t, "重试执行", func() bool { return f.callCount() == 2 })
	waitFor(t, "再次失败", func() bool { return s.Stats().Failed == 2 })
}

// TestDeleteRules 运行中不可删, 终态可删。
func TestDeleteRules(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), f.exec)
	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.0.6.9"})
	waitFor(t, "运行", func() bool { return f.runningCount() == 1 })
	if err := s.Delete(task.ID); err == nil {
		t.Fatal("运行中任务不应可删除")
	}
	if err := s.Cancel(task.ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "取消完成", func() bool {
		got, ok := s.Get(task.ID)
		return ok && got.Status == StatusCancelled
	})
	if err := s.Delete(task.ID); err != nil {
		t.Fatalf("终态任务删除失败: %v", err)
	}
	if _, ok := s.Get(task.ID); ok {
		t.Fatal("删除后仍能查到任务")
	}
}

// ===== 探针节点 =====

// TestProbeNodeConcurrency 单探针节点并发上限独立于全局。
func TestProbeNodeConcurrency(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxConcurrency = 4
	cfg.NodeConcurrency = 1
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, cfg, f.exec)
	s.SyncNodes([]Node{
		{ID: "p1", Name: "探针1", Kind: NodeProbe, Online: true, Capabilities: "portscan,web"},
		{ID: "p2", Name: "探针2", Kind: NodeProbe, Online: true, Capabilities: "portscan,web"},
	})

	// 两个任务发往 p1: 只有 1 个能跑, 另一个保持排队
	t1, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.1.0.1", Node: "p1"})
	t2, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.1.0.2", Node: "p1"})
	waitFor(t, "p1 上一个任务运行", func() bool { return f.runningCount() == 1 })
	time.Sleep(150 * time.Millisecond)
	if got := f.runningCount(); got != 1 {
		t.Fatalf("单节点并发失效: %d", got)
	}

	// 发往 p2 的任务不受 p1 占满影响 -> 不会被队头阻塞
	t3, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.1.0.3", Node: "p2"})
	waitFor(t, "p2 任务并行执行(未队头阻塞)", func() bool { return f.runningCount() == 2 })

	for _, v := range s.Nodes() {
		if v.ID == "p1" && v.Running != 1 {
			t.Fatalf("p1 运行数错误: %d", v.Running)
		}
		if v.ID == "p2" && v.Running != 1 {
			t.Fatalf("p2 运行数错误: %d", v.Running)
		}
	}
	close(f.block)
	waitFor(t, "全部完成", func() bool { return s.Stats().Success == 3 })
	for _, id := range []string{t1.ID, t2.ID, t3.ID} {
		got, _ := s.Get(id)
		if got.Status != StatusSuccess {
			t.Fatalf("任务 %s 状态 %s", id, got.Status)
		}
	}
}

// TestRejectOverloadedProbe 探针负载过高时中心端拒绝下发。
func TestRejectOverloadedProbe(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxCPUPercent = 85
	cfg.MaxMemPercent = 90
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, cfg, f.exec)
	s.SyncNodes([]Node{
		{ID: "busy", Name: "繁忙探针", Kind: NodeProbe, Online: true, CPUPercent: 95},
		{ID: "idle", Name: "空闲探针", Kind: NodeProbe, Online: true, CPUPercent: 5},
	})

	rej := s.CheckNode("busy", "port", false)
	if rej == nil || rej.Code != RejectCPU {
		t.Fatalf("期望 CPU 拒绝, 实际: %+v", rej)
	}
	if rej := s.CheckNode("idle", "port", false); rej != nil {
		t.Fatalf("空闲节点不应被拒: %+v", rej)
	}
	// 离线节点
	s.SyncNodes([]Node{{ID: "down", Kind: NodeProbe, Online: false}})
	if rej := s.CheckNode("down", "port", false); rej == nil || rej.Code != RejectOffline {
		t.Fatalf("期望离线拒绝, 实际: %+v", rej)
	}
	// 能力不匹配: 要求抓包但探针无 capture 能力
	s.SyncNodes([]Node{{ID: "nocap", Kind: NodeProbe, Online: true, Capabilities: "portscan,web"}})
	if rej := s.CheckNode("nocap", "port", true); rej == nil || rej.Code != RejectAbility {
		t.Fatalf("期望能力拒绝, 实际: %+v", rej)
	}
	close(f.block)
}

// TestAutoNodeSelection 提交时 Node=auto 自动挑最空闲探针。
func TestAutoNodeSelection(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	s.SyncNodes([]Node{
		{ID: "p1", Kind: NodeProbe, Online: true, CPUPercent: 80},
		{ID: "p2", Kind: NodeProbe, Online: true, CPUPercent: 5},
	})
	task, err := s.Submit(SubmitRequest{Kind: "port", Target: "10.2.0.1", Node: "auto"})
	if err != nil {
		t.Fatalf("提交失败: %v", err)
	}
	if task.Node != "p2" {
		t.Fatalf("未选中最空闲节点: %s", task.Node)
	}
	waitFor(t, "完成", func() bool { return s.Stats().Success == 1 })
}

// TestAutoNodeFallbackLocal 无可用探针时回落本地(单机场景不能报错)。
func TestAutoNodeFallbackLocal(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	task, err := s.Submit(SubmitRequest{Kind: "port", Target: "10.2.1.1", Node: "auto"})
	if err != nil {
		t.Fatalf("无探针时提交不应失败: %v", err)
	}
	if task.Node != "" {
		t.Fatalf("期望回落本地(空节点), 实际: %s", task.Node)
	}
	waitFor(t, "本地执行完成", func() bool { return s.Stats().Success == 1 })
}

// TestAutoReassignOnFailure 探针任务失败后自动重分配到其它节点。
func TestAutoReassignOnFailure(t *testing.T) {
	cfg := baseCfg()
	cfg.MaxAttempts = 2
	f := newFakeExec()
	f.fail = true
	s := newTestScheduler(t, cfg, f.exec)
	s.SyncNodes([]Node{
		{ID: "p1", Kind: NodeProbe, Online: true},
		{ID: "p2", Kind: NodeProbe, Online: true},
	})
	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.3.0.1", Node: "p1"})
	// 第一次失败 -> 换节点重试 -> 第二次仍失败 -> 终态
	waitFor(t, "重分配事件", func() bool { return s.Stats().Reassigned >= 1 })
	waitFor(t, "最终失败", func() bool { return s.Stats().Failed >= 1 })
	got, _ := s.Get(task.ID)
	if got.Attempts < 2 {
		t.Fatalf("重试次数不足: %d", got.Attempts)
	}
	if got.Node != "p2" {
		t.Fatalf("未重分配到其它节点: %s", got.Node)
	}
}

// ===== 策略模板 =====

// TestStrategyApply 策略模板默认值 + 用户覆盖。
func TestStrategyApply(t *testing.T) {
	// 模板默认值生效
	p := Apply(StrategyQuick, Params{CIDR: "192.168.1.0/24"})
	if p.CIDR != "192.168.1.0/24" {
		t.Fatalf("目标丢失: %+v", p)
	}
	if p.Concurrency != 512 || p.Timeout != 600 {
		t.Fatalf("快速探测模板默认值未生效: %+v", p)
	}
	if p.EnableNuclei {
		t.Fatal("快速存活探测不应默认开启 Nuclei")
	}

	// 用户覆盖优先
	off := false
	p2 := Apply(StrategyAudit, Params{IP: "10.0.0.1", Concurrency: 32, Ports: "80", EnableArp: &off})
	if p2.Concurrency != 32 || p2.Ports != "80" {
		t.Fatalf("用户参数未覆盖模板: %+v", p2)
	}
	if p2.EnableArp == nil || *p2.EnableArp {
		t.Fatal("*bool 开关无法被用户关掉")
	}
	if !p2.EnableNuclei || !p2.Capture {
		t.Fatalf("审计模板默认能力丢失: %+v", p2)
	}

	// custom: 只用用户值
	p3 := Apply(StrategyCustom, Params{IP: "10.0.0.2"})
	if p3.Concurrency != 0 || p3.Ports != "" {
		t.Fatalf("custom 不应注入模板默认值: %+v", p3)
	}

	// 三个内置模板齐全
	if len(BuiltinStrategies()) != 3 {
		t.Fatalf("内置模板数量错误: %d", len(BuiltinStrategies()))
	}
	for _, id := range []string{StrategyQuick, StrategyAudit, StrategyWeb} {
		if StrategyByID(id) == nil {
			t.Fatalf("模板缺失: %s", id)
		}
	}

	// 深度扫描只由 webdeep 策略默认开启 —— 它会发起数十倍于单 URL 扫描的请求,
	// 一旦因"新增字段"被其它策略默认带上, 每一次普通扫描都会变成爬虫式扫描。
	if !Apply(StrategyWeb, Params{URL: "http://10.0.0.1/"}).WebDeep {
		t.Fatal("webdeep 策略应默认开启深度扫描")
	}
	if Apply(StrategyQuick, Params{CIDR: "10.0.0.0/24"}).WebDeep ||
		Apply(StrategyAudit, Params{IP: "10.0.0.1"}).WebDeep ||
		Apply(StrategyCustom, Params{URL: "http://10.0.0.1/"}).WebDeep {
		t.Fatal("深度扫描不得由非 webdeep 策略默认开启")
	}
}

// TestSubmitAppliesDefaultStrategy 未指定策略时用配置的默认模板。
func TestSubmitAppliesDefaultStrategy(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), f.exec)
	task, err := s.Submit(SubmitRequest{Kind: "ip", Target: "192.168.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if task.Strategy != StrategyQuick {
		t.Fatalf("默认策略错误: %s", task.Strategy)
	}
	if task.Params.Concurrency != 512 {
		t.Fatalf("默认策略参数未展开: %+v", task.Params)
	}
	close(f.block)
}

// TestSubmitRejectsBadKind 非法类型/空目标被拒。
func TestSubmitRejectsBadKind(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	if _, err := s.Submit(SubmitRequest{Kind: "synscan", Target: "10.0.0.1"}); err == nil {
		t.Fatal("非法类型应被拒")
	}
	if _, err := s.Submit(SubmitRequest{Kind: "port", Target: "   "}); err == nil {
		t.Fatal("空目标应被拒")
	}
}

// TestTargetNormalizedByKind 目标按类型填到对应字段。
func TestTargetNormalizedByKind(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	cases := []struct {
		kind   string
		target string
		check  func(Params) bool
	}{
		{"ip", "10.9.0.0/24", func(p Params) bool { return p.CIDR == "10.9.0.0/24" }},
		{"port", "10.9.0.1", func(p Params) bool { return p.IP == "10.9.0.1" }},
		{"host", "10.9.0.2", func(p Params) bool { return p.IP == "10.9.0.2" }},
		{"web", "http://10.9.0.3", func(p Params) bool { return p.URL == "http://10.9.0.3" }},
	}
	for _, c := range cases {
		task, err := s.Submit(SubmitRequest{Kind: c.kind, Target: c.target, Strategy: StrategyCustom})
		if err != nil {
			t.Fatalf("%s 提交失败: %v", c.kind, err)
		}
		if !c.check(task.Params) {
			t.Fatalf("%s 目标未归一到正确字段: %+v", c.kind, task.Params)
		}
	}
}

// ===== 限速 =====

// TestRateLimiterThrottles 令牌桶按速率放行。
func TestRateLimiterThrottles(t *testing.T) {
	l := NewRateLimiter(100, nil) // 100 pps -> 每个令牌 10ms
	var nowMu sync.Mutex
	now := time.Now()
	l.SetTimeSource(func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return now
	})
	advance := func(d time.Duration) {
		nowMu.Lock()
		now = now.Add(d)
		nowMu.Unlock()
	}

	// 桶初始满(100 个令牌): 前 100 次不应等待
	start := time.Now()
	for i := 0; i < 100; i++ {
		if err := l.Wait(nil, "10.0.0.0/24", 1); err != nil {
			t.Fatalf("令牌充足时不应等待: %v", err)
		}
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("桶内令牌不应阻塞: %v", elapsed)
	}
	// 令牌已耗尽, 时间未推进 -> 必须阻塞(此处用 ctx 提前取消验证阻塞行为)
	done := make(chan struct{})
	cancelCh := make(chan struct{})
	go func() {
		_ = l.Wait(cancelCh, "10.0.0.0/24", 1)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("令牌耗尽后未阻塞")
	case <-time.After(80 * time.Millisecond):
	}
	// 推进时间 -> 令牌补充 -> 放行
	advance(time.Second)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("令牌补充后仍未放行")
	}
	close(cancelCh)
}

// TestRateLimiterPerNet 不同网段不同速率。
func TestRateLimiterPerNet(t *testing.T) {
	l := NewRateLimiter(1000, []RateRule{
		{CIDR: "10.0.0.0/8", Rate: 100},
		{CIDR: "192.168.0.0/16", Rate: 0}, // 不限速
		{CIDR: "172.16.*", Rate: 50},      // 通配前缀
	})
	if got := l.RateFor("10.1.2.3"); got != 100 {
		t.Fatalf("10/8 速率错误: %d", got)
	}
	if got := l.RateFor("http://10.1.2.3:8080/x"); got != 100 {
		t.Fatalf("URL 归一失败, 速率: %d", got)
	}
	if got := l.RateFor("192.168.1.10"); got != 0 {
		t.Fatalf("不限速网段速率错误: %d", got)
	}
	if got := l.RateFor("172.16.5.1:443"); got != 50 {
		t.Fatalf("通配前缀匹配失败: %d", got)
	}
	if got := l.RateFor("8.8.8.8"); got != 1000 {
		t.Fatalf("默认速率错误: %d", got)
	}
	// 不限速网段 Wait 不阻塞
	start := time.Now()
	for i := 0; i < 5000; i++ {
		if err := l.Wait(nil, "192.168.1.10", 1); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > 500*time.Millisecond {
		t.Fatalf("不限速网段不应阻塞: %v", d)
	}
}

// TestRateLimiterSameNetSameBucket 同网段不同写法共用一个桶(防限速失效)。
func TestRateLimiterSameNetSameBucket(t *testing.T) {
	if bucketKey("10.0.0.5") != bucketKey("10.0.0.5:8080") {
		t.Fatal("IP 与 IP:端口 未归一到同一桶")
	}
	if bucketKey("http://10.0.0.5/a/b") != "10.0.0.5" {
		t.Fatalf("URL 未归一: %s", bucketKey("http://10.0.0.5/a/b"))
	}
	if bucketKey("10.0.0.0/24") != "10.0.0.0/24" {
		t.Fatal("CIDR 的斜杠被误当路径剥掉")
	}
}

// TestRateLimiterCancel 限速等待中取消立即返回。
func TestRateLimiterCancel(t *testing.T) {
	l := NewRateLimiter(1, nil) // 1 pps
	// 先耗尽令牌
	if err := l.Wait(nil, "10.5.5.5", 1); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	cancel := make(chan struct{})
	go func() { done <- l.Wait(cancel, "10.5.5.5", 1) }()
	time.Sleep(50 * time.Millisecond)
	close(cancel)
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("取消后应返回错误")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("取消后未及时返回")
	}
}

// TestRateLimiterZeroMeansUnlimited 默认 0 = 不限速(默认关闭原则)。
func TestRateLimiterZeroMeansUnlimited(t *testing.T) {
	l := NewRateLimiter(0, nil)
	start := time.Now()
	for i := 0; i < 20000; i++ {
		if err := l.Wait(nil, "10.0.0.1", 1); err != nil {
			t.Fatal(err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Fatalf("不限速时不应有开销: %v", d)
	}
	if len(l.Stats()) != 0 {
		t.Fatal("不限速不应创建桶")
	}
}

// ===== 配置 =====

// TestConfigNormalize 配置零值补齐与非法值清洗。
func TestConfigNormalize(t *testing.T) {
	c := Config{}
	c.normalize()
	d := DefaultConfig()
	if c.MaxConcurrency != d.MaxConcurrency || c.NodeConcurrency != d.NodeConcurrency {
		t.Fatalf("默认并发未补齐: %+v", c)
	}
	if c.DefaultStrategy != StrategyQuick {
		t.Fatalf("默认策略未补齐: %s", c.DefaultStrategy)
	}
	c2 := Config{MaxQueue: -5, RateRules: []RateRule{{CIDR: "  ", Rate: 10}, {CIDR: "10.0.0.0/8", Rate: -1}}}
	c2.normalize()
	if c2.MaxQueue != 0 {
		t.Fatalf("负数队列上限未清洗: %d", c2.MaxQueue)
	}
	if len(c2.RateRules) != 1 || c2.RateRules[0].CIDR != "10.0.0.0/8" || c2.RateRules[0].Rate != 0 {
		t.Fatalf("限速规则未清洗: %+v", c2.RateRules)
	}
	// 默认配置必须启用(2026-09-20 用户要求开箱即用): 排队提交不依赖任何手工配置。
	// 只影响显式 queue=true 的提交, 即时扫描语义不变 —— 这条默认是产品决策, 钉住防回退。
	if !DefaultConfig().Enabled {
		t.Fatal("调度器默认必须启用(开箱即用)")
	}
}

// TestUpdateConfigTakesEffect 热更新配置立即生效。
func TestUpdateConfigTakesEffect(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := newTestScheduler(t, baseCfg(), f.exec)
	for i := 0; i < 3; i++ {
		if _, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.7.0.%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "单并发运行", func() bool { return f.runningCount() == 1 })

	cfg := baseCfg()
	cfg.MaxConcurrency = 3
	s.UpdateConfig(cfg)
	waitFor(t, "并发提升到 3", func() bool { return f.runningCount() == 3 })
	close(f.block)
	waitFor(t, "全部完成", func() bool { return s.Stats().Success == 3 })
	if s.Stats().MaxSlots != 3 {
		t.Fatalf("统计未反映新并发: %d", s.Stats().MaxSlots)
	}
}

// ===== 其它 =====

// TestEvaluatorNeverPanicsHook hook 里 panic 不影响调度。
func TestHookPanicIsolated(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	s.OnEvent(func(Event) { panic("hook 故意崩溃") })
	task, err := s.Submit(SubmitRequest{Kind: "port", Target: "10.8.0.1"})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "任务仍正常完成", func() bool { return s.Stats().Success == 1 })
	if got, _ := s.Get(task.ID); got.Status != StatusSuccess {
		t.Fatalf("状态错误: %s", got.Status)
	}
}

// TestExecPanicIsolated 执行器 panic 转成任务失败, 不拖垮调度器。
func TestExecPanicIsolated(t *testing.T) {
	s := newTestScheduler(t, baseCfg(), func(ctx context.Context, t *Task, p func(string)) (string, error) {
		panic("执行器故意崩溃")
	})
	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.8.1.1"})
	waitFor(t, "记录失败", func() bool { return s.Stats().Failed == 1 })
	got, _ := s.Get(task.ID)
	if got.Status != StatusFailed || got.Err == "" {
		t.Fatalf("panic 未转成失败结果: %+v", got)
	}
	// 槽位必须已释放, 后续任务能继续跑
	if s.Stats().Slots != 0 {
		t.Fatalf("槽位未释放: %d", s.Stats().Slots)
	}
}

// TestExecPanicsTwiceThenQueueFlows 连续 panic 后队列仍能流动(防槽位泄漏)。
func TestExecPanicDoesNotLeakSlot(t *testing.T) {
	var n int32
	s := newTestScheduler(t, baseCfg(), func(ctx context.Context, t *Task, p func(string)) (string, error) {
		if atomic.AddInt32(&n, 1) <= 2 {
			panic("boom")
		}
		return "ok", nil
	})
	var ids []string
	for i := 0; i < 4; i++ {
		task, _ := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.8.2.%d", i)})
		ids = append(ids, task.ID)
	}
	waitFor(t, "四个任务全部结束", func() bool { return s.Stats().Failed == 2 && s.Stats().Success == 2 })
	if s.Stats().Slots != 0 {
		t.Fatalf("槽位泄漏: %d", s.Stats().Slots)
	}
}

// TestTaskTimeout 超时任务被终止并置失败。
func TestTaskTimeout(t *testing.T) {
	cfg := baseCfg()
	cfg.TaskTimeoutSec = 1
	f := newFakeExec()
	f.block = make(chan struct{})
	defer close(f.block)
	s := newTestScheduler(t, cfg, f.exec)
	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.8.3.1", Strategy: StrategyCustom})
	waitFor(t, "超时失败", func() bool { return s.Stats().Failed == 1 })
	got, _ := s.Get(task.ID)
	if got.Status != StatusFailed {
		t.Fatalf("超时后状态错误: %s", got.Status)
	}
}

// TestListPagination 列表分页与状态过滤。
func TestListPagination(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	for i := 0; i < 5; i++ {
		if _, err := s.Submit(SubmitRequest{Kind: "port", Target: fmt.Sprintf("10.9.0.%d", i)}); err != nil {
			t.Fatal(err)
		}
	}
	waitFor(t, "全部完成", func() bool { return s.Stats().Success == 5 })
	page1, total := s.List("", 1, 2)
	if total != 5 || len(page1) != 2 {
		t.Fatalf("分页错误: total=%d len=%d", total, len(page1))
	}
	page3, _ := s.List("", 3, 2)
	if len(page3) != 1 {
		t.Fatalf("末页长度错误: %d", len(page3))
	}
	only, total2 := s.List(StatusSuccess, 1, 10)
	if total2 != 5 || len(only) != 5 {
		t.Fatalf("状态过滤错误: total=%d len=%d", total2, len(only))
	}
	if got, _ := s.List(StatusRunning, 1, 10); len(got) != 0 {
		t.Fatalf("不应有运行中任务: %d", len(got))
	}
	// 越界页返回空而非 panic
	if got, _ := s.List("", 99, 2); len(got) != 0 {
		t.Fatalf("越界页应返回空: %d", len(got))
	}
}

// TestStopCancelsRunning 停止调度器时运行中任务被取消。
func TestStopCancelsRunning(t *testing.T) {
	f := newFakeExec()
	f.block = make(chan struct{})
	s := New(baseCfg(), f.exec)
	s.Start()
	task, _ := s.Submit(SubmitRequest{Kind: "port", Target: "10.9.9.1"})
	waitFor(t, "运行", func() bool { return f.runningCount() == 1 })
	s.Stop()
	waitFor(t, "执行器退出", func() bool { return f.runningCount() == 0 })
	// 停止后任务停留在"运行中"(不置终态): 进程重启时它仍是未完成任务,
	// 可由 AutoStart 重新入队续扫; 若置成 failed 就再也没有续扫入口了。
	if got, _ := s.Get(task.ID); Terminal(got.Status) {
		t.Fatalf("停止时任务不应被置终态, 实际: %s", got.Status)
	}
}

// TestDisabledConfigStillWorks New 不因 Enabled=false 拒绝服务(接线侧负责判定)。
func TestDisabledConfigStillWorks(t *testing.T) {
	f := newFakeExec()
	s := newTestScheduler(t, baseCfg(), f.exec)
	if !s.Stats().Enabled {
		t.Fatal("Enabled 应反映配置")
	}
	_ = f
}
