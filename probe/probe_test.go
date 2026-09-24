package probe

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startTestCenter 起一个测试用中心端(不监听真实端口, 连接由内存管道喂入)。
//
// 说明: 自动化/沙箱环境常拦截回环 TCP 拨号, 故测试不走真实网络,
// 用 net.Pipe 提供一条全双工连接直接交给中心端连接处理, 覆盖协议全流程。
func startTestCenter(t *testing.T, token string) *Center {
	t.Helper()
	c := NewCenter(ServerConfig{
		Enabled:      true,
		Listen:       "127.0.0.1:0",
		Token:        token,
		HeartbeatSec: 1,
		OfflineSec:   5,
	})
	// 标记为运行中: 不真正 Listen, 由 serveConnInner 直接处理喂入的连接
	c.mu.Lock()
	c.ln = nil
	c.closed = false
	c.mu.Unlock()
	t.Cleanup(c.Stop)
	return c
}

// attachPipe 建立 中心端<->探针 的内存连接, 返回拨号函数。
func attachPipe(center *Center) func(string) (net.Conn, error) {
	return func(addr string) (net.Conn, error) {
		client, server := net.Pipe()
		center.wg.Add(1)
		go func() {
			defer center.wg.Done()
			defer func() {
				if r := recover(); r != nil {
					_ = server.Close()
				}
			}()
			center.serveConnInner(server)
		}()
		return client, nil
	}
}

// newTestProbe 构造已接好内存管道的探针。
func newTestProbe(t *testing.T, center *Center, id, name, token string, exec ExecFunc) *Probe {
	t.Helper()
	p := NewProbe(ProbeConfig{
		Enabled:      true,
		CenterAddr:   "pipe",
		Token:        token,
		ID:           id,
		Name:         name,
		HeartbeatSec: 1,
		ReconnectSec: 1,
	}, exec)
	p.withDialer(attachPipe(center))
	return p
}

// TestRegisterAndHeartbeat 覆盖: 注册 -> 上线回调 -> 节点信息 -> 心跳 -> 快照。
func TestRegisterAndHeartbeat(t *testing.T) {
	center := startTestCenter(t, "")

	var mu sync.Mutex
	var online []*NodeInfo
	var hbCount int
	center.OnOnline(func(i *NodeInfo) { mu.Lock(); online = append(online, i); mu.Unlock() })
	center.OnHeartbeat(func(id string, ld *Load) { mu.Lock(); hbCount++; mu.Unlock() })

	p := newTestProbe(t, center, "test-probe-1", "测试探针", "", nil)
	p.Start()
	defer p.Stop()

	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-1") }, "探针上线")

	mu.Lock()
	n := len(online)
	mu.Unlock()
	if n != 1 {
		t.Fatalf("期望 1 次上线回调, 实际 %d", n)
	}

	info := online[0]
	if info.OS == "" || info.Arch == "" || info.CPUCores <= 0 {
		t.Fatalf("节点信息不完整: %+v", info)
	}
	if info.Hostname == "" {
		t.Fatal("主机名缺失")
	}
	if len(info.Engines) != 3 {
		t.Fatalf("引擎探测结果异常: %+v", info.Engines)
	}

	waitFor(t, 10*time.Second, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return hbCount >= 1
	}, "收到心跳")

	snaps := center.Snapshots()
	if len(snaps) != 1 || snaps[0].ProbeID != "test-probe-1" {
		t.Fatalf("快照异常: %+v", snaps)
	}
	if snaps[0].Load == nil {
		t.Fatal("快照缺少负载信息")
	}
	if snaps[0].Name != "测试探针" {
		t.Fatalf("快照节点名异常: %s", snaps[0].Name)
	}
}

// TestBadTokenRejected 覆盖: 密钥错误 -> 注册被拒 -> 探针不上线且报 ErrBadToken。
func TestBadTokenRejected(t *testing.T) {
	center := startTestCenter(t, "secret-token")
	p := newTestProbe(t, center, "test-probe-bad", "bad", "wrong-token", nil)

	err := p.session()
	if !errors.Is(err, ErrBadToken) {
		t.Fatalf("期望 ErrBadToken, 实际 %v", err)
	}
	if center.Online("test-probe-bad") {
		t.Fatal("密钥错误仍注册成功")
	}
}

// TestBadProtocolRejected 覆盖: 协议版本不匹配 -> 拒绝。
func TestBadProtocolRejected(t *testing.T) {
	center := startTestCenter(t, "")

	// 手工构造一条旧协议注册消息
	client, server := net.Pipe()
	center.wg.Add(1)
	go func() { defer center.wg.Done(); center.serveConnInner(server) }()

	client.SetDeadline(time.Now().Add(5 * time.Second))
	var wmu sync.Mutex
	if err := WriteMessage(client, &wmu, &Envelope{
		Type: MsgRegister, ID: "old-probe", Protocol: 999,
	}); err != nil {
		t.Fatalf("写入注册消息失败: %v", err)
	}
	resp, err := ReadMessage(NewScanner(client))
	if err != nil {
		t.Fatalf("读取响应失败: %v", err)
	}
	if resp.Type != MsgRegisterOK || resp.Code == 0 {
		t.Fatalf("旧协议应被拒绝: %+v", resp)
	}
	if !strings.Contains(resp.Error, ErrBadProtocol.Error()) {
		t.Fatalf("错误信息异常: %s", resp.Error)
	}
	client.Close()
}

// TestTaskRoundTrip 覆盖: 任务下发 -> 确认 -> 进度 -> 执行 -> 结果回传。
func TestTaskRoundTrip(t *testing.T) {
	center := startTestCenter(t, "")

	progressed := make(chan string, 16)
	results := make(chan *TaskResult, 4)
	center.OnProgress(func(id, taskID, msg string) { progressed <- msg })
	center.OnResult(func(id string, r *TaskResult) { results <- r })

	exec := func(tk *TaskAssign, progress func(string)) (*TaskResult, error) {
		progress("步骤 1")
		progress("步骤 2")
		return &TaskResult{
			Status:   TaskDone,
			Summary:  "完成 " + tk.Target,
			Findings: []Finding{{Severity: "open", Title: tk.Target + ":80 开放"}},
		}, nil
	}

	p := newTestProbe(t, center, "test-probe-2", "执行探针", "", exec)
	p.Start()
	defer p.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-2") }, "探针上线")

	if err := center.AssignTask("test-probe-2", &TaskAssign{
		TaskID: "task-1", Kind: "port", Target: "10.0.0.5", Ports: "80",
	}); err != nil {
		t.Fatalf("任务下发失败: %v", err)
	}

	select {
	case r := <-results:
		if r.TaskID != "task-1" {
			t.Fatalf("结果任务 ID 不符: %s", r.TaskID)
		}
		if r.Status != TaskDone {
			t.Fatalf("任务状态异常: %s (%s)", r.Status, r.Error)
		}
		if len(r.Findings) != 1 || r.Summary == "" {
			t.Fatalf("结果内容异常: %+v", r)
		}
		if r.FinishedAt == 0 || r.StartedAt == 0 {
			t.Fatalf("执行时间戳缺失: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("等待任务结果超时")
	}

	select {
	case msg := <-progressed:
		if msg == "" {
			t.Fatal("进度内容为空")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("未收到任务进度")
	}
}

// TestTaskFailureReported 覆盖: 执行器报错 -> 回传 failed 且带错误信息。
func TestTaskFailureReported(t *testing.T) {
	center := startTestCenter(t, "")
	results := make(chan *TaskResult, 4)
	center.OnResult(func(id string, r *TaskResult) { results <- r })

	exec := func(tk *TaskAssign, progress func(string)) (*TaskResult, error) {
		return nil, fmt.Errorf("目标不可达")
	}
	p := newTestProbe(t, center, "test-probe-3", "失败探针", "", exec)
	p.Start()
	defer p.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-3") }, "探针上线")

	if err := center.AssignTask("test-probe-3", &TaskAssign{TaskID: "task-fail", Kind: "port", Target: "x"}); err != nil {
		t.Fatalf("下发失败: %v", err)
	}
	select {
	case r := <-results:
		if r.Status != TaskFailed || !strings.Contains(r.Error, "目标不可达") {
			t.Fatalf("失败结果未正确回传: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("等待失败结果超时")
	}
}

// TestExecutorPanicRecovered 覆盖: 执行器 panic -> 回传 failed 而非崩溃/断连。
func TestExecutorPanicRecovered(t *testing.T) {
	center := startTestCenter(t, "")
	results := make(chan *TaskResult, 4)
	center.OnResult(func(id string, r *TaskResult) { results <- r })

	exec := func(tk *TaskAssign, progress func(string)) (*TaskResult, error) {
		panic("执行器内部崩溃")
	}
	p := newTestProbe(t, center, "test-probe-panic", "崩溃探针", "", exec)
	p.Start()
	defer p.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-panic") }, "探针上线")

	if err := center.AssignTask("test-probe-panic", &TaskAssign{TaskID: "task-panic", Kind: "port", Target: "x"}); err != nil {
		t.Fatalf("下发失败: %v", err)
	}
	select {
	case r := <-results:
		if r.Status != TaskFailed || r.Error == "" {
			t.Fatalf("panic 未转化为失败结果: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("panic 后未回传结果")
	}
}

// TestNoExecutorRejected 覆盖: 探针未配置执行器 -> 拒绝任务但连接保持。
func TestNoExecutorRejected(t *testing.T) {
	center := startTestCenter(t, "")
	p := newTestProbe(t, center, "test-probe-4", "无执行器", "", nil)
	p.Start()
	defer p.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-4") }, "探针上线")

	_ = center.AssignTask("test-probe-4", &TaskAssign{TaskID: "task-reject", Kind: "port", Target: "x"})
	time.Sleep(500 * time.Millisecond)
	if !center.Online("test-probe-4") {
		t.Fatal("拒绝任务后不应断连")
	}
}

// TestTaskCancel 覆盖: 取消下发 -> 任务终止并回传取消原因。
func TestTaskCancel(t *testing.T) {
	center := startTestCenter(t, "")
	results := make(chan *TaskResult, 4)
	center.OnResult(func(id string, r *TaskResult) { results <- r })

	exec := func(tk *TaskAssign, progress func(string)) (*TaskResult, error) {
		progress("阻塞中")
		time.Sleep(10 * time.Second)
		return &TaskResult{Status: TaskDone}, nil
	}
	p := newTestProbe(t, center, "test-probe-cancel", "取消探针", "", exec)
	p.Start()
	defer p.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-cancel") }, "探针上线")

	if err := center.AssignTask("test-probe-cancel", &TaskAssign{TaskID: "task-cancel", Kind: "port", Target: "x"}); err != nil {
		t.Fatalf("下发失败: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := center.CancelTask("test-probe-cancel", "task-cancel"); err != nil {
		t.Fatalf("取消失败: %v", err)
	}
	select {
	case r := <-results:
		if r.Status != TaskFailed || !strings.Contains(r.Error, "取消") {
			t.Fatalf("取消结果异常: %+v", r)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("取消后未回传结果")
	}
}

// TestDuplicateTaskRejected 覆盖: 同一任务 ID 重复下发 -> 拒绝。
func TestDuplicateTaskRejected(t *testing.T) {
	center := startTestCenter(t, "")
	results := make(chan *TaskResult, 8)
	center.OnResult(func(id string, r *TaskResult) { results <- r })

	release := make(chan struct{})
	exec := func(tk *TaskAssign, progress func(string)) (*TaskResult, error) {
		<-release
		return &TaskResult{Status: TaskDone, Summary: "done"}, nil
	}
	p := newTestProbe(t, center, "test-probe-dup", "重复探针", "", exec)
	p.Start()
	defer p.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-dup") }, "探针上线")

	task := &TaskAssign{TaskID: "task-dup", Kind: "port", Target: "x"}
	if err := center.AssignTask("test-probe-dup", task); err != nil {
		t.Fatalf("首次下发失败: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	// 第二次同 ID 下发应被探针拒绝(不会有第二个结果)
	_ = center.AssignTask("test-probe-dup", task)
	close(release)

	count := 0
	timeout := time.After(8 * time.Second)
	for {
		select {
		case <-results:
			count++
			if count > 1 {
				t.Fatalf("重复任务被执行了 %d 次", count)
			}
		case <-time.After(1500 * time.Millisecond):
			if count == 0 {
				t.Fatal("未收到任务结果")
			}
			return
		case <-timeout:
			t.Fatal("等待结果超时")
		}
	}
}

// TestOfflineCallback 覆盖: 探针停止 -> 中心端回调离线。
func TestOfflineCallback(t *testing.T) {
	center := startTestCenter(t, "")
	offline := make(chan string, 4)
	center.OnOffline(func(id, reason string) { offline <- id })

	p := newTestProbe(t, center, "test-probe-5", "离线探针", "", nil)
	p.Start()
	waitFor(t, 10*time.Second, func() bool { return center.Online("test-probe-5") }, "探针上线")

	p.Stop()
	select {
	case id := <-offline:
		if id != "test-probe-5" {
			t.Fatalf("离线回调 ID 不符: %s", id)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("等待离线回调超时")
	}
	if center.Online("test-probe-5") {
		t.Fatal("离线后仍标记在线")
	}
}

// TestReconnectReplacesOldConn 覆盖: 同 ID 重连 -> 旧连接被替换, 仅保留一条在线记录。
func TestReconnectReplacesOldConn(t *testing.T) {
	center := startTestCenter(t, "")
	offline := make(chan string, 8)
	center.OnOffline(func(id, reason string) { offline <- id })

	p1 := newTestProbe(t, center, "dup-id", "第一连接", "", nil)
	p1.Start()
	defer p1.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("dup-id") }, "第一连接上线")

	p2 := newTestProbe(t, center, "dup-id", "第二连接", "", nil)
	p2.Start()
	defer p2.Stop()
	waitFor(t, 10*time.Second, func() bool {
		snaps := center.Snapshots()
		return len(snaps) == 1 && snaps[0].Name == "第二连接"
	}, "重连替换旧连接")

	if got := len(center.OnlineIDs()); got != 1 {
		t.Fatalf("在线探针数期望 1, 实际 %d", got)
	}
}

// TestAssignToUnknownProbe 覆盖: 向不在线探针下发 -> ErrProbeOffline。
func TestAssignToUnknownProbe(t *testing.T) {
	center := startTestCenter(t, "")
	err := center.AssignTask("no-such-probe", &TaskAssign{TaskID: "t", Kind: "port", Target: "x"})
	if !errors.Is(err, ErrProbeOffline) {
		t.Fatalf("期望 ErrProbeOffline, 实际 %v", err)
	}
	if err := center.CancelTask("no-such-probe", "t"); !errors.Is(err, ErrProbeOffline) {
		t.Fatalf("取消期望 ErrProbeOffline, 实际 %v", err)
	}
}

// TestCenterStats 覆盖: 统计信息与实际在线数一致。
func TestCenterStats(t *testing.T) {
	center := startTestCenter(t, "tok")
	p := newTestProbe(t, center, "stat-probe", "统计探针", "tok", nil)
	p.Start()
	defer p.Stop()
	waitFor(t, 10*time.Second, func() bool { return center.Online("stat-probe") }, "探针上线")

	st := center.Stats()
	if st.OnlineCount != 1 || st.HeartbeatSec != 1 || !st.TokenRequired {
		t.Fatalf("统计异常: %+v", st)
	}
	if st.StartedAt == "" || st.OfflineSec != 5 {
		t.Fatalf("统计时间/离线阈值异常: %+v", st)
	}
	// 未真实 Listen 时 running 应为 false(测试直连管道)
	if st.Running {
		t.Fatalf("管道模式不应标记为运行中: %+v", st)
	}
}

// TestNodeInfoCollect 覆盖: 节点信息采集(受限环境下也必须有基础字段)。
func TestNodeInfoCollect(t *testing.T) {
	info := CollectNodeInfo("单元测试节点", "9.9.9")
	if info.Name != "单元测试节点" || info.Version != "9.9.9" {
		t.Fatalf("基础字段异常: %+v", info)
	}
	if info.OS == "" || info.Arch == "" || info.CPUCores <= 0 {
		t.Fatalf("系统字段异常: %+v", info)
	}
	if info.StartedAt == "" {
		t.Fatal("启动时间缺失")
	}
	if len(info.Engines) != 3 {
		t.Fatalf("引擎列表异常: %+v", info.Engines)
	}
	// 名称缺省时回退主机名
	info2 := CollectNodeInfo("", "9.9.9")
	if info2.Name == "" {
		t.Fatal("名称缺省未回退主机名")
	}
}

// TestCPUPercent 覆盖: CPU/内存占比计算与边界。
func TestCPUPercent(t *testing.T) {
	prev := CpuSample{Total: 100, Idle: 40}
	cur := CpuSample{Total: 200, Idle: 80}
	if got := CPUPercent(prev, cur); got != 60 {
		t.Fatalf("CPU 占比期望 60, 实际 %v", got)
	}
	if got := CPUPercent(CpuSample{}, cur); got != 0 {
		t.Fatalf("无前置采样期望 0, 实际 %v", got)
	}
	if got := CPUPercent(cur, prev); got != 0 {
		t.Fatalf("采样回退期望 0, 实际 %v", got)
	}
	// idle 超过总增量(时钟回拨等异常)不出现负值
	if got := CPUPercent(CpuSample{Total: 100, Idle: 0}, CpuSample{Total: 200, Idle: 500}); got != 0 {
		t.Fatalf("异常采样期望 0, 实际 %v", got)
	}
	if got := MemPercent(0, 100); got != 0 {
		t.Fatalf("总量为 0 期望 0, 实际 %v", got)
	}
	if got := MemPercent(200, 50); got != 25 {
		t.Fatalf("内存占比期望 25, 实际 %v", got)
	}
}

// TestSampleCPU 覆盖: CPU 采样在当前平台可返回合理结构(不 panic)。
func TestSampleCPU(t *testing.T) {
	s := SampleCPU()
	if s.At.IsZero() {
		t.Fatal("采样时间缺失")
	}
	// Windows 用 GetTickCount64(Idle=0), 其它平台读 /proc/stat
	if s.Total == 0 {
		t.Log("警告: 本平台 CPU 累计值不可用(受限环境)")
	}
}

// TestSanitizeID 覆盖: 主机名 -> ID 规范化。
func TestSanitizeID(t *testing.T) {
	cases := map[string]string{
		"WIN-SERVER.01": "win-server-01",
		"host name":     "host-name",
		"a_b-1":         "a_b-1",
		"正常中文":          "probe",
		"":              "probe",
	}
	for in, want := range cases {
		if got := sanitizeID(in); got != want {
			t.Fatalf("sanitizeID(%q) = %q, 期望 %q", in, got, want)
		}
	}
}

// TestTimeoutOf 覆盖: 任务超时取值(显式 > 默认 30 分钟)。
func TestTimeoutOf(t *testing.T) {
	if got := timeoutOf(&TaskAssign{TimeoutSec: 30}); got != 30*time.Second {
		t.Fatalf("显式超时异常: %v", got)
	}
	if got := timeoutOf(&TaskAssign{}); got != 30*time.Minute {
		t.Fatalf("默认超时异常: %v", got)
	}
}

// TestDescribeTask 覆盖: 任务描述文本。
func TestDescribeTask(t *testing.T) {
	s := describeTask(&TaskAssign{Kind: "port", Target: "10.0.0.1", Ports: "80,443"})
	if !strings.Contains(s, "port") || !strings.Contains(s, "10.0.0.1") || !strings.Contains(s, "80,443") {
		t.Fatalf("任务描述异常: %s", s)
	}
	if describeTask(nil) != "-" {
		t.Fatal("nil 任务描述异常")
	}
}

// TestReadMessageCompatLongLine 覆盖: 超长消息的边界行为。
//
// NewScanner 上限 4MB: 4MB 以内常规路径可读; 超过后常规路径报
// bufio.ErrTooLong, 兼容路径给出明确错误(不返回半个消息造成协议错位)。
func TestReadMessageCompatLongLine(t *testing.T) {
	// 4MB 以内: 常规路径即可读取
	normal := strings.Repeat("x", 300*1024)
	msg, err := ReadMessage(NewScanner(strings.NewReader(string(buildBigJSON([]byte(normal))))))
	if err != nil {
		t.Fatalf("常规长度消息读取失败: %v", err)
	}
	if len(msg.Message) != len(normal) {
		t.Fatalf("常规消息内容不完整: %d", len(msg.Message))
	}

	// 超过 4MB: 常规路径超限
	huge := strings.Repeat("x", 5*1024*1024)
	raw := string(buildBigJSON([]byte(huge)))
	if _, err := ReadMessage(NewScanner(strings.NewReader(raw))); !errors.Is(err, bufio.ErrTooLong) {
		t.Fatalf("超过 4MB 应报 ErrTooLong, 实际 %v", err)
	}
	// 兼容路径: 转化为明确的业务错误, 不返回残缺消息
	if m, err := readMessageCompat(NewScanner(strings.NewReader(raw))); err == nil {
		t.Fatalf("超限应报错, 实际返回 %+v", m)
	} else if !strings.Contains(err.Error(), "上限") {
		t.Fatalf("错误信息应说明上限, 实际: %v", err)
	}
}

// TestEngineProbeNoError 覆盖: 引擎探测在无 bin 目录时静默降级。
func TestEngineProbeNoError(t *testing.T) {
	dir := binDirPath()
	if filepath.Base(dir) != "bin" {
		t.Fatalf("bin 目录约定异常: %s", dir)
	}
	evs := engineVersions()
	if len(evs) != 3 {
		t.Fatalf("引擎条目数异常: %d", len(evs))
	}
	for _, e := range evs {
		if e.Name == "" {
			t.Fatal("引擎条目缺少名称")
		}
	}
}

// ===== 测试辅助 =====

// buildBigJSON 构造一条超长(>256KB)的合法心跳消息。
func buildBigJSON(payload []byte) []byte {
	env := Envelope{Type: MsgHeartbeat, ID: "big", Message: string(payload)}
	b, _ := json.Marshal(env)
	return append(b, '\n')
}

func waitFor(t *testing.T, d time.Duration, cond func() bool, what string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("等待超时: %s", what)
}
