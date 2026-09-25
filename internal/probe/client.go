package probe

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===== 探针端 SDK =====
//
// 职责: 主动连接中心端 -> 注册(带节点信息) -> 心跳保活 -> 接收任务并执行 -> 回传结果。
// 断线自动重连(指数退避, 上限 60s), 中心端不可达时只记日志不阻塞本地功能(降级不崩溃)。
//
// 执行器注入: Executor 由调用方提供(中心端执行本地扫描的同一入口),
// 探针端不依赖具体扫描实现, 便于单测与后续替换。

// ExecFunc 任务执行函数: 由上层注入(通常是"以探针身份跑一次本地扫描")。
// 返回值 Result 为归一化后的结果; error 表示执行失败(仍会回传 failed 结果)。
type ExecFunc func(t *TaskAssign, progress func(string)) (*TaskResult, error)

// ProbeConfig 探针端配置(exe 同目录 probe.json 的 client 段)。
type ProbeConfig struct {
	Enabled      bool   `json:"enabled"`      // 默认关闭: 不连接中心端, 保持单机模式
	CenterAddr   string `json:"centerAddr"`   // 中心端地址, 如 192.168.1.10:8600
	Token        string `json:"token"`        // 节点密钥(与中心端一致)
	ID           string `json:"id"`           // 探针标识(空则由 hostname 生成并落盘保持稳定)
	Name         string `json:"name"`         // 节点别名(默认 hostname)
	HeartbeatSec int    `json:"heartbeatSec"` // 心跳间隔(秒), 默认 15
	ReconnectSec int    `json:"reconnectSec"` // 初始重连等待(秒), 默认 5
}

// Probe 探针端运行时。
type Probe struct {
	cfg ProbeConfig
	id  string

	mu     sync.Mutex
	conn   net.Conn
	closed bool
	exec   ExecFunc

	running map[string]bool // taskID -> 执行中(用于取消与进度)
	cancel  map[string]chan struct{}
	cur     string // 当前任务描述(心跳上报)

	// done/doneOrder 已完成任务 ID 去重窗口(环形): 见 completedTasks 说明
	done      map[string]bool
	doneOrder []string

	prevCPU CpuSample
	startAt time.Time

	// dial 连接工厂: 默认走 TCP 拨号, 测试可替换为内存管道(见 withDialer)。
	dial func(addr string) (net.Conn, error)

	// update 自更新执行器(nil = 不支持, 收到更新指令仅记日志)。
	//
	// 【为什么默认 nil】探针的核心职责是执行扫描任务, 自更新是附加能力。未显式
	// 启用时收到指令只打日志不动作, 保证行为可预期(规则 5: 新功能默认关闭)。
	update *SelfUpdater
	// onUpdated 更新完成回调(装配层用于提示用户重启)。
	onUpdated func(UpdateResult)
	// updateOnce 保证一次进程生命周期内只尝试一次自更新(重连会反复下发指令)。
	updateOnce sync.Once

	logf func(string)
	wg   sync.WaitGroup
}

// SetSelfUpdater 启用探针自动更新(装配层调用; 传 nil 则关闭)。
func (p *Probe) SetSelfUpdater(u *SelfUpdater) { p.update = u }

// OnUpdated 注册更新结果回调(更新成功后装配层可据此提示重启)。
func (p *Probe) OnUpdated(f func(UpdateResult)) { p.onUpdated = f }

// NewProbe 构造探针端(不连接; 由 Start 启动)。
func NewProbe(cfg ProbeConfig, exec ExecFunc) *Probe {
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 15
	}
	if cfg.ReconnectSec <= 0 {
		cfg.ReconnectSec = 5
	}
	id := strings.TrimSpace(cfg.ID)
	if id == "" {
		id = loadOrCreateProbeID(cfg.Name)
	}
	if cfg.Name == "" {
		cfg.Name, _ = os.Hostname()
	}
	p := &Probe{
		cfg:     cfg,
		id:      id,
		exec:    exec,
		running: make(map[string]bool),
		cancel:  make(map[string]chan struct{}),
		done:    make(map[string]bool),
		startAt: time.Now(),
		logf:    logGlobal, // 未注入全局日志时静默
		dial: func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 8*time.Second)
		},
	}
	p.prevCPU = SampleCPU()
	return p
}

// withDialer 替换连接工厂(测试注入内存管道用; 生产不调用)。
func (p *Probe) withDialer(f func(addr string) (net.Conn, error)) { p.dial = f }

// SetDialer 替换拨号实现(导出给装配层/集成测试用)。
//
// 用途: 沙箱或受限网络下无法真实回环连接时, 用内存管道把探针端与中心端接起来
// 做全链路验证。生产正常运行不调用, 走 net.DialTimeout 默认实现。
// f 为 nil 时恢复默认拨号, 因此可安全用于"临时替换后还原"的场景。
func (p *Probe) SetDialer(f func(addr string) (net.Conn, error)) {
	if f == nil {
		p.dial = func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 8*time.Second)
		}
		return
	}
	p.dial = f
}

// SetLogger 注入日志函数(并入 yugsight.log)。
func (p *Probe) SetLogger(f func(string)) {
	if f != nil {
		p.logf = f
	}
}

// ID 探针标识。
func (p *Probe) ID() string { return p.id }

// Start 启动探针连接循环(非阻塞, 后台自动重连)。
func (p *Probe) Start() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.mu.Unlock()
	p.wg.Add(1)
	go p.loop()
	p.logf(fmt.Sprintf("探针客户端启动: id=%s 目标中心端 %s", p.id, p.cfg.CenterAddr))
}

// Stop 关闭探针(断开连接, 等待循环退出)。
func (p *Probe) Stop() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	c := p.conn
	p.mu.Unlock()
	if c != nil {
		_ = c.Close()
	}
	p.wg.Wait()
	p.logf("探针客户端已停止")
}

// Online 当前是否与中心端保持连接。
func (p *Probe) Online() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.conn != nil
}

// loop 连接 - 注册 - 收发 - 断开重连(退避)。
func (p *Probe) loop() {
	defer p.wg.Done()
	backoff := time.Duration(p.cfg.ReconnectSec) * time.Second
	for {
		p.mu.Lock()
		if p.closed {
			p.mu.Unlock()
			return
		}
		p.mu.Unlock()

		err := p.session()
		if err != nil {
			if errors.Is(err, ErrBadToken) || errors.Is(err, ErrBadProtocol) {
				// 密钥/协议不匹配属配置错误, 重试无意义: 记日志后退避拉长(便于用户改配置后自愈)
				p.logf("探针连接被拒: " + err.Error() + " (请检查 probe.json 的 token 与中心端版本)")
				backoff = 60 * time.Second
			} else {
				p.logf("探针连接中断, " + backoff.String() + " 后重连: " + err.Error())
			}
		} else {
			backoff = time.Duration(p.cfg.ReconnectSec) * time.Second
		}
		p.mu.Lock()
		closed := p.closed
		p.mu.Unlock()
		if closed {
			return
		}
		select {
		case <-time.After(backoff):
		}
		if backoff < 60*time.Second {
			backoff *= 2
			if backoff > 60*time.Second {
				backoff = 60 * time.Second
			}
		}
	}
}

// session 单次连接生命周期(阻塞直到断开)。
func (p *Probe) session() error {
	dial := p.dial
	if dial == nil {
		dial = func(addr string) (net.Conn, error) {
			return net.DialTimeout("tcp", addr, 8*time.Second)
		}
	}
	nc, err := dial(p.cfg.CenterAddr)
	if err != nil {
		return err
	}
	defer nc.Close()
	if tcp, ok := nc.(*net.TCPConn); ok {
		_ = tcp.SetKeepAlive(true)
		_ = tcp.SetKeepAlivePeriod(30 * time.Second)
	}
	sc := NewScanner(nc)
	var wmu sync.Mutex

	// 注册
	if err := WriteMessage(nc, &wmu, &Envelope{
		Type:     MsgRegister,
		ID:       p.id,
		Token:    p.cfg.Token,
		Protocol: ProtocolVersion,
		Info:     CollectNodeInfo(p.cfg.Name, appVerForProbe()),
		Load:     p.sampleLoad(),
	}); err != nil {
		return err
	}
	_ = nc.SetReadDeadline(time.Now().Add(15 * time.Second))
	resp, err := readMessageCompat(sc)
	if err != nil {
		return err
	}
	if resp.Type != MsgRegisterOK {
		return fmt.Errorf("中心端未返回注册确认(%s)", resp.Type)
	}
	if resp.Code != 0 {
		if strings.Contains(resp.Error, ErrBadToken.Error()) {
			return ErrBadToken
		}
		if strings.Contains(resp.Error, ErrBadProtocol.Error()) {
			return ErrBadProtocol
		}
		return fmt.Errorf("注册失败: %s", resp.Error)
	}
	if resp.HeartbeatSec > 0 {
		p.cfg.HeartbeatSec = resp.HeartbeatSec
	}
	// 版本不一致时中心端会回带更新指令, 这里异步执行。
	//
	// 【为什么必须异步】更新要下载 6-7MB 并替换文件, 耗时数秒到数十秒。若在读循环里
	// 同步做, 期间心跳协程虽在跑, 但主循环无法读消息 —— 中心端等不到任务回执会认为
	// 探针卡死, 且读超时可能直接把连接掐掉。异步执行让注册流程立即继续, 更新在后台
	// 完成后再提示重启。
	//
	// 【为什么用 go 而不是塞进心跳协程】更新是一次性动作, 不需要周期性触发;
	// 独立 goroutine 做完即退出, 生命周期清晰。
	if resp.Update != nil {
		p.maybeSelfUpdate(resp.Update)
	}
	p.mu.Lock()
	p.conn = nc
	p.mu.Unlock()
	p.logf(fmt.Sprintf("已连接中心端 %s (心跳 %ds)", p.cfg.CenterAddr, p.cfg.HeartbeatSec))
	defer func() {
		p.mu.Lock()
		if p.conn == nc {
			p.conn = nil
		}
		p.mu.Unlock()
	}()

	// 心跳协程(退出信号触发即结束)
	hbStop := make(chan struct{})
	var hbWG sync.WaitGroup
	hbWG.Add(1)
	go func() {
		defer hbWG.Done()
		tk := time.NewTicker(time.Duration(p.cfg.HeartbeatSec) * time.Second)
		defer tk.Stop()
		for {
			select {
			case <-hbStop:
				return
			case <-tk.C:
				_ = nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
				if err := WriteMessage(nc, &wmu, &Envelope{
					Type: MsgHeartbeat,
					ID:   p.id,
					Load: p.sampleLoad(),
					Info: nil, // 常规心跳只报负载, 信息变更时随注册刷新
				}); err != nil {
					return
				}
			}
		}
	}()
	defer func() {
		close(hbStop)
		hbWG.Wait()
	}()

	// 主循环: 读消息
	readTimeout := time.Duration(p.cfg.HeartbeatSec*3) * time.Second
	if readTimeout < 45*time.Second {
		readTimeout = 45 * time.Second
	}
	for {
		_ = nc.SetReadDeadline(time.Now().Add(readTimeout))
		msg, err := readMessageCompat(sc)
		if err != nil {
			if err == io.EOF {
				return errors.New("中心端断开连接")
			}
			return err
		}
		switch msg.Type {
		case MsgRegisterOK:
			// 中心端在重连场景下的重复注册确认: 忽略
		case MsgPing:
			// 中心端保活探测: 回 pong(不可回 ping —— 两端互回会形成死循环)
			_ = nc.SetWriteDeadline(time.Now().Add(10 * time.Second))
			_ = WriteMessage(nc, &wmu, &Envelope{Type: MsgPong, ID: p.id, TS: time.Now().Unix()})
		case MsgPong:
			// 中心端对心跳的应答: 无需处理。它能刷新上面的读超时
			// (收到任意消息即视为链路活跃), 这正是保活的目的。
		case MsgTaskAssign:
			if msg.Task != nil {
				p.onAssign(nc, &wmu, msg.Task)
			}
		case MsgTaskCancel:
			if msg.Task != nil {
				p.cancelTask(msg.Task.TaskID)
			}
		default:
			// 未知消息忽略(向前兼容)
		}
	}
}

// maybeSelfUpdate 处理中心端下发的更新指令。
//
// 【为什么要防重复】探针会因网络抖动频繁重连, 每次注册中心端都会比对版本并下发
// 指令(中心端只看"版本号不同", 不知道探针是否已经开始下载)。若不做去重, 一次抖动
// 就能触发多轮并发下载, 把带宽打满、并互相覆盖临时文件。这里用 updateOnce 保证
// 同一进程生命周期内只执行一次; 更新成功后进程需要重启才生效, 重启后版本已一致,
// 自然不会再触发。
func (p *Probe) maybeSelfUpdate(d *UpdateDirective) {
	if p.update == nil {
		p.logf(fmt.Sprintf("中心端提示可更新到 v%s, 但本机未启用自动更新(请手动替换程序)", d.Version))
		return
	}
	p.updateOnce.Do(func() {
		go func() {
			// 更新是"用网络数据覆盖正在运行的程序", 任何异常都必须被兜住:
			// 一个 panic 会带走整个探针进程(它有顶层 recover, 但那是最后一道防线)。
			defer func() {
				if r := recover(); r != nil {
					p.logf(fmt.Sprintf("自动更新异常(已忽略, 保持当前版本): %v", r))
				}
			}()
			res := p.update.Apply(d)
			if res.Updated {
				p.logf(fmt.Sprintf("自动更新完成: 已更新到 v%s, 请重启探针使新版本生效", res.Version))
			} else if res.Reason != "" {
				p.logf("自动更新未执行: " + res.Reason)
			}
			// 回调在日志之后: 装配层可能弹窗或写状态文件, 让它拿到最终结论
			if p.onUpdated != nil {
				p.onUpdated(res)
			}
		}()
	})
}

// completedTasks 已完成任务 ID 的环形保留上限(去重窗口)。
//
// 取值理由: 内存开销极小(每条仅 ID 字符串), 覆盖"任务完成到结果回传被中心端确认"
// 这段窗口; 超过后按最早完成顺序淘汰, 淘汰后同 ID 再下发会被当作新任务执行。
const completedTasks = 256

// markDone 把任务 ID 记入已完成集合(带去重与淘汰)。
func (p *Probe) markDone(taskID string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.done[taskID] {
		p.done[taskID] = true
		p.doneOrder = append(p.doneOrder, taskID)
		if len(p.doneOrder) > completedTasks {
			old := p.doneOrder[0]
			p.doneOrder = p.doneOrder[1:]
			delete(p.done, old)
		}
	}
}

// isDuplicate 任务是否已被处理过: 正在执行中, 或已完成(在去重窗口内)。
//
// 存在的意义: 中心端在"结果回传丢失/连接抖动重派"时会重复下发同一 taskId;
// 若执行完就从 running 表删掉, 重派的同 ID 任务会被再执行一遍(重复扫描 + 重复回传),
// 中心端也会收到两条同 ID 结果。
func (p *Probe) isDuplicate(taskID string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.running[taskID] || p.done[taskID]
}

// onAssign 收到任务: 先确认(accepted/rejected), 再异步执行避免阻塞读循环。
func (p *Probe) onAssign(nc net.Conn, wmu *sync.Mutex, t *TaskAssign) {
	defer func() {
		if r := recover(); r != nil {
			p.logf(fmt.Sprintf("任务 %s 处理异常(已恢复): %v", t.TaskID, r))
		}
	}()
	if p.isDuplicate(t.TaskID) {
		_ = WriteMessage(nc, wmu, &Envelope{Type: MsgTaskAck, ID: p.id, Code: 1, Error: "任务重复下发", Task: t})
		return
	}
	p.mu.Lock()
	if p.exec == nil {
		p.mu.Unlock()
		_ = WriteMessage(nc, wmu, &Envelope{Type: MsgTaskAck, ID: p.id, Code: 1, Error: "探针未配置执行器(扫描能力不可用)", Task: t})
		return
	}
	// 登记栏位与去重集合必须在同一临界区写入: 否则两个协程都可能通过 isDuplicate
	// 检查后再各自执行一次(TOCTOU), 去重失效。
	p.running[t.TaskID] = true
	p.done[t.TaskID] = true
	p.doneOrder = append(p.doneOrder, t.TaskID)
	if len(p.doneOrder) > completedTasks {
		old := p.doneOrder[0]
		p.doneOrder = p.doneOrder[1:]
		delete(p.done, old)
	}
	cancelCh := make(chan struct{})
	p.cancel[t.TaskID] = cancelCh
	p.cur = describeTask(t)
	p.mu.Unlock()

	_ = WriteMessage(nc, wmu, &Envelope{Type: MsgTaskAck, ID: p.id, Code: 0, Task: t})
	p.logf(fmt.Sprintf("收到任务 %s: %s", t.TaskID, describeTask(t)))

	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		start := time.Now()
		res := p.runTask(t, cancelCh, func(msg string) {
			_ = WriteMessage(nc, wmu, &Envelope{Type: MsgTaskProgress, ID: p.id, Task: t, Message: msg})
		})
		res.StartedAt = start.Unix()
		res.FinishedAt = time.Now().Unix()
		if res.DurationMs == 0 {
			res.DurationMs = time.Since(start).Milliseconds()
		}
		p.mu.Lock()
		delete(p.running, t.TaskID)
		delete(p.cancel, t.TaskID)
		p.cur = ""
		p.mu.Unlock()

		// 结果先回传再允许该 ID 被重新执行: 回传失败(连接已断)时中心端会重派,
		// 此时 done 里仍有记录 -> 直接拒绝重派, 避免同 ID 任务被跑第二遍。
		_ = WriteMessage(nc, wmu, &Envelope{Type: MsgTaskResult, ID: p.id, Result: res})
		p.logf(fmt.Sprintf("任务 %s 执行完成: %s", t.TaskID, res.Summary))
	}()
}

// runTask 执行任务(内部 recover 兜底, 保证必回结果)。
func (p *Probe) runTask(t *TaskAssign, cancelCh chan struct{}, progress func(string)) (res *TaskResult) {
	res = &TaskResult{TaskID: t.TaskID, Status: TaskFailed}
	defer func() {
		if r := recover(); r != nil {
			res.Status = TaskFailed
			res.Error = fmt.Sprintf("探针执行异常: %v", r)
		}
		if res.Status == "" {
			res.Status = TaskFailed
		}
	}()
	done := make(chan *TaskResult, 1)
	errCh := make(chan error, 1)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				errCh <- fmt.Errorf("执行panic: %v", r)
			}
		}()
		r, err := p.exec(t, progress)
		if err != nil {
			errCh <- err
			return
		}
		done <- r
	}()
	select {
	case r := <-done:
		if r == nil {
			return &TaskResult{TaskID: t.TaskID, Status: TaskFailed, Error: "执行器返回空结果"}
		}
		r.TaskID = t.TaskID
		if r.Status == "" {
			r.Status = TaskDone
		}
		return r
	case err := <-errCh:
		return &TaskResult{TaskID: t.TaskID, Status: TaskFailed, Error: err.Error()}
	case <-cancelCh:
		return &TaskResult{TaskID: t.TaskID, Status: TaskFailed, Error: "任务已被中心端取消"}
	case <-time.After(timeoutOf(t)):
		return &TaskResult{TaskID: t.TaskID, Status: TaskFailed, Error: "任务执行超时(探针侧)"}
	}
}

// cancelTask 取消执行中的任务(仅通知, 底层扫描是否可中断由执行器决定)。
func (p *Probe) cancelTask(taskID string) {
	p.mu.Lock()
	ch := p.cancel[taskID]
	p.mu.Unlock()
	if ch == nil {
		return
	}
	select {
	case <-ch:
	default:
		close(ch)
		p.logf("任务 " + taskID + " 已取消")
	}
}

// sampleLoad 采集负载指标(CPU 由前后两次采样差值粗算)。
func (p *Probe) sampleLoad() *Load {
	cur := SampleCPU()
	cpu := CPUPercent(p.prevCPU, cur)
	p.prevCPU = cur
	var memPct float64
	if info := CollectMemBrief(); info != nil {
		memPct = MemPercent(info.total, info.used)
	}
	p.mu.Lock()
	running := len(p.running)
	curTask := p.cur
	p.mu.Unlock()
	return &Load{
		CPUPercent:   round1(cpu),
		MemPercent:   round1(memPct),
		TasksRunning: running,
		CurrentTask:  curTask,
		UptimeSec:    int64(time.Since(p.startAt).Seconds()),
	}
}

// MemBrief 内存快照(避免整包 NodeInfo 采集开销)。
type MemBrief struct {
	total uint64
	used  uint64
}

// CollectMemBrief 轻量内存采集(心跳用)。
func CollectMemBrief() *MemBrief {
	t, u, ok := memStatsOS()
	if !ok {
		return nil
	}
	return &MemBrief{total: t, used: u}
}

func timeoutOf(t *TaskAssign) time.Duration {
	if t.TimeoutSec > 0 {
		return time.Duration(t.TimeoutSec) * time.Second
	}
	return 30 * time.Minute // 默认上限, 防任务卡死占住连接
}

// readMessageCompat 读取消息并做"长行兜底"。
//
// bufio.Scanner 的缓冲上限必须在首次 Scan 之前设定(Scan 之后再调 Buffer 会 panic),
// 因此超限时不能就地扩容, 而是改为从底层 io.Reader 走一遍扩容版读取重试:
// 用 ReadMessage 拿到的 ErrTooLong 已消费掉部分字节, 这里改用 LineReader
// (基于 bufio.Reader.ReadString, 无固定上限) 补读整行。
//
// 注意: 该兜底仅在 Scanner 与底层 Reader 可分离(即常规流式连接)时有效;
// 若 Scanner 已越过 4MB 上限, 已读走的部分无法回退, 调用方应保证
// 使用 NewScanner 时缓冲上限足够, 或在超限时重连(此处返回错误由上层处理)。
func readMessageCompat(sc *bufio.Scanner) (*Envelope, error) {
	msg, err := ReadMessage(sc)
	if err == nil || !errors.Is(err, bufio.ErrTooLong) {
		return msg, err
	}
	// 已消费的片段无法回退: 明确报错而不是返回半个消息, 避免协议错位。
	return nil, fmt.Errorf("probe: 单条消息超过 %d 字节上限(建议精简结果或增大缓冲): %w",
		maxMessageBytes, err)
}

// describeTask 任务描述(日志/心跳展示)。
func describeTask(t *TaskAssign) string {
	if t == nil {
		return "-"
	}
	s := t.Kind + " " + t.Target
	if t.Ports != "" {
		s += " 端口 " + t.Ports
	}
	return s
}

func round1(f float64) float64 {
	return float64(int(f*10+0.5)) / 10
}

// appVerForProbe 探针上报的版本(与中心端 appVersion 同源, 由装配层注入)。
var probeVer = "1.0.0"

// SetProbeVersion 由装配层注入程序版本。
func SetProbeVersion(v string) {
	if strings.TrimSpace(v) != "" {
		probeVer = v
	}
}

func appVerForProbe() string { return probeVer }

// ===== 探针 ID 持久化 =====

// probeIDFile 探针 ID 落盘路径(exe 同目录 probe.id)。
func probeIDFile() string {
	exe, err := os.Executable()
	if err != nil {
		return "probe.id"
	}
	return filepath.Join(filepath.Dir(exe), "probe.id")
}

// loadOrCreateProbeID 读取持久化探针 ID; 不存在则按主机名生成并落盘。
// 落盘失败(只读目录等)不报错, 退回内存 ID(重启后 ID 变化, 仅影响历史归属)。
func loadOrCreateProbeID(name string) string {
	path := probeIDFile()
	if b, err := os.ReadFile(path); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	host, _ := os.Hostname()
	if name != "" {
		host = name
	}
	if host == "" {
		host = "probe"
	}
	id := sanitizeID(host) + "-" + strconv.FormatInt(time.Now().Unix()%100000, 10)
	_ = os.WriteFile(path, []byte(id), 0o644)
	return id
}

// sanitizeID 主机名 -> 安全 ID(仅保留字母数字与短横线)。
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '_':
			b.WriteRune(r)
		case r == '.' || r == ' ':
			b.WriteByte('-')
		}
	}
	if b.Len() == 0 {
		return "probe"
	}
	return b.String()
}
