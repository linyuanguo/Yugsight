package probe

import (
	"bufio"
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ===== 中心端探针管理服务 =====
//
// 职责: TCP 长连接监听 -> Token 鉴权 -> 探针在线状态管理 -> 节点信息落 DAO -> 任务下发。
// 单连接单 goroutine 读写(写侧加锁), 常驻直到连接断开或被 CancelAll。
//
// 连接生命周期:
//  1. 探针连上(或已连)后发 register(带 token + 节点信息);
//  2. 中心端校验 token/协议版本 -> 落库节点 -> 回 register_ok(带心跳间隔);
//  3. 探针周期 heartbeat(带负载) -> 中心端刷新 lastSeen/负载;
//  4. 中心端 AssignTask 找到在线连接 -> task_assign -> 探针 task_ack -> 执行 -> task_result;
//  5. 连接断开 -> 标记离线 + 回调通知(用于离线告警/任务重派)。

// ServerConfig 中心端配置(exe 同目录 probe.json 的 center 段)。
type ServerConfig struct {
	Enabled      bool   `json:"enabled"`      // 默认关闭: 不启动监听, 行为与单机版完全一致
	Listen       string `json:"listen"`       // 监听地址, 如 ":8600"(空则默认 :8600)
	Token        string `json:"token"`        // 节点密钥; 为空表示不校验(内网测试用)
	HeartbeatSec int    `json:"heartbeatSec"` // 推荐心跳间隔(秒), 默认 15
	OfflineSec   int    `json:"offlineSec"`   // 超过该秒数无心跳判离线, 默认 3*心跳
	MaxProbes    int    `json:"maxProbes"`    // 最大并发探针连接数, 默认 200
}

// verOrUnknown 版本号为空时给个人话说法(探针未上报版本属正常, 不该显示空白)。
func verOrUnknown(v string) string {
	if v == "" {
		return "未知"
	}
	return v
}

// agentVersionOf 从更新指令推导中心端当前 agent 版本(无指令时返回空串)。
func agentVersionOf(u *UpdateDirective) string {
	if u == nil {
		return ""
	}
	return u.Version
}

// Center 中心端探针管理服务。
type Center struct {
	cfg ServerConfig

	mu    sync.RWMutex
	conns map[string]*conn // probeID -> 连接
	ln    net.Listener

	// stopCh Stop() 时关闭, 立即唤醒 sweepLoop —— 否则 sweepLoop 只靠 ticker
	// 醒来(周期最大 OfflineSec=30s), Stop 的 wg.Wait 最坏要干等 30 秒。
	// 表现为关控制台/停服务时卡半分钟, 用户以为程序挂了。
	stopCh chan struct{}

	// 回调: 节点上线 / 节点离线 / 收到任务结果(由 api 层设置, 用于落库与推送)
	onOnline    func(*NodeInfo)
	onOffline   func(id, reason string)
	onHeartbeat func(id string, ld *Load)
	onResult    func(id string, r *TaskResult)
	onProgress  func(id string, taskID, msg string)

	// updateFor 版本不一致时生成更新指令(由装配层注入, 返回 nil 表示不支持自动更新)。
	//
	// 【为什么用回调而不是让 probe 包自己算】"当前 agent 版本是多少、更新包在哪"
	// 属于部署形态知识(main 包的 agentVersion 常量 + agents/ 目录布局), probe 包
	// 是通信层不该知道。注入回调既保持了依赖方向, 也让单测能塞入假实现验证下发逻辑。
	//
	// 参数带 (版本, 操作系统, 架构): 中心端据此前置判断"该给这台探针发哪个平台的包"。
	// 探针上报的 OS/Arch 在注册消息里就有, 直接传下来比在装配层再猜一次可靠得多 ——
	// 猜错会下发一个下不动的地址, 探针白跑一趟。
	updateFor func(reportVer, probeOS, probeArch string) *UpdateDirective

	// 任务执行回调: 中心端把任务下发给探针后, 结果回来时由上层接管落库
	logf func(string)

	wg        sync.WaitGroup
	closed    bool
	startedAt time.Time
}

// SetUpdateProvider 注入自动更新指令提供者(装配层调用; nil 表示关闭自动更新)。
//
// 关闭是默认状态: 未注入时更新指令恒为 nil, 探针端行为与升级前完全一致(规则 5)。
func (s *Center) SetUpdateProvider(f func(reportVer, probeOS, probeArch string) *UpdateDirective) {
	s.mu.Lock()
	s.updateFor = f
	s.mu.Unlock()
}

// updateProvider 读取更新提供者(并发安全)。
func (s *Center) updateProvider() func(string, string, string) *UpdateDirective {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.updateFor
}

// SuggestedUpdate 返回该版本/平台探针应执行的更新指令(供 API 层展示"可更新"列表用)。
func (s *Center) SuggestedUpdate(reportVer, probeOS, probeArch string) *UpdateDirective {
	f := s.updateProvider()
	if f == nil {
		return nil
	}
	return f(reportVer, probeOS, probeArch)
}

// conn 单条探针长连接。
//
// 并发模型: 读循环(serveConnInner)写 info/load/lastSeen, 而快照/心跳统计
// (Snapshots/Stats)由其它 goroutine 读 —— 因此这些字段统一用 mu 保护。
// 注意这与 wmu(保护 net.Conn 并发写)是两把不同的锁, 不要合并:
// mu 可能被长时间持有的调用方(如直接持有 *conn)连带阻塞写路径。
type conn struct {
	id    string
	c     net.Conn
	sc    *bufio.Scanner // 行读取器
	wmu   sync.Mutex    // 写锁(保护 net.Conn 的并发写)
	mu    sync.Mutex    // 状态锁(保护 info/load/lastSeen/remote/peerVersion)
	info  *NodeInfo
	load  *Load
	lastSeen    time.Time
	registered  bool
	remote      string
	peerVersion string
	center      *Center
}

// setInfo 更新节点信息(读循环内调用)。
func (c *conn) setInfo(i *NodeInfo) {
	c.mu.Lock()
	c.info = i
	c.mu.Unlock()
}

// setLoad 更新负载快照(心跳/注册时调用)。
func (c *conn) setLoad(l *Load) {
	c.mu.Lock()
	c.load = l
	c.mu.Unlock()
}

// touch 刷新最后活跃时间。
func (c *conn) touch() {
	c.mu.Lock()
	c.lastSeen = time.Now()
	c.mu.Unlock()
}

// snapshot 读取连接状态快照(并发安全)。
func (c *conn) snapshot() Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()
	sn := Snapshot{
		ProbeID:  c.id,
		Remote:   c.remote,
		Load:     c.load,
		LastSeen: c.lastSeen.Format("2006-01-02 15:04:05"),
		Info:     c.info,
	}
	if c.info != nil {
		sn.Name = c.info.Name
	}
	return sn
}

// idleFor 距上次活跃的时长(超时清理用)。
func (c *conn) idleFor() time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return time.Since(c.lastSeen)
}

// loadOf 读取负载快照(并发安全; 可能为 nil)。
func (c *conn) loadOf() *Load {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.load
}

// SetLogger 注入日志函数(并入 yugsight.log)。
func (s *Center) SetLogger(f func(string)) {
	if f != nil {
		s.logf = f
	}
}

// OnOnline 注册节点上线回调。
func (s *Center) OnOnline(f func(*NodeInfo)) { s.onOnline = f }

// OnOffline 注册节点离线回调(reason 为原因描述)。
func (s *Center) OnOffline(f func(id, reason string)) { s.onOffline = f }

// OnHeartbeat 注册心跳回调(用于刷新负载/在线时间)。
func (s *Center) OnHeartbeat(f func(id string, ld *Load)) { s.onHeartbeat = f }

// OnResult 注册任务结果回调。
func (s *Center) OnResult(f func(id string, r *TaskResult)) { s.onResult = f }

// OnProgress 注册任务进度回调(可选)。
func (s *Center) OnProgress(f func(id string, taskID, msg string)) { s.onProgress = f }

// NewCenter 构造中心端服务(不启动监听, 由 Start 启动)。
func NewCenter(cfg ServerConfig) *Center {
	if cfg.Listen == "" {
		cfg.Listen = ":8600"
	}
	if cfg.HeartbeatSec <= 0 {
		cfg.HeartbeatSec = 15
	}
	if cfg.OfflineSec <= 0 {
		cfg.OfflineSec = cfg.HeartbeatSec * 3
	}
	if cfg.MaxProbes <= 0 {
		cfg.MaxProbes = 200
	}
	return &Center{
		cfg:       cfg,
		conns:     make(map[string]*conn),
		logf:      logGlobal, // 未注入全局日志时为静默, 注入后自动跟随
		startedAt: time.Now(),
		stopCh:    make(chan struct{}),
	}
}

// Config 返回生效配置(供 API 展示)。
func (s *Center) Config() ServerConfig { return s.cfg }

// Start 启动监听(阻塞前返回; 监听失败返回错误由上层降级)。
func (s *Center) Start() error {
	ln, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("probe: 探针服务监听 %s 失败: %w", s.cfg.Listen, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.closed = false
	s.mu.Unlock()
	s.logf(fmt.Sprintf("探针中心端已启动: 监听 %s (鉴权 %s, 心跳 %ds)", s.Addr(), tokenState(s.cfg.Token), s.cfg.HeartbeatSec))

	s.wg.Add(1)
	go s.acceptLoop(ln)
	s.wg.Add(1)
	go s.sweepLoop()
	return nil
}

// Addr 实际监听地址(端口可为 0 时由系统分配)。
func (s *Center) Addr() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ln == nil {
		return s.cfg.Listen
	}
	return s.ln.Addr().String()
}

// Stop 停止服务: 关闭监听 + 断开所有探针连接。
func (s *Center) Stop() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	ln := s.ln
	conns := make([]*conn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.conns = make(map[string]*conn)
	s.mu.Unlock()

	close(s.stopCh) // 立即唤醒 sweepLoop, 不让 wg.Wait 等下一个 ticker 周期
	if ln != nil {
		_ = ln.Close()
	}
	for _, c := range conns {
		_ = c.c.Close()
	}
	s.wg.Wait()
	s.logf("探针中心端已停止")
}

func (s *Center) acceptLoop(ln net.Listener) {
	defer s.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			s.mu.RLock()
			closed := s.closed
			s.mu.RUnlock()
			if closed {
				return
			}
			// 临时错误(连接被打断等)继续接受, 避免退出循环
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			time.Sleep(200 * time.Millisecond)
			continue
		}
		if tcp, ok := c.(*net.TCPConn); ok {
			_ = tcp.SetKeepAlive(true)
			_ = tcp.SetKeepAlivePeriod(30 * time.Second)
		}
		go s.serveConn(c)
	}
}

// serveConn 处理单条探针连接: 首包必须是 register, 之后循环处理心跳/确认/结果。
func (s *Center) serveConn(nc net.Conn) {
	s.wg.Add(1)
	defer s.wg.Done()
	s.serveConnInner(nc)
}

// ServeConn 处理一条已建立的探针连接(导出给装配层/集成测试用)。
//
// 正常路径由 Start() 内部 accept 循环调用; 沙箱或受限网络下可用内存管道
// 手工把连接喂进来做全链路验证(配合 Probe.SetDialer)。
func (s *Center) ServeConn(nc net.Conn) { s.serveConn(nc) }

// serveConnInner 连接处理主体(与 serveConn 分离, 便于测试直接喂入内存管道连接)。
func (s *Center) serveConnInner(nc net.Conn) {

	pc := &conn{
		c:        nc,
		sc:       NewScanner(nc),
		lastSeen: time.Now(),
		remote:   nc.RemoteAddr().String(),
		center:   s,
	}
	defer func() {
		if r := recover(); r != nil {
			s.logf(fmt.Sprintf("探针连接处理异常(已恢复): %v", r))
		}
		_ = nc.Close()
		s.dropConn(pc, "连接关闭")
	}()

	// 首包: 注册(15s 未注册则断开, 防呆连接占用)
	_ = nc.SetReadDeadline(time.Now().Add(15 * time.Second))
	first, err := ReadMessage(pc.sc)
	if err != nil {
		return
	}
	if first.Type != MsgRegister {
		_ = pc.send(&Envelope{Type: MsgRegisterOK, Code: 1, Error: "首包必须是 register"})
		return
	}
	if !TokenOK(s.cfg.Token, first.Token) {
		// 定长比较避免时序侧信道; 失败只记日志不回细节
		_ = subtle.ConstantTimeCompare([]byte(s.cfg.Token), []byte(first.Token))
		_ = pc.send(&Envelope{Type: MsgRegisterOK, Code: 1, Error: ErrBadToken.Error()})
		s.logf("探针注册被拒(密钥无效): " + pc.remote)
		return
	}
	if first.Protocol != 0 && first.Protocol != ProtocolVersion {
		_ = pc.send(&Envelope{Type: MsgRegisterOK, Code: 1, Error: ErrBadProtocol.Error()})
		s.logf(fmt.Sprintf("探针注册被拒(协议版本 %d != %d): %s", first.Protocol, ProtocolVersion, pc.remote))
		return
	}
	id := first.ID
	if id == "" {
		_ = pc.send(&Envelope{Type: MsgRegisterOK, Code: 1, Error: "缺少探针标识"})
		return
	}
	info := first.Info
	if info == nil {
		info = &NodeInfo{ProbeID: id}
	}
	info.ProbeID = id
	if info.Name == "" {
		info.Name = id
	}

	// 同 ID 重连: 踢掉旧连接(探针重启/网络切换后常见)
	pc.id = id
	pc.peerVersion = info.Version
	pc.registered = true
	pc.setInfo(info)
	pc.setLoad(first.Load)
	pc.touch()

	s.mu.Lock()
	if len(s.conns) >= s.cfg.MaxProbes {
		s.mu.Unlock()
		_ = pc.send(&Envelope{Type: MsgRegisterOK, Code: 1, Error: "中心端连接数已达上限"})
		return
	}
	old := s.conns[id]
	s.conns[id] = pc
	s.mu.Unlock()
	if old != nil {
		_ = old.send(&Envelope{Type: MsgRegisterOK, Code: 2, Message: "该探针已在别处重连, 本连接被替换"})
		_ = old.c.Close()
	}

	// 版本比对与自动更新指令(在应答里回带, 探针据此自行下载替换)。
	//
	// 【为什么这里是"注册即更新"而不是另开一条更新消息】注册是探针必然要做的事,
	// 把版本判断挂在注册应答上, 意味着"探针一上线且版本不对就会自动修好", 不需要
	// 用户去页面上点。老探针(不认识 Update 字段)会忽略它, 保持向前兼容。
	upd := s.SuggestedUpdate(info.Version, info.OS, info.Arch)
	if upd != nil {
		s.logf(fmt.Sprintf("探针 %s(%s/%s) 版本 %s 与中心端 %s 不一致, 已下发自动更新",
			id, info.OS, info.Arch, verOrUnknown(info.Version), upd.Version))
	}

	_ = nc.SetReadDeadline(time.Time{})
	if err := pc.send(&Envelope{
		Type:         MsgRegisterOK,
		ID:           id,
		HeartbeatSec: s.cfg.HeartbeatSec,
		Message:      "注册成功",
		AgentVersion: agentVersionOf(upd),
		Update:       upd,
		TS:           time.Now().Unix(),
	}); err != nil {
		return
	}
	s.logf(fmt.Sprintf("探针上线: %s (%s, %s/%s, %d 核, %s) 来自 %s",
		info.Name, id, info.OS, info.Arch, info.CPUCores, humanBytes(info.MemTotal), pc.remote))
	if s.onOnline != nil {
		s.onOnline(info)
	}

	// socket 读超时独立于 OfflineSec(业务语义: 多久无心跳判离线)。
	//
	// 早期实现直接拿 OfflineSec 当读超时, 真机联调暴露问题: 默认 OfflineSec=3*心跳,
	// 心跳 3s 时只有 10s —— 网络抖动/GC 停顿一旦让某次心跳迟到 10s, 中心端就
	// ReadMessage 报 i/o timeout 并直接断开连接, 探针随即重连又重注册, 表现为
	// "连接反复抖动"。这里改为在心跳周期上留足冗余(至少 3 个周期且不低于 60s),
	// 让读超时只承担"连接确实已死"的兜底职责, 离线判定仍由业务层的 OfflineSec 负责。
	readTimeout := time.Duration(s.cfg.HeartbeatSec) * time.Second * 3
	if readTimeout < 60*time.Second {
		readTimeout = 60 * time.Second
	}
	for {
		_ = nc.SetReadDeadline(time.Now().Add(readTimeout))
		msg, err := ReadMessage(pc.sc)
		if err != nil {
			if err == io.EOF {
				return
			}
			return
		}
		pc.touch()
		switch msg.Type {
		case MsgHeartbeat:
			if msg.Load != nil {
				pc.setLoad(msg.Load)
			}
			if msg.Info != nil { // 探针信息变化(装了 Npcap / 加了引擎)时增量刷新
				msg.Info.ProbeID = id
				pc.setInfo(msg.Info)
			}
			// 心跳回执(必须): 探针端的读循环有独立读超时, 收不到任何下行消息
			// 即判定链路已死并重连。早期实现中心端对心跳完全静默, 真机联调中
			// 探针每 45s 就"读超时"抖一次(心跳上行是通的, 但下行从无流量)。
			// 这里回一个 pong, 使每个心跳周期都有一次双向确认。
			// 回执失败不中断循环: 由读超时/写错误在下一轮自然收敛。
			// 用 MsgPong 而非 MsgPing 应答: 见 MsgPong 定义处对 ping-pong 死循环的说明。
			_ = pc.send(&Envelope{Type: MsgPong, ID: id, TS: time.Now().Unix()})
			if s.onHeartbeat != nil {
				s.onHeartbeat(id, pc.loadOf())
			}
		case MsgTaskAck:
			state := "已接收"
			if msg.Code != 0 {
				state = "已拒绝: " + msg.Error
			}
			tid := ""
			if msg.Task != nil {
				tid = msg.Task.TaskID
			}
			s.logf(fmt.Sprintf("探针 %s 任务 %s %s", id, tid, state))
		case MsgTaskProgress:
			if s.onProgress != nil && msg.Task != nil {
				s.onProgress(id, msg.Task.TaskID, msg.Message)
			}
		case MsgTaskResult:
			// 结果回调内部自行 recover: 一个任务的落库失败不能拖垮整条连接
			if s.onResult != nil && msg.Result != nil {
				func(r *TaskResult) {
					defer func() {
						if p := recover(); p != nil {
							s.logf(fmt.Sprintf("探针 %s 任务结果处理异常(已恢复): %v", id, p))
						}
					}()
					s.onResult(id, r)
				}(msg.Result)
			}
			s.logf(fmt.Sprintf("探针 %s 任务 %s 执行%s", id, resultTaskID(msg.Result), resultState(msg.Result)))
		case MsgPing:
			// 探针主动探活: 回 pong 应答(绝不可回 ping, 否则两端互回形成死循环)
			_ = pc.send(&Envelope{Type: MsgPong, ID: id, TS: time.Now().Unix()})
		case MsgPong:
			// 对端对保活 ping 的应答: 无需处理, touch() 已在上方刷新活跃时间
		default:
			// 未知类型忽略(向前兼容: 新版本探针发新消息, 老中心端不崩)
		}
	}
}

// dropConn 从在线表移除连接(仅当表中仍是该连接, 防重连后被误删)。
func (s *Center) dropConn(pc *conn, reason string) {
	if pc.id == "" {
		return
	}
	s.mu.Lock()
	cur := s.conns[pc.id]
	if cur == pc {
		delete(s.conns, pc.id)
	}
	s.mu.Unlock()
	if cur != pc {
		return // 已被新连接替换, 不通知离线
	}
	s.logf(fmt.Sprintf("探针离线: %s (%s)", pc.id, reason))
	if s.onOffline != nil {
		s.onOffline(pc.id, reason)
	}
}

// sweepLoop 定期清理超时未心跳的连接, 并对空闲连接主动发保活 ping。
//
// 两个职责:
//  1. 保活(主动 ping): 协议里心跳是"探针端单向上报", 中心端平时不下发任何消息。
//     探针端的读循环有独立读超时(收不到消息即认为链路已死), 若中心端长时间静默,
//     探针会自己断开重连 —— 真机联调中表现为约 45s 一次的周期性抖动。
//     这里在连接空闲超过半个心跳周期时主动发 ping, 保证下行始终有流量;
//     探针端读循环收到 MsgPing 会自动回 pong(见 client.go), 双向都有活跃证据。
//  2. 清理(离线判定): 超过 OfflineSec 无心跳视为探针已死, 关闭连接并通知上线层。
//     注意这里用的是业务层的 OfflineSec, 与 socket 读超时(独立、更宽松)是两回事。
func (s *Center) sweepLoop() {
	defer s.wg.Done()
	iv := time.Duration(s.cfg.OfflineSec) * time.Second
	if iv < 10*time.Second {
		iv = 10 * time.Second
	}
	tk := time.NewTicker(iv)
	defer tk.Stop()
	for {
		select {
		case <-s.stopCh:
			return // Stop 已触发, 立即退出(不等本周期剩余清理, 连接已在 Stop 里关闭)
		case <-tk.C:
		}
		s.mu.RLock()
		if s.closed {
			s.mu.RUnlock()
			return
		}
		var dead []*conn
		var idle []*conn
		limit := time.Duration(s.cfg.OfflineSec) * time.Second
		// 空闲阈值取半个心跳周期(下限 5s): 保证任意两个保活间隔内至少有一次下行,
		// 探针端的读超时(至少 45s)不可能被触发。
		pingAfter := time.Duration(s.cfg.HeartbeatSec) * time.Second / 2
		if pingAfter < 5*time.Second {
			pingAfter = 5 * time.Second
		}
		for _, c := range s.conns {
			if c.idleFor() > limit {
				dead = append(dead, c)
				continue
			}
			if c.idleFor() > pingAfter {
				idle = append(idle, c)
			}
		}
		s.mu.RUnlock()
		for _, c := range dead {
			s.logf(fmt.Sprintf("探针 %s 心跳超时(%ds 无心跳), 断开连接", c.id, s.cfg.OfflineSec))
			_ = c.c.Close()
		}
		// 主动保活: 失败只记日志, 真正的离线判定交由下一轮 idleFor 处理
		for _, c := range idle {
			if err := c.send(&Envelope{Type: MsgPing, ID: c.id, TS: time.Now().Unix()}); err != nil {
				s.logf(fmt.Sprintf("探针 %s 保活 ping 发送失败: %v", c.id, err))
			}
		}
	}
}

// ===== 任务下发 =====

// AssignTask 向指定探针下发任务。
// 探针不在线时返回 ErrProbeOffline(上层据此提示用户或改本地执行)。
func (s *Center) AssignTask(id string, t *TaskAssign) error {
	s.mu.RLock()
	c := s.conns[id]
	s.mu.RUnlock()
	if c == nil {
		return fmt.Errorf("%w: %s", ErrProbeOffline, id)
	}
	if t.CreatedAt == 0 {
		t.CreatedAt = time.Now().Unix()
	}
	return c.send(&Envelope{Type: MsgTaskAssign, ID: id, Task: t, TS: time.Now().Unix()})
}

// CancelTask 通知探针取消任务(探针端按 taskId 中断执行)。
func (s *Center) CancelTask(id, taskID string) error {
	s.mu.RLock()
	c := s.conns[id]
	s.mu.RUnlock()
	if c == nil {
		return fmt.Errorf("%w: %s", ErrProbeOffline, id)
	}
	return c.send(&Envelope{Type: MsgTaskCancel, ID: id, Task: &TaskAssign{TaskID: taskID}, TS: time.Now().Unix()})
}

// Online 判断探针是否在线。
func (s *Center) Online(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.conns[id]
	return ok
}

// OnlineIDs 返回当前在线探针 ID 列表。
func (s *Center) OnlineIDs() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.conns))
	for id := range s.conns {
		out = append(out, id)
	}
	return out
}

// Snapshot 在线探针运行时快照(负载/连接信息, 与 db 持久化的静态信息互补)。
type Snapshot struct {
	ProbeID  string    `json:"probeId"`
	Name     string    `json:"name"`
	Remote   string    `json:"remote"`
	Load     *Load     `json:"load,omitempty"`
	LastSeen string    `json:"lastSeen"`
	Info     *NodeInfo `json:"info,omitempty"`
}

// Snapshots 返回所有在线探针快照(探针状态面板数据来源)。
//
// 只持有在线表读锁收集连接指针, 逐个取快照时用各自的状态锁:
// 避免连接读循环持锁期间(如写 socket)阻塞整个在线表查询。
func (s *Center) Snapshots() []Snapshot {
	s.mu.RLock()
	conns := make([]*conn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.RUnlock()
	out := make([]Snapshot, 0, len(conns))
	for _, c := range conns {
		out = append(out, c.snapshot())
	}
	return out
}

// Stat 中心端服务运行统计。
type Stat struct {
	Running       bool   `json:"running"`
	Addr          string `json:"addr"`
	StartedAt     string `json:"startedAt"`
	OnlineCount   int    `json:"onlineCount"`
	TokenRequired bool   `json:"tokenRequired"`
	HeartbeatSec  int    `json:"heartbeatSec"`
	OfflineSec    int    `json:"offlineSec"`
	MaxProbes     int    `json:"maxProbes"`
}

// Stats 服务统计(前端状态卡片)。
func (s *Center) Stats() Stat {
	s.mu.RLock()
	running := s.ln != nil && !s.closed
	n := len(s.conns)
	s.mu.RUnlock()
	return Stat{
		Running:       running,
		Addr:          s.Addr(),
		StartedAt:     s.startedAt.Format("2006-01-02 15:04:05"),
		OnlineCount:   n,
		TokenRequired: s.cfg.Token != "",
		HeartbeatSec:  s.cfg.HeartbeatSec,
		OfflineSec:    s.cfg.OfflineSec,
		MaxProbes:     s.cfg.MaxProbes,
	}
}

// send 并发安全地给探针写消息。
func (c *conn) send(msg *Envelope) error {
	if msg.TS == 0 {
		msg.TS = time.Now().Unix()
	}
	_ = c.c.SetWriteDeadline(time.Now().Add(10 * time.Second))
	return WriteMessage(c.c, &c.wmu, msg)
}

// ===== 小工具 =====

// humanBytes 人类可读容量(日志展示)。
func humanBytes(n uint64) string {
	if n == 0 {
		return "-"
	}
	const unit = 1024
	units := []string{"B", "KB", "MB", "GB", "TB", "PB"}
	f := float64(n)
	i := 0
	for f >= unit && i < len(units)-1 {
		f /= unit
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%d%s", n, units[i])
	}
	return fmt.Sprintf("%.1f%s", f, units[i])
}

func tokenState(tok string) string {
	if tok == "" {
		return "关闭(不需密钥)"
	}
	return "开启"
}

func resultTaskID(r *TaskResult) string {
	if r == nil {
		return ""
	}
	return r.TaskID
}

func resultState(r *TaskResult) string {
	if r == nil {
		return "结果为空"
	}
	if r.Status == TaskDone || r.Status == "success" {
		return "成功" + durationSuffix(r)
	}
	return "失败: " + r.Error
}

func durationSuffix(r *TaskResult) string {
	if r.DurationMs <= 0 {
		return ""
	}
	return fmt.Sprintf(" (耗时 %dms)", r.DurationMs)
}

// MarshalJSON 便于 API 层直接复用(Center 不直接暴露连接细节)。
func (s Snapshot) MarshalJSON() ([]byte, error) {
	type alias Snapshot
	return json.Marshal(alias(s))
}

// ErrProbeOffline 目标探针不在线。
var ErrProbeOffline = errors.New("probe: 探针不在线")

// 上下文占位: 供后续按 ctx 取消任务使用(当前留空实现保持接口稳定)。
var _ = context.Background
