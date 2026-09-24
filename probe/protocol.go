// Package probe 分布式扫描探针框架: 中心端管理服务 + 探针端 SDK。
//
// 设计要点(项目约束):
//   - 仅使用 Go 标准库, 零第三方依赖;
//   - 新增功能默认关闭: 中心端需 probe.json 中 enabled=true 或 -probe 标志才启动监听;
//   - 外部资源/配置缺失时静默降级, 不影响原有单机扫描流程;
//   - 所有错误用 slog 记录, 不 panic, 失败降级不崩溃;
//   - 探针在线状态/节点信息通过 db 包 DAO 持久化(FileStore JSONL, 与原项目口径一致)。
package probe

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
)

// 协议版本: 中心端与探针端必须一致, 不一致时中心端拒绝注册并提示升级。
const ProtocolVersion = 1

// 消息类型: 中心端与探针端通过 Type 区分消息语义。
const (
	// ---- 探针端 -> 中心端 ----
	MsgRegister     = "register"      // 探针主动注册(携带 Token + 节点信息)
	MsgHeartbeat    = "heartbeat"     // 心跳保活(携带负载: CPU/内存/当前任务)
	MsgTaskAck      = "task_ack"      // 任务接收确认(accepted / rejected)
	MsgTaskResult   = "task_result"   // 任务执行结果回传
	MsgTaskProgress = "task_progress" // 任务执行进度(可选, 长任务用)

	// ---- 中心端 -> 探针端 ----
	MsgRegisterOK = "register_ok" // 注册成功(回带心跳间隔等参数)
	MsgTaskAssign = "task_assign" // 任务下发
	MsgTaskCancel = "task_cancel" // 任务取消
	MsgPing       = "ping"        // 保活探测(任一端可发, 对端须回 MsgPong)
	// MsgPong 保活回执: 收到 ping 时回复, 语义为"我只应答不再发起"。
	//
	// 为什么必须与 ping 区分: 若两端都用 MsgPing 应答, A 收 ping 回 ping ->
	// B 收 ping 又回 ping -> 无限 ping-pong 死循环打满链路。区分后形成
	// "发起 -> 应答"的单向语义, 不会互相触发。
	MsgPong = "pong"
)

// 任务执行位置: 中心创建扫描任务时选择执行位置。
const (
	ExecLocal = "local" // 本地中心端执行(默认, 与原有单机扫描一致)
	ExecProbe = "probe" // 下发到指定探针节点执行
)

// 任务状态机(中心端侧): 与 db.ProbeTask.Status 同口径。
const (
	TaskPending = "pending" // 已创建待下发
	TaskSent    = "sent"    // 已下发待确认
	TaskRunning = "running" // 探针执行中
	TaskDone    = "success" // 执行完成
	TaskFailed  = "failed"  // 执行失败
)

// NodeInfo 探针节点主机信息: 注册与心跳时上报, 中心端持久化。
// 字段与 db.ProbeNode 的 Info 段一一对应。
type NodeInfo struct {
	ProbeID        string      `json:"probeId"`   // 探针唯一标识(自生成, 落盘保持稳定)
	Name           string      `json:"name"`      // 节点别名(默认 hostname)
	OS             string      `json:"os"`        // 操作系统(运行时 GOOS)
	OSVersion      string      `json:"osVersion"` // 内核/系统版本
	Arch           string      `json:"arch"`      // 架构(amd64/arm64)
	Hostname       string      `json:"hostname"`
	CPUModel       string      `json:"cpuModel,omitempty"`  // CPU 型号
	CPUCores       int         `json:"cpuCores"`            // 逻辑核心数
	MemTotal       uint64      `json:"memTotal"`            // 内存总量(字节)
	MemUsed        uint64      `json:"memUsed,omitempty"`   // 已用内存(字节)
	DiskTotal      uint64      `json:"diskTotal,omitempty"` // 磁盘总量(字节)
	DiskUsed       uint64      `json:"diskUsed,omitempty"`  // 已用磁盘(字节)
	LocalIPs       []string    `json:"localIps,omitempty"`  // 本机 IP 列表
	NetIfaces      []NetIface  `json:"netIfaces,omitempty"` // 网卡信息(IP/MAC)
	Gateway        string      `json:"gateway,omitempty"`   // 默认网关
	DNS            []string    `json:"dns,omitempty"`       // DNS 服务器
	NpcapInstalled bool        `json:"npcapInstalled"`      // 是否安装 Npcap(抓包能力)
	Engines        []EngineVer `json:"engines,omitempty"`   // 本地 bin 引擎版本列表
	Version        string      `json:"version"`             // 探针程序版本
	StartedAt      string      `json:"startedAt,omitempty"` // 探针启动时间
}

// NetIface 网卡信息(IP + MAC)。
type NetIface struct {
	Name string `json:"name"`
	IP   string `json:"ip,omitempty"`
	MAC  string `json:"mac,omitempty"`
}

// EngineVer 本地引擎版本(nmap/trivy/zap)。
type EngineVer struct {
	Name    string `json:"name"`
	Found   bool   `json:"found"`
	Version string `json:"version,omitempty"`
}

// Load stat: 心跳时上报的负载指标。
type Load struct {
	CPUPercent   float64 `json:"cpuPercent,omitempty"`  // CPU 占用百分比(粗算)
	MemPercent   float64 `json:"memPercent,omitempty"`  // 内存占用百分比
	TasksRunning int     `json:"tasksRunning"`          // 正在执行的任务数
	CurrentTask  string  `json:"currentTask,omitempty"` // 当前任务描述
	UptimeSec    int64   `json:"uptimeSec,omitempty"`   // 探针运行时长
}

// Envelope 统一消息信封: 所有通信消息都是单行 JSON。
// 使用 bufio.Scanner 按行读取, 避免 JSON 流式解码的粘包问题。
type Envelope struct {
	Type         string      `json:"type"`
	ID           string      `json:"id,omitempty"`       // 探针标识
	Token        string      `json:"token,omitempty"`    // 注册时携带的节点密钥
	Protocol     int         `json:"protocol,omitempty"` // 协议版本
	Info         *NodeInfo   `json:"info,omitempty"`
	Load         *Load       `json:"load,omitempty"`
	Task         *TaskAssign `json:"task,omitempty"`
	Result       *TaskResult `json:"result,omitempty"`
	Code         int         `json:"code,omitempty"` // 0 成功, 非 0 失败
	Error        string      `json:"error,omitempty"`
	Message      string      `json:"message,omitempty"`
	HeartbeatSec int         `json:"heartbeatSec,omitempty"` // 中心端下发的推荐心跳间隔(秒)
	TS           int64       `json:"ts,omitempty"`           // Unix 时间戳(秒)
	// AgentVersion 中心端当前提供的 agent 版本(注册应答回带)。
	//
	// 【为什么放在协议里而不是让 agent 走 HTTP 查】探针只对中心端发起一条出站 TCP,
	// 没有 HTTP 客户端能力(也不该为了查版本再实现一套 HTTP+鉴权)。注册应答是探针
	// 必然收到的一条消息, 顺带回带版本号即可完成比对, 零额外交互。
	AgentVersion string `json:"agentVersion,omitempty"`
	// Update 版本不一致时中心端下发的自动更新指令, 一致时为 nil。
	//
	// 中心端判断依据是 agent 注册时上报的 NodeInfo.Version(即它自己的程序版本),
	// 与中心端手上 agents/ 目录里新包的版本比对。探针端**不自行判断**版本新旧 ——
	// "谁是最新版"是中心端的知识, 探针只负责执行下发结果。
	Update *UpdateDirective `json:"update,omitempty"`
}

// UpdateDirective 自动更新指令: 中心端 -> 探针端。
//
// 【为什么不传绝对路径】探针拿到的是 URL, 实际文件由中心端已有的
// /api/v2/probe/agent/download 路由提供(带 Range 断点续传)。这样探针端不需要
// 了解中心端的目录结构, 也不必为更新单开一个文件传输通道。
type UpdateDirective struct {
	Version string `json:"version"`           // 目标版本号
	URL     string `json:"url"`               // 下载地址(中心端 agent 下载接口)
	SHA256  string `json:"sha256,omitempty"`  // 校验和(缺省则不校验, 仅做长度校验)
	Size    int64  `json:"size,omitempty"`    // 文件大小(校验下载完整性)
	Force   bool   `json:"force,omitempty"`   // 强制更新(版本不同即 true)
	Note    string `json:"note,omitempty"`    // 更新说明(展示给用户)
}

// TaskAssign 任务下发载荷: 中心端 -> 探针端。
// Args 承载扫描参数(与 /api/scan 的 payload 同构), 探针端按 Kind 分派执行。
type TaskAssign struct {
	TaskID     string         `json:"taskId"`
	Kind       string         `json:"kind"`   // ip / port / web / host
	Target     string         `json:"target"` // 目标网段 / IP / URL
	Ports      string         `json:"ports,omitempty"`
	Args       map[string]any `json:"args,omitempty"` // 其余扫描参数(并发/超时/nuclei 开关等)
	CreatedAt  int64          `json:"createdAt,omitempty"`
	TimeoutSec int            `json:"timeoutSec,omitempty"`
}

// TaskResult 任务执行结果: 探针端 -> 中心端。
// Findings 为归一化后的漏洞/风险条目, Raw 为原始文本输出(截断后)。
type TaskResult struct {
	TaskID     string    `json:"taskId"`
	Status     string    `json:"status"` // success / failed
	Error      string    `json:"error,omitempty"`
	StartedAt  int64     `json:"startedAt,omitempty"`
	FinishedAt int64     `json:"finishedAt,omitempty"`
	DurationMs int64     `json:"durationMs,omitempty"`
	Summary    string    `json:"summary,omitempty"` // 一句话摘要(如 "存活 12 / 开放端口 34")
	Findings   []Finding `json:"findings,omitempty"`
	Raw        string    `json:"raw,omitempty"`

	// Report 结构化探针报告(任务 6.4): 资产 + 漏洞(含证据/请求响应/PCAP 路径)。
	//
	// 与 Findings 的关系: Findings 是"扁平发现列表"(旧版中心端展示用),
	// Report 是"归一化输入"(中心端送入 normalizer 统一处理, 产出 models.Asset/Vuln)。
	// 中心端应优先读 Report, 缺失时回落到 Findings(向前兼容旧探针)。
	//
	// 用 any 而非 concrete 类型: probe 包是协议层, 不应反向依赖 normalizer
	// (否则 agent 二进制会因协议层依赖而被迫链入归一化模块)。
	Report any `json:"report,omitempty"`
}

// Finding 探针回传的单条发现(与中心端漏洞库/报表口径对齐)。
type Finding struct {
	Severity string `json:"severity"`
	Title    string `json:"title"`
	Detail   string `json:"detail,omitempty"`
	Fix      string `json:"fix,omitempty"`
	CVE      string `json:"cve,omitempty"`
	Asset    string `json:"asset,omitempty"`
}

// 协议错误。
var (
	ErrBadToken      = errors.New("probe: 节点密钥无效")
	ErrBadProtocol   = errors.New("probe: 协议版本不匹配")
	ErrUnknownType   = errors.New("probe: 未知消息类型")
	ErrNotRegistered = errors.New("probe: 探针未注册")
)

// ===== 日志注入 =====
//
// probe 包不直接依赖 slog/main 包: 由装配层调用 SetGlobalLogger 注入日志函数,
// 未注入时静默丢弃(库包默认无副作用), 避免"未配置即报错"。

var (
	globalLogMu sync.Mutex
	globalLog   func(string)
)

// SetGlobalLogger 注入全局日志函数(并入程序主日志)。f 为 nil 时重置为静默。
func SetGlobalLogger(f func(string)) {
	globalLogMu.Lock()
	globalLog = f
	globalLogMu.Unlock()
}

// logGlobal 输出一条日志(未注入时丢弃)。
func logGlobal(msg string) {
	globalLogMu.Lock()
	f := globalLog
	globalLogMu.Unlock()
	if f != nil {
		f(msg)
	}
}

// WriteMessage 编码并写出单行 JSON 消息(并发安全由调用方保证)。
func WriteMessage(w io.Writer, mu *sync.Mutex, msg *Envelope) error {
	b, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("probe: 消息编码失败: %w", err)
	}
	b = append(b, '\n')
	if mu != nil {
		mu.Lock()
		defer mu.Unlock()
	}
	_, err = w.Write(b)
	return err
}

// ReadMessage 读取单行 JSON 消息。
func ReadMessage(r *bufio.Scanner) (*Envelope, error) {
	if !r.Scan() {
		if err := r.Err(); err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	var msg Envelope
	if err := json.Unmarshal(r.Bytes(), &msg); err != nil {
		return nil, fmt.Errorf("probe: 消息解码失败: %w", err)
	}
	return &msg, nil
}

// maxMessageBytes 单条消息(一行 JSON)大小上限。
//
// 取 4MB: 任务结果的 finding 明细可能较多, 但也不能无上限(防内存放大攻击)。
// 注意 bufio.Scanner 的缓冲须在首次 Scan 前设定, 故此为硬上限;
// 超过后由 readMessageCompat 报错, 由上层决定是否重连/精简结果。
const maxMessageBytes = 4 * 1024 * 1024

// NewScanner 构造带更大缓冲的分析器(节点信息/任务结果可能较长)。
func NewScanner(r io.Reader) *bufio.Scanner {
	s := bufio.NewScanner(r)
	s.Buffer(make([]byte, 0, 64*1024), maxMessageBytes)
	return s
}

// TokenOK 校验节点密钥: 中心端配置的密钥为空时代表"不校验"(与项目 test_mode 口径一致)。
func TokenOK(want, got string) bool {
	if want == "" {
		return true
	}
	return want == got
}
