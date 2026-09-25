// Package collect 节点监控采集底座(阶段 1)。
//
// 定位: 统一的"周期采集引擎 + 协议适配器 + 指标时序 + 异常事件"底座, 服务
// 节点监控页的两个 Tab:
//   - 主机侧(side=host): WinRM / SSH 命令采集 / 主机 SNMP
//     (yugsight-agent 探针走独立的 probe 框架, 不在本调度器内, 页面同屏展示);
//   - 网络侧(side=net): ICMP 链路探测 / NetFlow v5+IPFIX 流量接收 /
//     RESTCONF / NETCONF(TLS)。
//
// 公共基础能力(用户口径):
//   - 采集任务调度: 每任务独立间隔, 秒级 tick 判定到期, 并发信号量限流;
//   - 采集限速: 全局令牌桶(每秒最多 N 个采集动作), 防止多任务打爆设备/链路;
//   - IP 白名单: 非空时只允许采集白名单内 IP/CIDR(防误配成对外网段发流量);
//   - 指标时序: 内存环形(最新/上一轮 + 每任务历史) + 注入式落库(装配层接 db);
//   - 异常事件: 连续失败→离线、恢复→上线、阈值越限(边缘触发) → Event 输出;
//   - 标准化输出: 全部产出统一为 Metric 数组(进程/事件/流统计也走 Metric +
//     Labels, 不再各协议一套结构), ReportSink 接口预留报告中心入口
//     (本阶段默认空实现, 不实现 AI)。
//
// 包边界: 不 import db/http —— 落库/广播/配置读取全部经注入函数(与 monitor 包
// 同一装配模式); 配置缺失默认全关(规则 5), 不监听端口、不发起外连。
package collect

import (
	"time"
)

// 采集协议(任务 Protocol 字段取值)。
const (
	ProtoSNMP     = "snmp"     // 主机 SNMP(HR-MIB: CPU/内存/磁盘)
	ProtoICMP     = "icmp"     // ICMP 链路探测(时延/抖动/丢包)
	ProtoWinRM    = "winrm"    // WinRM WS-Management(Windows, HTTP+XML)
	ProtoSSH      = "ssh"      // SSH 命令采集(Linux, 调用系统 ssh 客户端)
	ProtoNetFlow  = "netflow"  // NetFlow v5 / IPFIX 流量接收(UDP 监听)
	ProtoRESTCONF = "restconf" // RESTCONF(HTTPS + JSON/YANG)
	ProtoNETCONF  = "netconf"  // NETCONF over TLS(RFC 8012, 行分隔 XML RPC)
	// ProtoAgent 不属于本调度器: yugsight-agent 由独立的 probe 框架管理
	// (注册/心跳/任务下发/日志全在 /api/v2/probe/*), 这里只为协议清单占位,
	// 页面据此显示"由探针中心管理"而不是允许建一个会失败的采集任务。
	ProtoAgent = "agent"
)

// 任务归属侧(页面 Tab 维度)。
const (
	SideHost = "host" // 主机侧(Tab 1 探针节点管理)
	SideNet  = "net"  // 网络设备侧(Tab 2 网络设备监控)
)

// 事件级别(与漏洞等级无关, 是运维告警级别)。
const (
	EvtInfo     = "info"
	EvtWarn     = "warn"
	EvtCritical = "critical"
)

// 事件类型。
const (
	EvtOffline  = "offline"  // 连续失败达阈值
	EvtRecover  = "recover"  // 从离线恢复
	EvtHighCPU  = "high_cpu" // CPU 越限
	EvtHighMem  = "high_mem" // 内存越限
	EvtHighRTT  = "high_rtt" // 链路时延越限
	EvtHighLoss = "high_loss" // 链路丢包越限
)

// Task 一个采集任务(配置项)。
//
// 口令字段(Community / AuthPass / PrivPass)与 monitor.Target 同一口径:
// 配置里以密文存储(复用 monitor 包的加密, 密钥环境变量 YUGSIGHT_MONITOR_KEY),
// API 读取不回传(只回 has* 布尔), 编辑留空 = 不修改。
type Task struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Side     string `json:"side"`     // host / net
	Protocol string `json:"protocol"` // 见 Proto* 常量
	Target   string `json:"target"`   // host:port / URL / 监听地址(netflow)
	Enabled  bool   `json:"enabled"`
	// 0 = 用全局默认间隔; 钳制最小 5s(与 monitor 同口径, 防打爆设备)。
	IntervalSec int `json:"intervalSec,omitempty"`
	// 0 = 默认 10s(单任务采集时限, 防个别设备拖死整轮)。
	TimeoutMs int `json:"timeoutMs,omitempty"`

	// ---- 凭据(以是否为空区分协议用法) ----
	Community string `json:"community,omitempty"` // snmp v2c 社区串
	User      string `json:"user,omitempty"`      // ssh/winrm/netconf/restconf 用户名
	AuthProto string `json:"authProto,omitempty"` // snmp v3 认证协议(md5/sha), 其余协议忽略
	AuthPass  string `json:"authPass,omitempty"`  // 口令(密文)
	PrivProto string `json:"privProto,omitempty"` // snmp v3 加密协议(des/aes), 其余协议忽略
	PrivPass  string `json:"privPass,omitempty"`  // 加密口令(密文)

	// 协议参数(自由键值, 各协议自取所需):
	//   icmp:     count(探测次数, 默认 4)
	//   ssh:      port(默认 22), command(自定义远程命令, 默认内置 /proc 采集)
	//   winrm:    port(默认 5985), tls(true/false, 5986 时自动 https)
	//   netflow:  (监听地址在 Target, 无需额外参数)
	//   restconf: path(数据路径, 默认 if:interfaces), insecure
	//   netconf:  (无)
	Params map[string]string `json:"params,omitempty"`
}

// Param 读协议参数(不存在返回空串, 调用方无需判 nil)。
func (t Task) Param(key string) string {
	if t.Params == nil {
		return ""
	}
	v := t.Params[key]
	for len(v) > 0 && (v[0] == ' ' || v[0] == '\t') {
		v = v[1:]
	}
	for len(v) > 0 && (v[len(v)-1] == ' ' || v[len(v)-1] == '\t') {
		v = v[:len(v)-1]
	}
	return v
}

// IntParam 读整型协议参数(解析失败返回 def)。
func (t Task) IntParam(key string, def int) int {
	s := t.Param(key)
	if s == "" {
		return def
	}
	n := 0
	ok := false
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + int(c-'0')
		ok = true
	}
	if !ok {
		return def
	}
	return n
}

// Metric 标准化指标点 —— 全部采集产出统一走这个结构。
//
// 为什么进程/事件/流也走 Metric: 各协议各造一套结构会让时序存储/前端/
// 报告接入点都要分支处理; 统一成"名字+数值+单位+标签"后, 进程列表就是
// 一组 name=process 的 Metric(标签带 pid/name/mem), 流统计是 name=flow
// (标签带五元组), 存储与展示全走同一条路 —— 这就是"标准化输出接口"。
type Metric struct {
	Name   string            `json:"name"`
	Value  float64           `json:"value"`
	Unit   string            `json:"unit,omitempty"`
	Labels map[string]string `json:"labels,omitempty"`
}

// Round 一轮采集结果(一个任务一次)。
//
// 同时是 db 表实体(直接嵌入, 与 monitor.Sample 同一"单一事实来源"口径)。
type Round struct {
	ID        string    `json:"id"` // taskID@unixmilli, 每轮唯一
	TaskID    string    `json:"taskId"`
	Side      string    `json:"side"`
	Protocol  string    `json:"protocol"`
	Target    string    `json:"target"`
	At        time.Time `json:"at"`
	OK        bool      `json:"ok"`
	Err       string    `json:"err,omitempty"`
	ElapsedMs int64     `json:"elapsedMs"`
	Metrics   []Metric  `json:"metrics,omitempty"`
}

// Event 异常事件(异常事件输出能力)。
//
// 触发口径(全部边缘触发, 不每轮重复报):
//   - 连续失败达阈值 → offline(critical); 恢复成功 → recover(info);
//   - 指标从"低于阈值"跨到"达到/超过" → high_cpu / high_mem / high_rtt / high_loss。
type Event struct {
	ID     string    `json:"id"` // e + taskID@unixmilli + 随机后缀(同任务同毫秒多条不撞)
	TaskID string    `json:"taskId"`
	Side   string    `json:"side"`
	Target string    `json:"target"`
	At     time.Time `json:"at"`
	Level  string    `json:"level"` // info / warn / critical
	Type   string    `json:"type"`  // 见 Evt* 常量
	Msg    string    `json:"msg"`
}

// NetFlowConfig NetFlow/IPFIX 接收端配置。
type NetFlowConfig struct {
	Enabled bool   `json:"enabled"` // 默认关: 不开不监听 UDP 端口
	Listen  string `json:"listen"`  // 监听地址, 默认 0.0.0.0:2000
}

// Alerts 异常告警阈值(0 = 该项关闭)。
type Alerts struct {
	CPUPct     int `json:"cpuPct"`     // CPU 越限(%), 默认 90
	MemPct     int `json:"memPct"`     // 内存越限(%), 默认 90
	RTTMs      int `json:"rttMs"`      // 平均时延越限(ms), 0=关
	LossPct    int `json:"lossPct"`    // 丢包越限(%), 默认 30
	FailStreak int `json:"failStreak"` // 连续失败 N 轮判离线, 默认 3
}

// Config settings.json 的 collect 节。
//
// 默认全关(规则 5): enabled=false 时引擎不跑循环、不监听端口、不发起任何
// 外连 —— 与 probe 框架"配置缺失保持单机模式"同一口径。
type Config struct {
	Enabled        bool          `json:"enabled"`
	IntervalSec    int           `json:"intervalSec"`    // 全局默认间隔, 0=60
	Concurrent     int           `json:"concurrent"`     // 同时采集的任务数上限, 0=4
	GlobalRate     int           `json:"globalRate"`     // 全局限速: 每秒最多采集动作数, 0=10
	Whitelist      []string      `json:"whitelist"`      // IP/CIDR 白名单, 空=不限制
	RetentionHours int           `json:"retentionHours"` // 时序保留时长(小时), 0=24
	NetFlow        NetFlowConfig `json:"netflow"`
	Alerts         Alerts        `json:"alerts"`
	// Tasks 采集任务(页面增删; 落 settings.json 同节, 与 monitor.Targets 同模式)。
	Tasks []Task `json:"tasks"`
}
