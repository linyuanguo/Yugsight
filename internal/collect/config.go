// config.go 配置默认值与钳制。
package collect

import "time"

const (
	defaultIntervalSec  = 60
	defaultConcurrent   = 4
	defaultGlobalRate   = 10
	defaultRetentionHrs = 24
	defaultTaskTimeout  = 10 * time.Second
	minIntervalSec      = 5
	maxIntervalSec      = 3600 // 单任务间隔封顶 1 小时(再大没有运维意义)
	minTaskTimeoutMs    = 1000
	maxTaskTimeoutMs    = 120000
)

// WithDefaults 把零值字段填成默认值(不落盘, 供运行时使用)。
//
// 为什么返回副本而不是就地改: 调用方传的多是配置缓存里的值,
// 就地改会让"默认值回填"泄漏进下一次写盘(用户明明没写 intervalSec,
// 保存后 settings.json 里凭空多出一堆字段)。
func (c Config) WithDefaults() Config {
	if c.IntervalSec < minIntervalSec {
		c.IntervalSec = defaultIntervalSec
	}
	if c.Concurrent < 1 {
		c.Concurrent = defaultConcurrent
	}
	if c.GlobalRate < 1 {
		c.GlobalRate = defaultGlobalRate
	}
	if c.RetentionHours < 1 {
		c.RetentionHours = defaultRetentionHrs
	}
	if c.NetFlow.Listen == "" {
		c.NetFlow.Listen = "0.0.0.0:2000"
	}
	a := c.Alerts
	if a.CPUPct == 0 {
		a.CPUPct = 90
	}
	if a.MemPct == 0 {
		a.MemPct = 90
	}
	if a.LossPct == 0 {
		a.LossPct = 30
	}
	if a.FailStreak == 0 {
		a.FailStreak = 3
	}
	c.Alerts = a
	return c
}

// TaskInterval 任务实际间隔(任务值优先, 全局默认兜底, 两侧钳制)。
func (c Config) TaskInterval(t Task) time.Duration {
	sec := t.IntervalSec
	if sec <= 0 {
		sec = c.IntervalSec
	}
	if sec < minIntervalSec {
		sec = minIntervalSec
	}
	if sec > maxIntervalSec {
		sec = maxIntervalSec
	}
	return time.Duration(sec) * time.Second
}

// TaskTimeout 任务采集时限(任务值优先, 默认 10s)。
func (c Config) TaskTimeout(t Task) time.Duration {
	ms := t.TimeoutMs
	if ms <= 0 {
		ms = int(defaultTaskTimeout / time.Millisecond)
	}
	if ms < minTaskTimeoutMs {
		ms = minTaskTimeoutMs
	}
	if ms > maxTaskTimeoutMs {
		ms = maxTaskTimeoutMs
	}
	return time.Duration(ms) * time.Millisecond
}

// EnabledProtocols 协议可用性清单(页面展示 + 建任务时的合法性校验共用)。
//
// 注意: agent 协议在清单里但 NotInScheduler=true —— 它由 probe 框架管理,
// 本调度器不接受建 agent 任务(会永远失败, 不如直接拒绝并指路)。
type ProtocolInfo struct {
	Name          string `json:"name"`
	Label         string `json:"label"`
	Side          string `json:"side"`
	Desc          string `json:"desc"`
	NotInScheduler bool  `json:"notInScheduler"`
}

var protocolInfos = []ProtocolInfo{
	{ProtoAgent, "yugsight-agent 探针", SideHost, "自研分布式探针(注册/在线/版本/任务下发/日志), 由探针中心管理", true},
	{ProtoWinRM, "WinRM", SideHost, "Windows 远程管理(HTTP+XML, 5985/5986), 采集 CPU/内存/磁盘/进程", false},
	{ProtoSSH, "SSH 命令采集", SideHost, "Linux 主机, 调用本机 ssh 客户端执行 /proc 采集命令", false},
	{ProtoSNMP, "主机 SNMP", SideHost, "HR-MIB 只读采集(CPU/内存/磁盘/运行时长), 同网络设备 SNMP 协议", false},
	{ProtoICMP, "ICMP 链路探测", SideNet, "周期 ping, 输出平均/最大时延、抖动、丢包率", false},
	{ProtoNetFlow, "NetFlow/IPFIX", SideNet, "UDP 接收流量导出(v5 与 IPFIX), 聚合五元组流量统计", false},
	{ProtoRESTCONF, "RESTCONF", SideNet, "HTTPS + JSON(YANG), 采集设备接口状态与计数器", false},
	{ProtoNETCONF, "NETCONF", SideNet, "NETCONF over TLS(RFC 8012), XML RPC 采集接口状态与计数器", false},
}

// Protocols 协议清单(展示用副本)。
func Protocols() []ProtocolInfo {
	out := make([]ProtocolInfo, len(protocolInfos))
	copy(out, protocolInfos)
	return out
}

// ProtocolKnown 协议名是否受支持。
func ProtocolKnown(name string) bool {
	for _, p := range protocolInfos {
		if p.Name == name {
			return true
		}
	}
	return false
}

// InScheduler 协议是否可由本调度器建任务(agent 不行, 见 ProtocolInfo)。
func InScheduler(name string) bool {
	for _, p := range protocolInfos {
		if p.Name == name {
			return !p.NotInScheduler
		}
	}
	return false
}
