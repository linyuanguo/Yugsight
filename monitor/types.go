// types.go SNMP 网络监控的类型定义(纯标准库, 不依赖 db —— 落库经装配层注入)。
//
// 定位: 对一组 SNMPv2c 目标(交换机/路由器/服务器)做周期采集, 数据供:
//   1. 监控管理页(Monitor.vue): 目标增删 + 最新指标/接口表;
//   2. 安全大屏(bigscreen 的 monitors 段): 在线状态 + 流量速率 + TOP 接口。
//
// 只读 GET/GETBULK, 不写任何 MIB, 对目标设备零影响。
package monitor

import (
	"strings"
	"time"
)

// Target 一个 SNMP 监控目标。
//
// 鉴权二选一(以 V3.User 是否非空为准):
//   - v2c: Community 社区串(明文在网络上传输, 无加密)
//   - v3 : User + Auth*/Priv*(USM, 见 snmp/v3.go)
//
// 口令字段(Community / AuthPass / PrivPass)在配置里**以密文存储**(见 secrets.go);
// 通过 API 读取时一律不回传(只回 has* 布尔), 编辑时留空表示"不修改"。
type Target struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Addr      string `json:"addr"`      // host:port(无端口默认 161)
	Community string `json:"community"` // v2c 社区串(只读)
	TimeoutMs int    `json:"timeoutMs"` // 单次查询超时, 0 = 默认 3000ms

	// ----- SNMPv3(USM); User 非空即 v3 模式 -----
	User      string `json:"user,omitempty"`
	AuthProto string `json:"authProto,omitempty"` // md5 / sha
	AuthPass  string `json:"authPass,omitempty"`
	PrivProto string `json:"privProto,omitempty"` // des / aes
	PrivPass  string `json:"privPass,omitempty"`
	Context   string `json:"context,omitempty"`
}

// Version 目标使用的 SNMP 版本文案(展示用)。
func (t Target) Version() string {
	if strings.TrimSpace(t.User) != "" {
		if strings.TrimSpace(t.PrivProto) != "" {
			return "v3 authPriv"
		}
		if strings.TrimSpace(t.AuthProto) != "" {
			return "v3 authNoPriv"
		}
		return "v3 noAuthNoPriv"
	}
	return "v2c"
}

// Config settings.json 的 monitor 节。
//
// 默认启用(2026-09-21, 对齐"开箱即用"口径): 空 targets = 零网络活动、
// 零行为变化, 用户从页面加目标后才开始发 UDP 包。这与 scheduler 2026-09-20
// 默认启用的同一判断 —— "不改变既有默认行为的能力默认开"。
type Config struct {
	Enabled     bool     `json:"enabled"`
	IntervalSec int      `json:"intervalSec"` // 轮询间隔, 0 = 默认 60
	Targets     []Target `json:"targets"`
	// RetentionHours 采样保留时长(小时, 0 = 默认 24)。与条数上限 keepSamples
	// 双限裁剪: 冷目标靠时长淘汰陈数据, 热目标靠条数封顶(见 monitor_timeseries.go)。
	RetentionHours int `json:"retentionHours,omitempty"`
}

// IfaceSample 一条接口样本(ifTable walk 结果的一行)。
type IfaceSample struct {
	Index string `json:"index"` // 行索引(ifIndex)
	Name  string `json:"name"`  // ifDescr
	Speed int64  `json:"speed"` // bps
	Oper  int    `json:"oper"`  // ifOperStatus: 1=up 2=down 3=testing
	In    int64  `json:"in"`    // ifInOctets 累计字节
	Out   int64  `json:"out"`   // ifOutOctets 累计字节
}

// Sample 一轮中一个目标的采集结果。
//
// 同时是 db/monitor.go 的表实体(直接嵌入, 单一事实来源, 避免两份结构漂移)。
type Sample struct {
	ID        string        `json:"id"` // targetID@unixmilli, 每轮唯一 → Upsert 恒新建
	TargetID  string        `json:"targetId"`
	Target    string        `json:"target"` // 目标名(展示用)
	At        time.Time     `json:"at"`
	OK        bool          `json:"ok"`      // 采集成功(设备可达且至少回一个标量)
	Err       string        `json:"err,omitempty"`
	SysDescr  string        `json:"sysDescr,omitempty"`
	SysName   string        `json:"sysName,omitempty"`
	UptimeSec int64         `json:"uptimeSec"` // sysUpTime 百分秒 → 秒
	IfNumber  int64         `json:"ifNumber"`
	Ifaces    []IfaceSample `json:"ifaces,omitempty"`
	CpuLoad   int64         `json:"cpuLoad"`  // 首条 hrProcessorLoad(%), 0 = 设备不支持
	MemTotal  int64         `json:"memTotal"` // 首条 RAM 的 hrStorageSize*units(字节), 0 = 不支持
	MemUsed   int64         `json:"memUsed"`
	ElapsedMs int64         `json:"elapsedMs"`
}

// RoundResult 一轮采集的汇总。
type RoundResult struct {
	At         time.Time       `json:"at"`
	DurationMs int64           `json:"durationMs"`
	OKCount    int             `json:"ok"`
	Total      int             `json:"total"`
	Errors     map[string]any  `json:"errors,omitempty"` // targetID -> 错误文本
}
