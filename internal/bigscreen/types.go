// Package bigscreen 安全运维大屏数据聚合(任务 7.3)。
//
// 定位: 把"大屏一屏所需的全部指标"聚合成**一次请求**返回, 而不是让前端拉
// 五六个 CRUD 列表自己在前端算。原因有三:
//  1. 前端算不准: 列表接口都带 size 上限(200), 前端只能看到"前 200 条",
//     漏洞总数超过 200 时各等级分布/Top 榜单会静默失真;
//  2. 轮询成本: 大屏是全屏常驻页面且 5~30 秒自动刷新, 每次拉几百 KB 明细
//     纯属浪费, 且明细里含证据/请求响应等大字段;
//  3. 口径统一: 统计口径一旦散落在前端 JS 里, 大屏与报告/API 迟早对不上。
//
// 数据来源: 全部经 db 包统一 DAO 接口查询(不直接读存储文件、不写 SQL),
// 因此换数据库驱动时本包零改动。
//
// 本包仅依赖 Go 标准库与 yugsight/db、yugsight/models。
package bigscreen

import "time"

// 风险等级(与 models.SeverityXxx 同口径, 此处复述常量避免本包被 models 的
// 归一化函数绑死 —— 大屏只做展示, 不做等级推断)。
const (
	SevCritical = "critical"
	SevHigh     = "high"
	SevMedium   = "medium"
	SevLow      = "low"
	SevInfo     = "info"
)

// SevOrder 等级展示顺序(严重 -> 信息), 前端按此顺序渲染卡片与图例。
var SevOrder = []string{SevCritical, SevHigh, SevMedium, SevLow, SevInfo}

// SevTotal 风险等级的"问题级"集合: 不含 info 加固建议。
//
// 为什么单独定义: 大屏"漏洞总数""高危 TOP""风险占比饼图"若把 info 混进去,
// 数字会虚高十几倍(安全头缺失之类的加固建议动辄上百条), 让运维对风险规模
// 产生错误判断。info 单独计数展示, 不参与风险类指标。
var SevRisk = []string{SevCritical, SevHigh, SevMedium, SevLow}

// TrendDays 趋势图默认天数(任务书要求近 7 天)。
const TrendDays = 7

// MaxTopList Top 榜单默认条数。
const MaxTopList = 10

// SevCount 各等级漏洞数量(未修复口径)。
type SevCount struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`
	// Risk 四类风险等级之和(不含 info), 供前端直接取用。
	Risk int `json:"risk"`
	// Total 五类之和(含 info)。
	Total int `json:"total"`
}

// add 累加一个等级的计数。
func (s *SevCount) add(sev string, n int) {
	switch sev {
	case SevCritical:
		s.Critical += n
	case SevHigh:
		s.High += n
	case SevMedium:
		s.Medium += n
	case SevLow:
		s.Low += n
	case SevInfo:
		s.Info += n
	}
	s.Total += n
	if sev != SevInfo {
		s.Risk += n
	}
}

// Overview 数字卡片区指标。
type Overview struct {
	Assets      int `json:"assets"`      // 资产总量
	AssetsAlive int `json:"assetsAlive"` // 存活资产
	AssetsDown  int `json:"assetsDown"`  // 未响应/未探测资产(Assets - AssetsAlive)

	Vulns     SevCount `json:"vulns"`     // 未修复漏洞分级统计
	VulnTotal int      `json:"vulnTotal"` // 漏洞库总记录数(含已修复, 供趋势对照)
	VulnFixed int      `json:"vulnFixed"` // 已修复数量

	Probes         int `json:"probes"`         // 已登记探针总数
	ProbesOnline   int `json:"probesOnline"`   // 在线探针
	ProbesOffline  int `json:"probesOffline"`  // 离线/停用探针
	TasksRunning   int `json:"tasksRunning"`   // 当前运行中任务(pending + running)
	TasksToday     int `json:"tasksToday"`     // 今日新建任务
	TasksSuccess   int `json:"tasksSuccess"`   // 累计成功
	TasksFailed    int `json:"tasksFailed"`    // 累计失败
	FindingsToday  int `json:"findingsToday"`  // 今日新发现漏洞
	FindingsWeek   int `json:"findingsWeek"`   // 近 7 天新发现漏洞
	FixedWeek      int `json:"fixedWeek"`      // 近 7 天修复漏洞
	WhitelistCount int `json:"whitelistCount"` // 生效白名单条数
	FalsePosCount  int `json:"falsePosCount"`  // 误报标记条数
}

// TrendPoint 趋势图的一个数据点(一天)。
type TrendPoint struct {
	Date   string `json:"date"`   // 2006-01-02
	Label  string `json:"label"`  // 01-02(图表 X 轴用, 省得前端再切字符串)
	New    int    `json:"new"`    // 当日新增漏洞(首次发现)
	Fixed  int    `json:"fixed"`  // 当日修复漏洞
	Opened int    `json:"opened"` // 当日新增 - 当日修复(可负, 表示净收敛)
}

// Trend 趋势区数据。
type Trend struct {
	Days   int          `json:"days"`
	Points []TrendPoint `json:"points"`
	// NewTotal / FixedTotal 窗口内合计(前端懒得自己 reduce 时直接用)。
	NewTotal   int `json:"newTotal"`
	FixedTotal int `json:"fixedTotal"`
}

// TopVuln 高危漏洞 TOP 榜单项。
//
// 刻意不带 Evidence/Request/Response: 大屏只展示"哪台机器上有什么风险",
// 证据报文动辄几十 KB, 放进轮询响应会把接口体积顶到不可接受。
type TopVuln struct {
	ID         string    `json:"id"`
	AssetIP    string    `json:"assetIp"`
	Port       int       `json:"port"`
	Protocol   string    `json:"protocol,omitempty"`
	Severity   string    `json:"severity"`
	Title      string    `json:"title"`
	CVE        string    `json:"cve,omitempty"`
	CVSS       float64   `json:"cvss,omitempty"`
	Confidence int       `json:"confidence"`
	Source     string    `json:"source,omitempty"`
	FoundAt    time.Time `json:"foundAt"`
	LastSeenAt time.Time `json:"lastSeenAt"`
}

// assetRisk 单个资产的风险计数聚合中间态(不对外暴露)。
type assetRisk struct {
	risk     int // 风险类漏洞数(不含 info)
	critical int
	high     int
}

// TopAsset 风险资产排行项(按"风险类漏洞数"排序)。
type TopAsset struct {
	IP        string `json:"ip"`
	Hostname  string `json:"hostname,omitempty"`
	OS        string `json:"os,omitempty"`
	Risk      int    `json:"risk"`      // 风险类漏洞数(不含 info)
	Critical  int    `json:"critical"`  // 其中严重
	High      int    `json:"high"`      // 其中高危
	OpenPorts int    `json:"openPorts"` // 开放端口数
}

// ProbeNode 探针在线状态与负载(状态面板)。
//
// 负载字段用指针 + omitempty: "探针只登记未上线"与"上线了但没报负载"是
// 两种不同状态, 指针为 nil 时前端显示 "-" 而不是误导性的 0%。
type ProbeNode struct {
	ID           string    `json:"id"`
	Name         string    `json:"name,omitempty"`
	Status       string    `json:"status"`
	Online       bool      `json:"online"`
	Addr         string    `json:"addr,omitempty"`
	Capabilities string    `json:"capabilities,omitempty"`
	CPUPercent   *float64  `json:"cpuPercent,omitempty"`
	MemPercent   *float64  `json:"memPercent,omitempty"`
	DiskPercent  *float64  `json:"diskPercent,omitempty"`
	Hostname     string    `json:"hostname,omitempty"`
	OS           string    `json:"os,omitempty"`
	CPUCores     int       `json:"cpuCores,omitempty"`
	MemTotal     uint64    `json:"memTotal,omitempty"`
	MemUsed      uint64    `json:"memUsed,omitempty"`
	TasksRunning int       `json:"tasksRunning"`
	CurrentTask  string    `json:"currentTask,omitempty"`
	TaskTotal    int       `json:"taskTotal"`
	TaskSuccess  int       `json:"taskSuccess"`
	TaskFailed   int       `json:"taskFailed"`
	LastSeenAt   time.Time `json:"lastSeenAt"`
}

// Snapshot 大屏一次刷新的完整数据(对应一个 HTTP 响应体)。
type Snapshot struct {
	GeneratedAt time.Time   `json:"generatedAt"`
	TrendDays   int         `json:"trendDays"`
	Overview    Overview    `json:"overview"`
	Trend       Trend       `json:"trend"`
	Severity    []SevBar    `json:"severity"`     // 漏洞风险占比(饼图/条形图通用)
	Probes      []ProbeNode `json:"probes"`       // 探针在线状态 + 负载
	TopVulns    []TopVuln   `json:"topVulns"`     // 高危漏洞 TOP
	TopAssets   []TopAsset  `json:"topAssets"`    // 风险资产 TOP
	RecentTasks []TaskBrief `json:"recentTasks"`  // 最近任务(大屏底部滚动条)
	Warnings    []string    `json:"warnings,omitempty"` // 降级/数据缺失提示(非致命)
}

// SevBar 漏洞风险占比的一项(前端饼图/环形图/条形图共用同一份数据)。
type SevBar struct {
	Key   string  `json:"key"`
	Count int     `json:"count"`
	Pct   float64 `json:"pct"` // 占比百分数(保留 1 位小数), 基于风险类合计
}

// TaskBrief 最近任务摘要(大屏滚动列表)。
type TaskBrief struct {
	ID        string     `json:"id"`
	Type      string     `json:"type"`
	Target    string     `json:"target"`
	Status    string     `json:"status"`
	ProbeNode string     `json:"probeNode,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	FinishedAt *time.Time `json:"finishedAt,omitempty"`
}
