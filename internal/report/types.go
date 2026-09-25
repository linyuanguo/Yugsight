// Package report Yugsight 商业级报告引擎(任务 7.2)。
//
// 职责边界(与既有代码的分工):
//
//	report 包   = 纯数据 + 渲染: 快照存档结构、多维筛选、聚合统计、
//	              拓扑构建、历史对比算法、HTML/PDF 导出
//	装配层      = report_api.go(main 包): 从 db 取数填充快照、落库存档、暴露 HTTP
//
// 为什么不依赖 db 包:
//
//	1. report 只依赖 models + 标准库, 可以脱离数据库单测(算法正确性靠单测守护);
//	2. 未来换存储(SQLite/PostgreSQL)时报告引擎零改动;
//	3. 分层清晰: "取数"是装配层的事, "算与画"是本包的事。
//
// PDF 生成说明(重要设计取舍):
//
//	纯标准库无法可靠地生成带中文字体的 PDF —— Go 标准库不含 PDF 库, 而中文字体
//	子集嵌入需要 TrueType 解析与 CID 字体映射(数千行且极易出乱码), 也与项目
//	"零第三方依赖"的硬约束冲突。因此采用行业通行的等效方案:
//
//	  1. 生成的 HTML 自带 @page/@media print 分页与打印样式(浏览器"另存为 PDF"即得正式报告);
//	  2. 提供 PrintHTML(): 在服务器端把 HTML 包装成带"自动唤起打印"脚本的页面,
//	     前端在新窗口打开即自动弹打印对话框, 用户一步导出 PDF。
//
//	这样既满足"HTML + PDF 导出"的业务要求, 又不引入任何第三方依赖。
package report

import (
	"encoding/base64"
	"time"

	"yugsight/internal/models"
)

// 报告状态常量(与存档记录 Status 字段对应)。
const (
	StatusReady = "ready" // 已生成可下载/导出
	StatusDraft = "draft" // 仅存档元数据, 无渲染产物(预留)
)

// 导出格式。
const (
	FormatHTML = "html"
	FormatPDF  = "pdf" // 经由浏览器打印通道(PrintHTML)
	FormatJSON = "json"
	// FormatWord Word 文档(.docx, 纯标准库 docx 引擎, 见 docx.go)。
	// 由 Word 模板渲染: word/html/pdf 三种格式共享同一份模板与章节(用户
	// 2026-09-20 要求"基于 Word 模板生成三种类型")。
	FormatWord = "word"
)

// Header 报告页眉页脚模板(任务书: 报告模板支持自定义页眉页脚)。
//
// 所有字段支持 {{占位符}} 展开, 可用占位符:
//
//	{{title}}     报告标题
//	{{operator}}  操作者
//	{{time}}      生成时间
//	{{page}}      页码(浏览器打印时由 CSS 计数器填充, 不参与文本替换)
//	{{tool}}      工具名与版本
//
// 为空时回落到内置默认文案(不是"什么都不显示")。
type Header struct {
	HeaderLeft   string `json:"headerLeft,omitempty"`
	HeaderCenter string `json:"headerCenter,omitempty"`
	HeaderRight  string `json:"headerRight,omitempty"`
	FooterLeft   string `json:"footerLeft,omitempty"`
	FooterCenter string `json:"footerCenter,omitempty"`
	FooterRight  string `json:"footerRight,omitempty"`
	// ShowPageNumber 页脚是否显示页码(默认 true)
	ShowPageNumber *bool `json:"showPageNumber,omitempty"`
	// Disclaimer 免责声明(为空用内置默认)
	Disclaimer string `json:"disclaimer,omitempty"`
}

// Archive 报告存档记录(任务书: 报告存档通过 DAO 持久化, 可随时重新下载)。
//
// Content 内联保存渲染产物(HTML 文本)。为什么内联而不是只存路径:
//
//	报告是"出具即定稿"的合规材料, 存档必须自包含 —— 依赖外部文件路径会让
//	用户移动/清理目录后再也下载不到历史报告(存档就失去意义)。
type Archive struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Operator  string    `json:"operator,omitempty"`
	CreatedBy string    `json:"createdBy,omitempty"`
	CreatedAt time.Time `json:"createdAt"`

	// Format 导出格式(html / pdf / json)
	Format string `json:"format"`
	// Status 存档状态(ready / draft)
	Status string `json:"status,omitempty"`

	// Filter 生成时的筛选条件(回显与"按同条件重新生成")
	Filter Filter `json:"filter"`

	// Stats 汇总统计(列表页直接展示, 无需解析 Content)
	Stats SnapshotStats `json:"stats"`

	// Header 页眉页脚模板(重新渲染时复用)
	Header Header `json:"header,omitempty"`

	// TemplateName 使用的模板名(default / classic / 自定义)
	TemplateName string `json:"templateName,omitempty"`
	// TemplateID 关联的自定义模板 ID
	TemplateID string `json:"templateId,omitempty"`

	// Content 渲染产物(HTML 文本; 体积较大但保证自包含可下载)
	Content string `json:"content,omitempty"`
	// ContentB64 二进制产物(Word .docx)的 base64。文本格式(html/pdf/json)
	// 恒为空; 为什么用 base64 而不是新表: 存档表是 JSONL, 二进制直接内嵌
	// 会破坏行格式, base64 是唯一自包含且对存储层透明的携带方式。
	ContentB64 string `json:"contentB64,omitempty"`
	// Size 产物字节数
	Size int `json:"size,omitempty"`
	// Note 备注
	Note string `json:"note,omitempty"`
}

// EntityID 实现 db.Entity 契约(存档 ID 稳定不变)。
func (a *Archive) EntityID() string {
	if a.ID == "" {
		a.ID = NewArchiveID()
	}
	return a.ID
}

// Validate 自检: 标题必填, 缺省字段补全。
//
// 刻意保持宽松(不因缺字段拒绝存档): 存档是不可逆操作, 宁可存下不完美的报告,
// 也不要让用户因为"操作者没填"而丢掉整份报告。
func (a *Archive) Validate() error {
	if a.Title == "" {
		a.Title = "Yugsight 安全扫描报告"
	}
	if a.Format == "" {
		a.Format = FormatHTML
	}
	if a.Status == "" {
		a.Status = StatusReady
	}
	if a.CreatedAt.IsZero() {
		a.CreatedAt = time.Now()
	}
	if a.ContentB64 != "" {
		// 二进制产物: Size 记录解码后字节数(下载时的真实文件大小)
		if dec, err := base64.StdEncoding.DecodeString(a.ContentB64); err == nil {
			a.Size = len(dec)
		} else {
			a.Size = len(a.ContentB64)
		}
	} else {
		a.Size = len(a.Content)
	}
	return nil
}

// Filter 报告内容多维筛选条件(任务书: 按风险等级 / IP 段 / CVE 编号 / 扫描时间 / 探针节点筛选)。
//
// 所有字段为零值 = 不过滤。多字段之间是"与"关系。
type Filter struct {
	// Severity 风险等级列表(critical/high/medium/low/info; 空 = 全部)
	Severity []string `json:"severity,omitempty"`
	// IP 精确 IP(归一化后匹配)
	IP string `json:"ip,omitempty"`
	// CIDR IP 段筛选(如 192.168.1.0/24; 非法值被忽略)
	CIDR string `json:"cidr,omitempty"`
	// CVE CVE 编号(归一化后前缀匹配, 支持 "CVE-2021" 这类前缀)
	CVE string `json:"cve,omitempty"`
	// ProbeNode 探针节点 ID(空串不代表"本地", 见 IncludeLocal)
	ProbeNode string `json:"probeNode,omitempty"`
	// IncludeLocal 与 ProbeNode="local" 同义: 筛选本地(非探针)扫描的条目
	IncludeLocal bool `json:"includeLocal,omitempty"`
	// TimeFrom / TimeTo 扫描时间范围(按发现时间过滤)
	TimeFrom time.Time `json:"timeFrom,omitempty"`
	TimeTo   time.Time `json:"timeTo,omitempty"`
	// Status 漏洞状态(new/duplicate/fixed)
	Status string `json:"status,omitempty"`
	// OnlyWithEvidence 仅保留带验证证据的条目
	OnlyWithEvidence bool `json:"onlyWithEvidence,omitempty"`
	// ExcludeFalsePositive 排除人工标记的误报(默认 true, 报告不应统计误报)
	ExcludeFalsePositive *bool `json:"excludeFalsePositive,omitempty"`
	// Keywords 标题关键字(包含匹配, 大小写不敏感)
	Keywords string `json:"keywords,omitempty"`
}

// LocalNode 本地执行的标识(非探针下发)。
const LocalNode = "local"

// Snapshot 报告数据快照: 生成报告所需的全部数据(与存储层解耦)。
type Snapshot struct {
	Title     string    `json:"title"`
	Operator  string    `json:"operator,omitempty"`
	Tool      string    `json:"tool,omitempty"`
	CreatedAt time.Time `json:"createdAt"`

	Filter Filter `json:"filter"`

	Assets []*models.Asset `json:"assets"`
	Vulns  []*models.Vuln  `json:"vulns"`

	// Scans 相关扫描任务(可选, 用于"扫描范围"章节)
	Scans []ScanInfo `json:"scans,omitempty"`

	// Topology 资产拓扑(可选, 为空时由 BuildTopology 依 Assets/Vulns 构建)
	Topology *Topology `json:"topology,omitempty"`

	// Summary 报告摘要/总体结论(可选, 为空时自动生成)
	Summary string `json:"summary,omitempty"`

	// Penta 渗透验证结果(阶段 5: 整合报告"扫描+渗透验证", 无数据时省略)
	Penta []PentaEntry `json:"penta,omitempty"`
}

// PentaEntry 渗透验证条目(只收录已得出验证结论的任务)。
type PentaEntry struct {
	TaskID         string    `json:"taskId"`
	Target         string    `json:"target"`
	Title          string    `json:"title,omitempty"`
	CVE            string    `json:"cve,omitempty"`
	Exploitability string    `json:"exploitability"` // exploitable / partial / not_exploitable
	RiskLevel      string    `json:"riskLevel,omitempty"`
	Summary        string    `json:"summary,omitempty"`
	Operator       string    `json:"operator,omitempty"`
	VerifiedAt     time.Time `json:"verifiedAt,omitempty"`
}

// ScanInfo 报告中展示的扫描任务条目(来自 db.ScanTask 的精简视图)。
type ScanInfo struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`
	Target     string    `json:"target"`
	Status     string    `json:"status"`
	ProbeNode  string    `json:"probeNode,omitempty"`
	Result     string    `json:"result,omitempty"`
	CreatedAt  time.Time `json:"createdAt"`
	FinishedAt time.Time `json:"finishedAt,omitempty"`
}

// SnapshotStats 聚合统计(风险总览图表的数据源)。
type SnapshotStats struct {
	AssetTotal int `json:"assetTotal"` // 资产总数
	AssetAlive int `json:"assetAlive"` // 在线资产数
	PortTotal  int `json:"portTotal"`  // 开放端口总数
	VulnTotal  int `json:"vulnTotal"`  // 漏洞总数

	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Info     int `json:"info"`

	WithCVE      int `json:"withCve"`      // 带 CVE 编号的漏洞数
	WithEvidence int `json:"withEvidence"` // 带验证证据的漏洞数
	WithFix      int `json:"withFix"`      // 有修复建议的漏洞数
	WithPcap     int `json:"withPcap"`     // 有 PCAP 附件的漏洞数
	FalsePos     int `json:"falsePos"`     // 被排除的误报数(透明展示)

	// RiskScore 风险评分 0-100(越高越危险), RiskLevel 对应等级文案
	RiskScore int    `json:"riskScore"`
	RiskLevel string `json:"riskLevel"`

	// BySource 来源分布(引擎/探针), 用于图表
	BySource map[string]int `json:"bySource,omitempty"`
	// ByProbe 探针节点分布
	ByProbe map[string]int `json:"byProbe,omitempty"`
	// BySeverity 等级分布(与上方字段重复但便于前端直接遍历画图)
	BySeverity map[string]int `json:"bySeverity,omitempty"`
}

// Topology 资产拓扑: IP -> 端口 -> 服务 的关联关系(前端画布数据源)。
//
// 结构刻意做成"扁平节点 + 边"而不是嵌套树:
// 前端画布(Canvas/SVG)需要的是统一坐标与连线列表, 嵌套结构还得再摊平一次。
type Topology struct {
	Nodes []TopoNode `json:"nodes"`
	Edges []TopoEdge `json:"edges"`

	// Stats 拓扑汇总
	Stats TopoStats `json:"stats"`
}

// TopoNode 拓扑节点。
type TopoNode struct {
	ID    string `json:"id"`    // 节点唯一 ID(资产为 IP; 端口为 "ip:port"; 服务为 "ip:port/svc")
	Kind  string `json:"kind"`  // asset | port | service | probe
	Label string `json:"label"` // 显示文本

	IP    string `json:"ip,omitempty"`
	Port  int    `json:"port,omitempty"`
	Proto string `json:"proto,omitempty"` // tcp / http / https ...
	// Service 服务名(如 http / ssh / mysql)
	Service string `json:"service,omitempty"`
	Version string `json:"version,omitempty"`

	// Online 资产在线状态(存活探测结果; 无存活信息时为 true 但 Unknown=true)
	Online  bool `json:"online"`
	Unknown bool `json:"unknown,omitempty"`

	// Risk 该节点风险等级(critical/high/medium/low/info/none) —— 前端按此着色
	Risk string `json:"risk"`
	// VulnCount 关联漏洞数
	VulnCount int `json:"vulnCount"`

	// OS / Hostname / Tags 资产附加信息
	OS       string   `json:"os,omitempty"`
	Hostname string   `json:"hostname,omitempty"`
	Tags     []string `json:"tags,omitempty"`
	// ProbeNode 来源探针节点(空 = 本地)
	ProbeNode string `json:"probeNode,omitempty"`
	// Severity 风险级别明细(资产节点用: 各等级漏洞数)
	Severity map[string]int `json:"severity,omitempty"`
}

// TopoEdge 拓扑边(父子关联)。
type TopoEdge struct {
	From  string `json:"from"`
	To    string `json:"to"`
	Kind  string `json:"kind"` // host-port | port-service
	Label string `json:"label,omitempty"`
	// Risk 边上的最高风险等级(前端高亮重点路径)
	Risk string `json:"risk,omitempty"`
}

// TopoStats 拓扑汇总。
type TopoStats struct {
	Assets   int `json:"assets"`
	Ports    int `json:"ports"`
	Services int `json:"services"`
	Online   int `json:"online"`
	Offline  int `json:"offline"`
	AtRisk   int `json:"atRisk"` // 存在高危风险的资产数
}

// Diff 历史扫描对比结果(任务书: 自动识别新增 / 已修复 / 仍然存在的漏洞)。
type Diff struct {
	BaseID   string    `json:"baseId"`   // 基线(较早)扫描标识
	TargetID string    `json:"targetId"` // 对比目标(较晚)扫描标识
	BaseName string    `json:"baseName,omitempty"`
	TargetName string  `json:"targetName,omitempty"`
	ComparedAt time.Time `json:"comparedAt"`

	// New 新增漏洞(基线没有, 目标有) —— 需要立即处置
	New []*DiffItem `json:"new"`
	// Fixed 已修复漏洞(基线有, 目标没有) —— 可确认修复成效
	Fixed []*DiffItem `json:"fixed"`
	// Persisted 仍然存在的漏洞(两次都有)
	Persisted []*DiffItem `json:"persisted"`
	// Appeared / Disappeared 资产维度的变化
	NewAssets   []string `json:"newAssets"`
	FixedAssets []string `json:"fixedAssets"`

	// Stats 差异统计
	Stats DiffStats `json:"stats"`
}

// DiffItem 单条差异条目。
type DiffItem struct {
	Key      string `json:"key"` // 合并键(models.Vuln.MergeKey)
	CVE      string `json:"cve,omitempty"`
	Title    string `json:"title"`
	AssetIP  string `json:"assetIp"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`

	BaseSeverity   string `json:"baseSeverity,omitempty"`
	TargetSeverity string `json:"targetSeverity,omitempty"`
	// SeverityChange 等级变化(如 "medium -> high"; 未变化为空)
	SeverityChange string `json:"severityChange,omitempty"`

	BaseConfidence   int `json:"baseConfidence,omitempty"`
	TargetConfidence int `json:"targetConfidence,omitempty"`

	BaseFoundAt   time.Time `json:"baseFoundAt,omitempty"`
	TargetFoundAt time.Time `json:"targetFoundAt,omitempty"`

	Status string `json:"status"` // new | fixed | persisted
	// Vuln 目标侧(新增/仍然存在)漏洞详情; 已修复条目取基线侧详情
	Vuln *models.Vuln `json:"vuln,omitempty"`
}

// DiffStats 差异统计。
type DiffStats struct {
	BaseTotal      int `json:"baseTotal"`
	TargetTotal    int `json:"targetTotal"`
	NewCount       int `json:"newCount"`
	FixedCount     int `json:"fixedCount"`
	PersistedCount int `json:"persistedCount"`
	// Delta 总数变化(目标 - 基线)
	Delta int `json:"delta"`
	// NewCritical / NewHigh 新增中的高危数量(最需要关注的两个数字)
	NewCritical int `json:"newCritical"`
	NewHigh     int `json:"newHigh"`

	BaseAssetTotal   int `json:"baseAssetTotal"`
	TargetAssetTotal int `json:"targetAssetTotal"`
	NewAssetCount    int `json:"newAssetCount"`
	FixedAssetCount  int `json:"fixedAssetCount"`
}

// HistoryEntry 历史扫描记录(供前端做对比选择)。
type HistoryEntry struct {
	ID        string    `json:"id"`
	Name      string    `json:"name,omitempty"`
	Target    string    `json:"target,omitempty"`
	Type      string    `json:"type,omitempty"`
	ProbeNode string    `json:"probeNode,omitempty"`
	Status    string    `json:"status,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
	// VulnCount / AssetCount 该次扫描的规模(用于列表展示)
	VulnCount  int `json:"vulnCount"`
	AssetCount int `json:"assetCount"`
}

// Template 报告模板(自定义页眉页脚 / 样式开关)。
type Template struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	Builtin   bool      `json:"builtin,omitempty"`
	CreatedAt time.Time `json:"createdAt,omitempty"`

	Header Header `json:"header"`

	// Accent 主题色(十六进制, 如 #4f46e5); 为空用内置默认
	Accent string `json:"accent,omitempty"`
	// LogoText 封面品牌文案
	LogoText string `json:"logoText,omitempty"`
	// Subtitle 封面副标题
	Subtitle string `json:"subtitle,omitempty"`
	// ShowTopology / ShowEvidence / ShowRaw 章节开关
	ShowTopology *bool `json:"showTopology,omitempty"`
	ShowEvidence *bool `json:"showEvidence,omitempty"`
	ShowRaw      *bool `json:"showRaw,omitempty"`
	// Sections 章节顺序(空 = 内置顺序)
	Sections []string `json:"sections,omitempty"`
}

// EntityID 实现 db.Entity 契约。
func (t *Template) EntityID() string {
	if t.ID == "" {
		t.ID = NewTemplateID()
	}
	return t.ID
}

// Validate 自检: 模板名必填。
func (t *Template) Validate() error {
	if t.Name == "" {
		t.Name = "自定义模板"
	}
	if t.CreatedAt.IsZero() {
		t.CreatedAt = time.Now()
	}
	return nil
}
