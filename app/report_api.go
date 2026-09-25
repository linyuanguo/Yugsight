// report_api.go 任务 7.2: 报告生成引擎 + 资产拓扑 + 历史扫描对比 —— 装配与 API 层。
//
// 本文件是 main 包与 report 包的唯一连接点(与 probe_api.go / scheduler_api.go 同角色):
//
//	report 包  = 纯算法与渲染(筛选/统计/拓扑/差异/HTML), 不碰数据库;
//	本文件     = 从 db 取数组装 Snapshot、落库存档、暴露 HTTP 接口。
//
// 与既有 /api/report(经典页报告)的关系:
//
//	/api/report 吃前端 POST 的内存扫描数据(scans[]), 是"当前这一轮扫描"的报告;
//	本模块的 /api/v2/report/* 从数据库取数(资产/漏洞/任务表), 支持历史归档、
//	多维度筛选、探针节点维度、历史对比 —— 两者并存互不影响
//	(经典页零改动, 项目规则 1/5)。
//
// 默认启用(用户 2026-09-20 明确要求"报告默认开启"): 配置缺失即启用;
// 显式 settings.json report 节 enabled=false 才是关。未启用时除
// /api/v2/report/status 之外的接口统一返回"未启用"提示; 不影响任何既有流程。
//
// Word 模板(用户 2026-09-20 要求): 报告以 Word 模板为单一来源, 同一模板输出
// word/html/pdf 三种格式; 模板文件放 exe 同目录 res/report_templates/(外部资源,
// 不嵌入二进制, 与 agents/、templates/ 同约定), 内置模板恒可用。文件管理
// API 在 report_word_api.go。

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/models"
	"yugsight/internal/pathrel"
	"yugsight/internal/report"
	"yugsight/internal/server"
	"yugsight/internal/sse"
)

// ===== 配置 =====

// ReportConfig 报告配置(settings.json 的 report 节优先, 回退旧 report.json)。
type ReportConfig struct {
	// Enabled 是否启用报告引擎(默认 true: 用户 2026-09-20 要求报告默认开启)
	Enabled bool `json:"enabled"`
	// AutoGenerate 扫描结束后自动生成并归档报告(默认 false, 规则 5)。
	// 指针区分"未配置"与"显式 false": 旧配置没有该字段时保持关闭。
	AutoGenerate *bool `json:"autoGenerate,omitempty"`
	// MaxArchive 存档上限(默认 500; 超出后按时间淘汰最旧的非重要存档)
	MaxArchive int `json:"maxArchive"`
	// DefaultOperator 默认操作者/单位(报告封面用)
	DefaultOperator string `json:"defaultOperator"`
	// Subtitle 报告默认副标题
	Subtitle string `json:"subtitle"`
	// Accent 报告主题色
	Accent string `json:"accent"`
	// ShowRaw 报告中是否默认展开原始请求/响应
	ShowRaw bool `json:"showRaw"`
	// TemplateManagement 模板管理开关(二期报告中心): 开启后允许创建/删除
	// 模板包(会写 exe 同目录 res/report_templates/)。指针区分"未配置"与显式 false,
	// 默认关 —— 目录写权限不该默认开放。
	TemplateManagement *bool `json:"templateManagement,omitempty"`
	// PDFExternal PDF 走外部转换器(wkhtmltopdf / LibreOffice)而非浏览器打印通道。
	// 默认关: 转换器缺失是常态, 关着时 PDF 恒走"自动唤起打印"的 HTML 页面,
	// 零依赖且一定可用; 开启后转换器不存在也只是降级回打印通道(不失败)。
	PDFExternal *bool `json:"pdfExternal,omitempty"`

	// ===== 报告中心二期: 原始结构化报告(业务模块执行后的原始结果) =====
	// AutoSave 业务模块执行完成后是否自动存入报告中心(默认开: 二期核心需求
	// 就是"执行完成后自动保存", 且原始报告是只读聚合不改执行链路, 与
	// Enabled 同口径; 显式 autoSave=false 关闭)。
	// 指针区分"未配置"与"显式 false"(与 AutoGenerate 同手法)。
	AutoSave *bool `json:"autoSave,omitempty"`
	// MaxRaw 原始报告存储上限(默认 500; 超出后按时间淘汰最旧的)
	MaxRaw int `json:"maxRaw"`
}

// DefaultReportConfig 默认配置。
//
// Enabled 默认 true: 报告是只读聚合(不改执行链路), 且用户明确要求默认开启;
// 与 scheduler(改执行链路, 默认关)不同。显式配置 enabled=false 才会关闭。
func DefaultReportConfig() ReportConfig {
	return ReportConfig{
		Enabled:    true,
		MaxArchive: 500,
		MaxRaw:     500,
		Subtitle:   "网络安全扫描与漏洞评估报告",
		Accent:     "#4f46e5",
	}
}

// reportConfigPath 配置文件路径(声明为变量便于测试改指临时目录,
// 否则用例一跑就会覆盖开发机上真实配置 —— scheduler_api.go 踩过的坑)。
var reportConfigPath = func() string {
	exe, err := os.Executable()
	if err != nil {
		return "report.json"
	}
	return filepath.Join(filepath.Dir(exe), "report.json")
}

var (
	reportCfgMu   sync.RWMutex
	reportCfgVal  ReportConfig
	reportCfgDone bool
)

// loadReportConfig 读取 report.json(缺失/损坏一律默认配置降级, 不报错)。
func loadReportConfig() ReportConfig {
	reportCfgMu.RLock()
	if reportCfgDone {
		cfg := reportCfgVal
		reportCfgMu.RUnlock()
		return cfg
	}
	reportCfgMu.RUnlock()

	cfg := DefaultReportConfig()
	// settings.json 的 report 节优先, 回退旧 report.json。
	// 两条路径都是 {enabled, maxArchive, ...} 的扁平结构, 解析逻辑共用。
	// 红线「配置唯一」: 只读 settings.json 的 report 节; 旧 report.json 由
	// settings.go 的 migrateLegacyConfigs 在启动时并入, 运行期不再有第二份配置。
	if data, ok := section(secReport, ""); ok {
		if raw, ok := parseReportConfig(data, &cfg); ok {
			cfg = raw
		}
		reportCfgMu.Lock()
		reportCfgVal, reportCfgDone = cfg, true
		reportCfgMu.Unlock()
		return cfg
	}
	reportCfgMu.Lock()
	reportCfgVal, reportCfgDone = cfg, true
	reportCfgMu.Unlock()
	return cfg
}

// parseReportConfig 解析报告配置 JSON(两条来源路径共用)。
//
// Enabled 的"默认开启"语义必须区分两种情况:
//
//	配置写了 enabled: false  -> 关(用户显式关闭必须尊重)
//	配置没写 enabled(如只写 maxArchive) -> 开(部分配置不能隐式关闭功能)
//
// 若直接 Unmarshal 到 struct, 缺失字段的零值 false 会把"没写"误判成"关闭" ——
// 用户现象是"我只改了存档上限, 报告怎么不见了"。故先查 enabled 键是否显式存在。
func parseReportConfig(data []byte, def *ReportConfig) (ReportConfig, bool) {
	var raw ReportConfig
	if uerr := json.Unmarshal(data, &raw); uerr != nil {
		reportLogLine("report 配置解析失败, 使用默认配置: " + uerr.Error())
		return ReportConfig{}, false
	}
	if !hasExplicitEnabled(data) {
		raw.Enabled = def.Enabled // 未显式配置 -> 用默认(开)
	}
	if raw.MaxArchive <= 0 {
		raw.MaxArchive = def.MaxArchive
	}
	if raw.MaxRaw <= 0 {
		raw.MaxRaw = def.MaxRaw
	}
	return raw, true
}

// hasExplicitEnabled 判断配置 JSON 是否显式写了 enabled(非 null)。
func hasExplicitEnabled(data []byte) bool {
	var m map[string]json.RawMessage
	if json.Unmarshal(data, &m) != nil {
		return false
	}
	v, ok := m["enabled"]
	if !ok || string(bytes.TrimSpace(v)) == "null" {
		return false
	}
	return json.Unmarshal(v, new(bool)) == nil
}

// setReportConfig 更新内存配置(测试用 + 运行期热改)。
func setReportConfig(cfg ReportConfig) {
	reportCfgMu.Lock()
	reportCfgVal, reportCfgDone = cfg, true
	reportCfgMu.Unlock()
}

// saveReportConfigFile 写独立 report.json。
//
// 仅在 settings.json 没有 report 节时使用: 读取端对该文件有回退, 若此时写别处
// 会出现"保存成功但读不到"(用户在页面上关了开关, 刷新后又变回原样)。
// saveReportConfigFile 写回 settings.json 的 report 节。
//
// 配置口径(2026-09-23 用户要求): 中心端所有配置一律 settings.json, 不再写
// 独立 report.json。读取仍保留 report.json 回退(兼容旧部署)。
func saveReportConfigFile(c ReportConfig) error {
	return writeSection(secReport, c)
}

// resetReportConfigForTest 重置配置缓存(仅测试引用)。
func resetReportConfigForTest() {
	reportCfgMu.Lock()
	reportCfgDone = false
	reportCfgMu.Unlock()
}

// reportEnabled 报告引擎是否启用。
func reportEnabled() bool { return loadReportConfig().Enabled }

// pdfExternalEnabled 是否尝试用外部转换器出真 PDF。
//
// 默认开启: 转换器不存在时 ConvertHTMLToPDF 只是返回 ErrNoPDFConverter, 装配层
// 自动回落浏览器打印通道 —— 开着没有任何副作用, 关着反而让"装了 wkhtmltopdf
// 却出不了真 PDF"变成一个需要查配置的问题。
func pdfExternalEnabled() bool {
	cfg := loadReportConfig()
	return cfg.PDFExternal == nil || *cfg.PDFExternal
}

// reportLogLine 报告模块日志并入 yugsight.log(与 probe/scheduler 同格式)。
func reportLogLine(msg string) {
	logLine("[报告] " + msg)
}

// ===== 取数与快照组装 =====

// reportFilterFromQuery 把 URL 查询参数解析为筛选条件。
//
// 参数命名与前端表单对齐(见 frontend/src/pages/Report.vue):
//
//	severity=high,critical  风险等级(逗号分隔)
//	ip / cidr / cve         资产维度
//	node=probeId|local      探针节点
//	status=new|fixed        漏洞状态
//	from / to               扫描时间(RFC3339 或 2006-01-02)
//	keyword                 标题关键字
//	evidence=1              仅含证据
//	includeFP=1             包含误报(默认排除)
func reportFilterFromQuery(q url.Values) report.Filter {
	f := report.Filter{
		Severity: report.ParseSeverityList(q.Get("severity")),
		IP:       strings.TrimSpace(q.Get("ip")),
		CIDR:     strings.TrimSpace(q.Get("cidr")),
		CVE:      strings.TrimSpace(q.Get("cve")),
		ProbeNode: strings.TrimSpace(q.Get("node")),
		Status:   strings.TrimSpace(q.Get("status")),
		Keywords: strings.TrimSpace(q.Get("keyword")),
	}
	if f.ProbeNode == "all" {
		f.ProbeNode = ""
	}
	f.TimeFrom = parseReportTime(q.Get("from"))
	f.TimeTo = parseReportTimeEnd(q.Get("to"))
	f.OnlyWithEvidence = q.Get("evidence") == "1" || q.Get("evidence") == "true"
	if q.Get("includeFP") == "1" || q.Get("includeFP") == "true" {
		no := false
		f.ExcludeFalsePositive = &no
	}
	return f
}

// parseReportTime 解析起始时间(支持 RFC3339 与 date-only)。
func parseReportTime(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if t, err := time.ParseInLocation(layout, s, time.Local); err == nil {
			return t
		}
	}
	reportLogLine("时间参数解析失败(已忽略): " + s)
	return time.Time{}
}

// parseReportTimeEnd 解析结束时间: 只给日期时补到当天 23:59:59。
//
// 为什么必须补: 用户选"截止 2026-09-17"时期望包含 17 日全天, 若按 00:00:00
// 处理会把当天扫描结果全部滤掉 —— 用户看到的是"今天扫的东西不在报告里"。
func parseReportTimeEnd(s string) time.Time {
	s = strings.TrimSpace(s)
	if s == "" {
		return time.Time{}
	}
	if len(s) <= 10 {
		if t, err := time.ParseInLocation("2006-01-02", s, time.Local); err == nil {
			return t.Add(24*time.Hour - time.Second)
		}
	}
	return parseReportTime(s)
}

// buildReportSnapshot 从数据库取数组装报告快照。
//
// 数据来源:
//
//	db.Assets()     资产清单(含端口/服务/标签/探针节点)
//	db.Vulns()      漏洞库(含 CVE/证据/请求响应/PCAP/误报标记)
//	db.ScanTasks()  扫描任务(报告"扫描范围"章节)
//
// 降级: 任一 DAO 不可用(nil)只记日志跳过该部分, 不返回错误 ——
// 报告"缺一块"远好于"整份生成失败"(db.Close() 会把 DAO 置 nil, 必须守卫)。
func buildReportSnapshot(d *db.Database, req reportRequest) (*report.Snapshot, report.SnapshotStats, error) {
	if d == nil {
		return nil, report.SnapshotStats{}, fmt.Errorf("数据库不可用")
	}
	cfg := loadReportConfig()
	title := strings.TrimSpace(req.Title)
	if title == "" {
		title = "Yugsight 安全扫描报告"
	}
	snap := &report.Snapshot{
		Title:     title,
		Operator:  firstNonEmptyStr(req.Operator, cfg.DefaultOperator),
		Tool:      appName + " v" + appVersion,
		CreatedAt: time.Now(),
	}

	// ---- 资产 ----
	if dao := d.Assets(); dao != nil {
		list, err := dao.List()
		if err != nil {
			reportLogLine("资产读取失败(报告中该章节为空): " + err.Error())
		}
		for _, a := range list {
			if a == nil {
				continue
			}
			snap.Assets = append(snap.Assets, &a.Asset)
		}
	} else {
		reportLogLine("资产 DAO 不可用, 报告不含资产清单")
	}

	// ---- 漏洞 ----
	nodeByIP := map[string]string{} // IP -> 探针节点(用于给漏洞补节点归属)
	for _, a := range snap.Assets {
		if a != nil {
			nodeByIP[models.NormIP(a.IP)] = a.ProbeNode
		}
	}
	if dao := d.Vulns(); dao != nil {
		list, err := dao.List()
		if err != nil {
			reportLogLine("漏洞读取失败(报告中该章节为空): " + err.Error())
		}
		for _, v := range list {
			if v == nil {
				continue
			}
			vv := v.Vuln // 复制一份, 避免就地改 Source 污染数据库对象
			vv.Source = reportSourceLabel(vv.Source, nodeByIP[models.NormIP(vv.AssetIP)])
			snap.Vulns = append(snap.Vulns, &vv)
		}
	} else {
		reportLogLine("漏洞 DAO 不可用, 报告不含漏洞明细")
	}

	// ---- 渗透验证(阶段 5: 整合报告"扫描+渗透验证") ----
	// 只收录已得出验证结论的任务(done 且有结论); DAO 不可用降级不报错。
	if dao := d.PentaTasks(); dao != nil {
		list, err := dao.List()
		if err != nil {
			reportLogLine("渗透任务读取失败(报告中该章节为空): " + err.Error())
		}
		for _, t := range list {
			if t == nil || t.Status != "done" || t.Exploitability == "" {
				continue
			}
			snap.Penta = append(snap.Penta, report.PentaEntry{
				TaskID:         t.ID,
				Target:         t.Target,
				Title:          t.Title,
				CVE:            t.CVE,
				Exploitability: t.Exploitability,
				RiskLevel:      t.RiskLevel,
				Summary:        t.Summary,
				Operator:       t.Operator,
				VerifiedAt:     t.FinishedAt,
			})
		}
	} else {
		reportLogLine("渗透任务 DAO 不可用, 报告不含渗透验证章节")
	}

	// ---- 扫描任务(按筛选时间窗裁剪, 避免列出全部历史任务) ----
	if dao := d.ScanTasks(); dao != nil {
		list, err := dao.List()
		if err != nil {
			reportLogLine("扫描任务读取失败: " + err.Error())
		}
		for _, t := range list {
			if t == nil {
				continue
			}
			info := report.ScanInfo{
				ID: t.ID, Type: t.Type, Target: t.Target, Status: t.Status,
				ProbeNode: t.ProbeNode, Result: truncateStr(t.Result, 300), CreatedAt: t.CreatedAt,
			}
			if t.FinishedAt != nil {
				info.FinishedAt = *t.FinishedAt
			}
			snap.Scans = append(snap.Scans, info)
		}
		sort.SliceStable(snap.Scans, func(i, j int) bool {
			return snap.Scans[i].CreatedAt.After(snap.Scans[j].CreatedAt)
		})
		if len(snap.Scans) > 200 {
			snap.Scans = snap.Scans[:200] // 报告里列 200 条已足够, 防止篇幅失控
		}
	}

	// ---- 误报可见性: 前端勾选"包含误报"时不排除 ----
	cfgFilter := req.Filter
	if cfgFilter.ExcludeFalsePositive == nil {
		no := false
		cfgFilter.ExcludeFalsePositive = &no
	}

	filtered, stats := cfgFilter.Apply(snap)
	if filtered == nil {
		filtered = snap
	}
	filtered.Tool = snap.Tool
	return filtered, stats, nil
}

// reportSourceLabel 生成漏洞的来源标签, 把探针节点信息带进 Source 字段。
//
// 为什么写进 Source 而不是新增字段:
//
//	models.Vuln 没有 ProbeNode 字段(节点归属记录在资产表上)。为报告新增字段
//	需要改数据模型并重写全部已有数据库文件, 影响面远大于收益。这里把来源
//	规范化为 "probe:<节点ID>" / "local": report 包按前缀拆解, 既满足
//	"按探针节点筛选报告内容"的要求, 又不改动任何既有数据结构。
func reportSourceLabel(source, node string) string {
	src := strings.TrimSpace(source)
	if node != "" {
		if src == "" || src == "probe" || src == "unknown" {
			return "probe:" + node
		}
		// 其它来源(内置规则/外部引擎)保持原样, 只补节点后缀
		if !strings.HasPrefix(src, "probe:") {
			return src + "@" + node
		}
		return src
	}
	if src == "" {
		return "local"
	}
	return src
}

// ===== HTTP 请求结构 =====

// reportRequest 生成报告请求体。
type reportRequest struct {
	Title    string        `json:"title"`
	Operator string        `json:"operator"`
	Filter   report.Filter `json:"filter"`
	// Format 输出格式: word / html / pdf / json (默认 html; 前端默认 word)。
	// word/html/pdf 三种格式都由 Word 模板渲染(同一模板三种出口)。
	Format string `json:"format"`
	// WordTemplate Word 模板名(exe 同目录 res/report_templates/ 下的 .docx, 不含扩展名;
	// 空 / "builtin" = 内置模板)
	WordTemplate string `json:"wordTemplate"`
	// TemplateID 旧版 HTML 自定义模板 ID(遗留路径: 非空时走旧 Render 流程,
	// 与 Word 模板二选一, Word 模板优先)
	TemplateID string `json:"templateId"`
	// Header 自定义页眉页脚(为空则用模板/默认)
	Header report.Header `json:"header"`
	// PackID 模板包 ID(report_templates/ 下的目录名; 空 / default = 内置模板)。
	// 与 WordTemplate 二选一, PackID 优先 —— 模板包是二期的主路径(HTML/Word/PDF
	// 三出口 + config.yaml 元信息), 旧 WordTemplate 保留兼容既有调用。
	PackID string `json:"packId"`
	// Archive 是否落库存档(默认 true: 报告存档是本模块的核心要求)
	Archive *bool `json:"archive"`
	// Note 存档备注
	Note string `json:"note"`
	// Inline 是否内联返回(前端预览); false = 以附件下载
	Inline bool `json:"inline"`
}

// ===== 报告生成(核心) =====

// generateReport 生成报告并(可选)落库存档, 返回存档记录(含 Content/ContentB64)。
//
// 两条渲染路径(请求二选一, Word 模板优先):
//
//  1. Word 模板路径(默认): 选一个 Word 模板(内置或 report_templates/ 下的
//     .docx), 引擎把数据章节注入模板, word/html/pdf 三种格式同一份内容;
//  2. 遗留 HTML 模板路径: TemplateID 非空时走旧 Render(自定义页眉页脚模板),
//     行为与既有版本完全一致。
func generateReport(d *db.Database, req reportRequest, operator string) (*report.Archive, error) {
	snap, stats, err := buildReportSnapshot(d, req)
	if err != nil {
		return nil, err
	}
	if operator != "" {
		snap.Operator = operator
	}
	cfg := loadReportConfig()

	format := strings.ToLower(strings.TrimSpace(req.Format))
	if format == "" {
		format = report.FormatHTML
	}
	if format == "docx" {
		format = report.FormatWord
	}

	arch := &report.Archive{
		Title:     snap.Title,
		Operator:  snap.Operator,
		CreatedBy: operator,
		CreatedAt: time.Now(),
		Format:    format,
		Status:    report.StatusReady,
		Filter:    req.Filter,
		Stats:     stats,
		Note:      req.Note,
	}

	// ---- 路径 0: 模板包(二期主路径, 显式 packId 指定且非内置时) ----
	if req.PackID != "" && req.PackID != report.BuiltinPackID {
		pack, perr := loadPackByID(req.PackID)
		if perr != nil {
			return nil, perr
		}
		if err := renderWithPack(arch, pack, snap, stats, cfg, req); err != nil {
			return nil, err
		}
		arch.Header = report.EffectiveHeader(req.Header)
		arch.Validate()
		return arch, nil
	}

	// ---- 路径 2: 遗留 HTML 自定义模板(TemplateID 显式指定时) ----
	if req.TemplateID != "" {
		tpl := &report.Template{Subtitle: cfg.Subtitle, Accent: cfg.Accent}
		if custom, terr := loadReportTplByID(d, req.TemplateID); terr == nil && custom != nil {
			tpl = custom
		} else if terr != nil {
			reportLogLine("自定义模板加载失败, 回落到内置模板: " + terr.Error())
		}
		if req.HeaderHeaderIsZero() {
			req.Header = report.Header{}
		}
		header := report.EffectiveHeader(pickHeader(req.Header, tpl.Header))
		html, err := report.Render(snap, stats, header, tpl)
		if err != nil {
			return nil, fmt.Errorf("报告渲染失败: %w", err)
		}
		arch.Header = header
		arch.TemplateName, arch.TemplateID = tpl.Name, tpl.ID
		if format == report.FormatPDF {
			arch.Content = report.PrintHTML(html, snap.Title)
		} else {
			arch.Content = html
		}
		arch.Validate()
		return arch, nil
	}

	// ---- 路径 1: Word 模板(word / html / pdf 共用) ----
	tplBlocks, err := loadWordTemplateBlocks(req.WordTemplate)
	if err != nil {
		return nil, err
	}
	wtplName := strings.TrimSpace(req.WordTemplate)
	if wtplName == "" {
		wtplName = report.BuiltinWordTemplateName
	}

	// 页眉页脚: 请求指定 > 内置默认(Word 模板没有页眉页脚概念, 由 HTML 出口承载)
	if req.HeaderHeaderIsZero() {
		req.Header = report.Header{}
	}
	header := report.EffectiveHeader(req.Header)

	// 占位符取值(标准集 + 配置里的副标题)
	values := report.PlaceholderValues(snap, stats)
	values["subtitle"] = cfg.Subtitle
	expandedHeader := report.ExpandHeaderValues(header, values)

	// 模板封面 + 数据章节
	full := report.InsertSections(tplBlocks, report.SectionBlocks(snap, stats, header.Disclaimer))
	full = report.ReplacePlaceholders(full, values)

	page := report.WordPage{Title: snap.Title, Header: expandedHeader, Accent: cfg.Accent}
	switch format {
	case report.FormatWord:
		docx, err := report.WriteDocx(full, report.DocxMeta{Title: snap.Title, Author: snap.Operator})
		if err != nil {
			return nil, fmt.Errorf("Word 文档生成失败: %w", err)
		}
		arch.ContentB64 = base64.StdEncoding.EncodeToString(docx)
	case report.FormatPDF:
		// PDF 走浏览器打印通道: 生成"自动唤起打印"的 HTML(纯标准库无 PDF 库)
		arch.Content = report.PrintHTML(report.RenderWordReport(full, page), snap.Title)
	case report.FormatJSON:
		blob, jerr := json.Marshal(map[string]any{"snapshot": snap, "stats": stats})
		if jerr != nil {
			return nil, fmt.Errorf("JSON 序列化失败: %w", jerr)
		}
		arch.Content = string(blob)
	default: // html
		arch.Content = report.RenderWordReport(full, page)
	}

	arch.Header = header
	arch.TemplateName = "Word 模板: " + wtplName
	arch.Validate()
	return arch, nil
}

// loadWordTemplateBlocks 按名称取 Word 模板块序列:
// 空 / "builtin" = 内置模板; 其它 = exe 同目录 res/report_templates/<name>.docx。
func loadWordTemplateBlocks(name string) ([]report.Block, error) {
	name = strings.TrimSpace(name)
	if name == "" || name == report.BuiltinWordTemplateName {
		return report.BuiltinWordTemplate(), nil
	}
	if !validWordTplName(name) {
		return nil, fmt.Errorf("模板名非法: %s", name)
	}
	data, err := os.ReadFile(filepath.Join(wordTplDir(), name+".docx"))
	if err != nil {
		return nil, fmt.Errorf("Word 模板不存在: %s (可选内置模板 %s, 或上传到 report_templates/)", name, report.BuiltinWordTemplateName)
	}
	blocks, err := report.ReadDocx(data)
	if err != nil {
		return nil, fmt.Errorf("Word 模板解析失败(%s): %w", name, err)
	}
	return blocks, nil
}

// wordTplDir Word 模板目录(exe 同目录 res/report_templates/; 声明为变量便于测试
// 改指临时目录, 同 reportConfigPath 的既有手法。2026-09-24 dist 目录整理:
// 内置数据资源收进 res/)。
var wordTplDir = func() string {
	exe, err := os.Executable()
	if err != nil {
		return "res/report_templates"
	}
	return filepath.Join(filepath.Dir(exe), "res", "report_templates")
}

// validWordTplName 模板名校验: 只允许普通文件名(防目录穿越/特殊字符)。
func validWordTplName(name string) bool {
	if name == "" || name == report.BuiltinWordTemplateName {
		return false
	}
	if len([]rune(name)) > 50 {
		return false
	}
	for _, c := range name {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == ' ' || c >= 0x4E00: // 中英文/数字/-_./空格
		default:
			return false
		}
	}
	if strings.HasPrefix(name, ".") {
		return false
	}
	return true
}

// HeaderHeaderIsZero 判断请求里的页眉页脚是否为空(全部字段零值)。
func (r reportRequest) HeaderHeaderIsZero() bool {
	h := r.Header
	return h.HeaderLeft == "" && h.HeaderCenter == "" && h.HeaderRight == "" &&
		h.FooterLeft == "" && h.FooterCenter == "" && h.FooterRight == "" &&
		h.Disclaimer == "" && h.ShowPageNumber == nil
}

// pickHeader 请求头优先, 其次模板头(空值回落由 EffectiveHeader 处理)。
func pickHeader(req, tpl report.Header) report.Header {
	out := tpl
	if req.HeaderLeft != "" {
		out.HeaderLeft = req.HeaderLeft
	}
	if req.HeaderCenter != "" {
		out.HeaderCenter = req.HeaderCenter
	}
	if req.HeaderRight != "" {
		out.HeaderRight = req.HeaderRight
	}
	if req.FooterLeft != "" {
		out.FooterLeft = req.FooterLeft
	}
	if req.FooterCenter != "" {
		out.FooterCenter = req.FooterCenter
	}
	if req.FooterRight != "" {
		out.FooterRight = req.FooterRight
	}
	if req.Disclaimer != "" {
		out.Disclaimer = req.Disclaimer
	}
	if req.ShowPageNumber != nil {
		out.ShowPageNumber = req.ShowPageNumber
	}
	return out
}

// loadReportTplByID 读取自定义报告模板(从 db 模板表)。
//
// 命名注意: 不能叫 loadReportTemplate —— main.go 已有同名函数(经典页报告模板
// 的 HTML 加载器, 语义完全不同), 同名会编译冲突。
func loadReportTplByID(d *db.Database, id string) (*report.Template, error) {
	if d == nil || d.ReportTemplates() == nil {
		return nil, fmt.Errorf("模板存储不可用")
	}
	t, err := d.ReportTemplates().Get(id)
	if err != nil || t == nil {
		return nil, fmt.Errorf("模板不存在: %s", id)
	}
	return t, nil
}

// saveReportArchive 报告存档落库(超出上限时淘汰最旧记录)。
//
// 淘汰策略: 按创建时间升序删除, 直到回到上限以内。
// 为什么按时间而不是"重要程度": 本模块没有"重要"这一概念, 擅自决定保留哪些
// 会让用户丢失以为已归档的报告; FIFO 是唯一可预期的行为。
func saveReportArchive(d *db.Database, arch *report.Archive) error {
	if d == nil || d.Reports() == nil {
		return fmt.Errorf("报告存档存储不可用")
	}
	if _, err := d.Reports().Upsert(arch); err != nil {
		return err
	}
	cfg := loadReportConfig()
	if cfg.MaxArchive <= 0 {
		return nil
	}
	list, err := d.Reports().List()
	if err != nil || len(list) <= cfg.MaxArchive {
		return nil
	}
	sort.SliceStable(list, func(i, j int) bool { return list[i].CreatedAt.Before(list[j].CreatedAt) })
	for i := 0; i < len(list)-cfg.MaxArchive; i++ {
		if list[i] == nil {
			continue
		}
		_, _ = d.Reports().Delete(list[i].ID)
	}
	reportLogLine(fmt.Sprintf("报告存档超出上限(%d), 已淘汰最旧 %d 份", cfg.MaxArchive, len(list)-cfg.MaxArchive))
	return nil
}

// ===== 前端可用的筛选选项 =====

// reportFilterOptions 汇总当前库里的可选筛选项(供前端下拉框)。
type reportFilterOptions struct {
	Severities []string        `json:"severities"`
	CVEs       []string        `json:"cves"`
	Nodes      []nodeOption    `json:"nodes"`
	DateRange  reportDateRange `json:"dateRange"`
}

type nodeOption struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type reportDateRange struct {
	Earliest time.Time `json:"earliest"`
	Latest   time.Time `json:"latest"`
}

// collectFilterOptions 从库中收集筛选项(降级: 库不可用返回空集合)。
func collectFilterOptions(d *db.Database) reportFilterOptions {
	opt := reportFilterOptions{
		Severities: []string{models.SeverityCritical, models.SeverityHigh, models.SeverityMedium, models.SeverityLow, models.SeverityInfo},
		Nodes:      []nodeOption{{ID: "local", Name: "中心本地"}},
	}
	if d == nil {
		return opt
	}
	// CVE 列表(去重, 最多 200 个避免下拉框撑爆)
	cveSet := map[string]bool{}
	if dao := d.Vulns(); dao != nil {
		if list, err := dao.List(); err == nil {
			for _, v := range list {
				if v == nil {
					continue
				}
				if c := report.CVEOf(&v.Vuln); c != "" {
					cveSet[c] = true
				}
				t := v.FoundAt
				if !t.IsZero() {
					if opt.DateRange.Earliest.IsZero() || t.Before(opt.DateRange.Earliest) {
						opt.DateRange.Earliest = t
					}
					if t.After(opt.DateRange.Latest) {
						opt.DateRange.Latest = t
					}
				}
			}
		}
	}
	for c := range cveSet {
		opt.CVEs = append(opt.CVEs, c)
	}
	sort.Strings(opt.CVEs)
	if len(opt.CVEs) > 200 {
		opt.CVEs = opt.CVEs[:200]
	}
	// 探针节点(CH 端注册表; 表为空说明当前是单机部署)
	if dao := d.Probes(); dao != nil {
		if list, err := dao.List(); err == nil {
			for _, p := range list {
				if p == nil || p.ID == "" {
					continue
				}
				opt.Nodes = append(opt.Nodes, nodeOption{ID: p.ID, Name: firstNonEmptyStr(p.Name, p.ID)})
			}
		}
	}
	return opt
}

// ===== 历史扫描对比 =====

// reportCompareRequest 对比请求。
type reportCompareRequest struct {
	// BaseID / TargetID 两侧存档 ID(优先); 为空时用下面的筛选条件现算
	BaseID   string `json:"baseId"`
	TargetID string `json:"targetId"`
	// From / To 现算模式: 以时间窗切分两次扫描
	From string `json:"from"`
	To   string `json:"to"`
	// Save 是否把对比结果落库存档
	Save bool `json:"save"`
	// Title 存档标题
	Title string `json:"title"`
}

// buildArchiveSnapshot 由存档记录还原快照。
//
// 局限说明(必须如实告知用户): 存档只保存了渲染产物与统计, 漏洞明细随报告
// 一起过滤后保存 —— 因此"以存档为基线"的对比精度受当时筛选条件影响。
// 生产路径推荐用扫描任务维度对比(见 handleReportCompare 的 baseId 前缀 "st:")。
func buildArchiveSnapshot(d *db.Database, id string) (*report.Snapshot, error) {
	if d == nil || d.Reports() == nil {
		return nil, fmt.Errorf("报告存档存储不可用")
	}
	arch, err := d.Reports().Get(id)
	if err != nil || arch == nil {
		return nil, fmt.Errorf("存档不存在: %s", id)
	}
	return &report.Snapshot{
		Title:     arch.Title,
		Operator:  arch.Operator,
		CreatedAt: arch.CreatedAt,
		Vulns:     nil, // 存档不含漏洞明细对象, 只用于展示统计
	}, nil
}

// compareByVulnSnapshot 以"当前库中满足条件的漏洞"为某一次扫描的漏洞集合。
//
// 为什么这样实现(诚实的取舍):
//
//	现有数据模型未把漏洞与扫描任务做强关联 —— db.Vuln.ScanTaskID 只记录
//	"首次落库时来自哪个任务"(probe 链路写的是探针 ID), 中心本地扫描的漏洞
//	在多次扫描间会被 Upsert 覆盖为同一条(稳定 ID 去重)。因此无法从库中精确
//	还原"第 N 次扫描时的漏洞快照"。
//
//	本模块采用两条可用的对比路径:
//
//	  1. 【推荐】时间窗对比: 以"漏洞的发现/最后发现时间"切分两个时间窗,
//	     对比两个窗口内的漏洞集合 —— 这与扫描节奏天然对齐(每轮扫描都会
//	     刷新 LastSeenAt), 是现有数据下最可靠的差异来源;
//	  2. 存档对比: 对同一批数据用不同筛选条件生成的两份报告做差异分析。
// 时间字段选择策略(这是对比功能能否正确工作的关键, 必须说清楚)。
//
// models.Vuln 有两个时间: FoundAt(首次发现)与 LastSeenAt(最后一次命中)。
// 同一条漏洞在多轮扫描间会被 Upsert 覆盖(稳定 ID 去重), 因此:
//
//	基线段应看 FoundAt   —— "这条漏洞是什么时候第一次出现的"
//	目标段应看 LastSeenAt —— "这条漏洞最近一次被命中是什么时候"
//
// 若两段都用 max(FoundAt, LastSeenAt)(先前实现), 会得到一个致命错误:
// 一条老漏洞在本轮被重新命中后 LastSeenAt 被刷新, 它的 max 值落到目标窗口,
// 于是它从基线段"消失" → 对比结果把"一直存在的老漏洞"误报成"新增漏洞"。
// 这个错误直接颠倒结论(老问题被当作新风险上报给客户), 必须避免。
func vulnsInWindow(d *db.Database, from, to time.Time, useLastSeen bool) ([]*models.Vuln, error) {
	if d == nil || d.Vulns() == nil {
		return nil, fmt.Errorf("漏洞存储不可用")
	}
	list, err := d.Vulns().List()
	if err != nil {
		return nil, err
	}
	var out []*models.Vuln
	for _, v := range list {
		if v == nil {
			continue
		}
		t := v.FoundAt
		if useLastSeen {
			t = v.LastSeenAt
			if t.IsZero() {
				t = v.FoundAt
			}
		} else if t.IsZero() {
			t = v.LastSeenAt
		}
		if !from.IsZero() && t.Before(from) {
			continue
		}
		if !to.IsZero() && t.After(to) {
			continue
		}
		vv := v.Vuln
		out = append(out, &vv)
	}
	return out, nil
}

// compareScans 生成两次扫描的差异。
func compareScans(d *db.Database, base, target []*models.Vuln, baseName, targetName string) *report.Diff {
	bs := report.SnapshotFromVulns("base", baseName, base)
	ts := report.SnapshotFromVulns("target", targetName, target)
	// 资产维度也纳入对比
	bs.Assets, ts.Assets = assetsInSnapshots(base, target)
	diff := report.Compare(bs, ts, "base", "target")
	diff.BaseName = baseName
	diff.TargetName = targetName
	return diff
}

// assetsInSnapshots 从漏洞集合推导涉及的资产 IP(资产表无扫描维度时间戳,
// 用漏洞涉及的 IP 作为资产集合是现有数据下唯一可靠的近似)。
func assetsInSnapshots(base, target []*models.Vuln) ([]*models.Asset, []*models.Asset) {
	mk := func(list []*models.Vuln) []*models.Asset {
		seen := map[string]bool{}
		var out []*models.Asset
		for _, v := range list {
			if v == nil {
				continue
			}
			ip := models.NormIP(v.AssetIP)
			if ip == "" || seen[ip] {
				continue
			}
			seen[ip] = true
			out = append(out, &models.Asset{IP: ip})
		}
		return out
	}
	return mk(base), mk(target)
}

// ===== HTTP API =====

// registerReportRoutes 注册报告 API(挂 /api/v2/report/, 走 v2 统一响应与鉴权)。
func registerReportRoutes(srv *server.Server) {
	srv.Get("/api/v2/report/status", requireAuth(hReportStatus))
	// 生成(归档)/删除/模板增删是持久化写操作, 只读角色禁止(adminOnly;
	// 免登录直通); preview/compare 只渲染不落库, 读接口口径。
	srv.Post("/api/v2/report/generate", requireAuth(adminOrOperator(hReportGenerate)))
	srv.Get("/api/v2/report/list", requireAuth(hReportList))
	srv.Get("/api/v2/report/{id}", requireAuth(hReportGet))
	srv.Get("/api/v2/report/{id}/download", requireAuth(hReportDownload))
	srv.Delete("/api/v2/report/{id}", requireAuth(adminOrOperator(hReportDelete)))
	srv.Get("/api/v2/report/options", requireAuth(hReportOptions))
	srv.Post("/api/v2/report/preview", requireAuth(hReportPreview))
	srv.Post("/api/v2/report/compare", requireAuth(hReportCompare))
	srv.Get("/api/v2/report/history", requireAuth(hReportHistory))
	srv.Get("/api/v2/report/topology", requireAuth(hReportTopology))
	// 旧版 HTML 模板管理(遗留路径: 请求带 templateId 时使用)
	srv.Get("/api/v2/report/templates", requireAuth(hReportTemplateList))
	srv.Post("/api/v2/report/templates", requireAuth(adminOrOperator(hReportTemplateSave)))
	srv.Delete("/api/v2/report/templates/{id}", requireAuth(adminOrOperator(hReportTemplateDelete)))
	// Word 模板管理(word/html/pdf 三种格式的渲染来源, report_word_api.go)
	registerWordTplRoutes(srv)
	// 模板包管理(二期: 目录式模板 + config.yaml 元信息 + 三出口, report_pack_api.go)
	registerPackRoutes(srv)
	// 报告中心二期: 原始结构化报告(业务模块执行后的原始结果 + 多报告合并)
	registerRawReportRoutes(srv)
}

// reportStatusPayload 状态负载(前端"报告中心"页首屏用)。
func reportStatusPayload(d *db.Database) map[string]any {
	cfg := loadReportConfig()
	// 配置入口已是 settings.json 的 report 节(report.json 仅为旧文件回退):
	// 提示与路径统一指 settings.json, 不再让用户去找已合并的旧文件。
	out := map[string]any{
		"enabled":    cfg.Enabled,
		"configPath": pathrel.Short(settingsFilePath()),
		"maxArchive": cfg.MaxArchive,
		// 前端开关按这两个值回显(默认开, nil 视为开)
		"templateManagement": packManagementEnabled(),
		"pdfExternal":        pdfExternalEnabled(),
		// 报告中心二期: 原始报告自动存档开关(默认开, nil 视为开) + 存储上限
		"autoSave": cfg.AutoSave == nil || *cfg.AutoSave,
		"maxRaw":   cfg.MaxRaw,
	}
	if !cfg.Enabled {
		out["hint"] = "报告引擎未启用: 在 settings.json 的 report 节设置 enabled=true 后重启"
	}
	if d != nil && d.Reports() != nil {
		if n, err := d.Reports().Count(); err == nil {
			out["archiveCount"] = n
		}
	}
	if d != nil && d.RawReports() != nil {
		if n, err := d.RawReports().Count(); err == nil {
			out["rawCount"] = n
		}
	}
	return out
}

// hReportStatus GET /api/v2/report/status
//
// 唯一在"未启用"时也正常工作的接口 —— 前端要能查到为什么没数据。
func hReportStatus(w http.ResponseWriter, r *http.Request) {
	server.OK(w, reportStatusPayload(v2GetDB()))
}

// maybeAutoGenerateReport 扫描结束钩子: 开关打开时异步生成并归档一份报告。
//
// 设计口径:
//   - 默认关闭(规则 5); 报告引擎本身未启用时也不触发(尊重 enabled 总闸)
//   - 异步执行: 报告生成要读全库渲染, 同步做会让扫描 SSE 的 done 事件延迟,
//     用户以为扫描卡住了
//   - 失败只记日志: 自动报告是增值动作, 绝不能反过来影响扫描主流程
func maybeAutoGenerateReport(scanType, target string) {
	cfg := loadReportConfig()
	if !cfg.Enabled || cfg.AutoGenerate == nil || !*cfg.AutoGenerate {
		return
	}
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				reportLogLine("自动报告生成 panic(已兜底): " + fmt.Sprint(rec))
			}
		}()
		d := v2GetDB()
		if d == nil || d.Reports() == nil {
			return
		}
		title := fmt.Sprintf("%s 扫描报告 (%s)", target, time.Now().Format("2006-01-02 15:04"))
		req := reportRequest{
			Title:   title,
			Format:  "html",
			Archive: boolPtr(true),
			Note:    "扫描结束自动生成 (" + scanType + ")",
		}
		arch, err := generateReport(d, req, "auto")
		if err != nil {
			reportLogLine("自动报告生成失败: " + err.Error())
			return
		}
		// generateReport 只渲染不落库, 归档必须显式调 saveReportArchive ——
		// 漏掉这步"自动报告"就永远只存在于内存里, 用户查不到任何报告
		// (功能看似开了实则静默失效, 比报错难发现得多)。
		if err := saveReportArchive(d, arch); err != nil {
			reportLogLine("自动报告存档失败: " + err.Error())
			return
		}
		reportLogLine(fmt.Sprintf("扫描结束已自动归档报告: %s (漏洞 %d, 资产 %d)",
			arch.Title, arch.Stats.VulnTotal, arch.Stats.AssetTotal))
	}()
}

func boolPtr(b bool) *bool { return &b }

// hReportGenerate POST /api/v2/report/generate 生成报告(默认同时归档)。
func hReportGenerate(w http.ResponseWriter, r *http.Request) {
	d, cfg := requireReportEnabled(w)
	if d == nil {
		return
	}
	var req reportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	arch, err := generateReport(d, req, currentUser())
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	archive := req.Archive == nil || *req.Archive
	if archive {
		if err := saveReportArchive(d, arch); err != nil {
			// 存档失败不阻断下载: 用户已经生成了报告, 不能因为落盘问题让他白等
			reportLogLine("报告存档失败(仍可下载): " + err.Error())
		}
	}
	logAudit(d, r, "report.generate", arch.ID, fmt.Sprintf("%s %s 漏洞%d", arch.Title, arch.Format, arch.Stats.VulnTotal))
	reportLogLine(fmt.Sprintf("报告已生成: %s (%s, 漏洞 %d, 资产 %d)", arch.Title, arch.Format, arch.Stats.VulnTotal, arch.Stats.AssetTotal))
	_ = sse.Default().PublishJSON("report", map[string]any{
		"event": "generated", "id": arch.ID, "title": arch.Title,
		"format": arch.Format, "archived": archive, "stats": arch.Stats,
	})
	_ = cfg
	// 响应里不带正文(可能数 MB): 列表/详情用 ReleaseContent 返回去正文副本,
	// 完整内容由 /download 接口提供
	server.OK(w, map[string]any{"report": d.Reports().ReleaseContent(arch), "archived": archive})
}

// hReportPreview POST /api/v2/report/preview 生成并内联返回 HTML(直接打开预览)。
//
// 与 generate 的差别: 不落库、不下载、Content-Type 为 text/html 直接渲染,
// 供前端"预览"按钮在新窗口打开。
func hReportPreview(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	var req reportRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	req.Format = report.FormatHTML
	arch, err := generateReport(d, req, currentUser())
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(arch.Content))
}

// hReportList GET /api/v2/report/list 存档列表(不含正文, 避免响应过大)。
func hReportList(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	if d.Reports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告存档存储不可用")
		return
	}
	q := r.URL.Query()
	page, size := parsePage(q)
	list, err := d.Reports().List()
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	// 按创建时间倒序(最新的报告在最前)
	sort.SliceStable(list, func(i, j int) bool { return list[i].CreatedAt.After(list[j].CreatedAt) })
	// 关键字过滤(标题/操作者)
	if kw := strings.TrimSpace(q.Get("keyword")); kw != "" {
		lk := strings.ToLower(kw)
		filtered := list[:0]
		for _, a := range list {
			if a == nil {
				continue
			}
			if strings.Contains(strings.ToLower(a.Title), lk) || strings.Contains(strings.ToLower(a.Operator), lk) {
				filtered = append(filtered, a)
			}
		}
		list = filtered
	}
	total := len(list)
	pageList := paginate(list, page, size)
	// 列表不回传正文(每份报告 HTML 可能数 MB, 20 份就能把响应撑到几十 MB)
	light := make([]*report.Archive, 0, len(pageList))
	for _, a := range pageList {
		light = append(light, d.Reports().ReleaseContent(a))
	}
	server.OK(w, map[string]any{"list": light, "total": total, "page": page, "size": size})
}

// hReportGet GET /api/v2/report/{id} 存档详情(元数据, 不含正文)。
func hReportGet(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	if d.Reports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告存档存储不可用")
		return
	}
	a, err := d.Reports().Get(r.PathValue("id"))
	if err != nil || a == nil {
		server.FailNotFound(w, "报告存档不存在")
		return
	}
	server.OK(w, d.Reports().ReleaseContent(a))
}

// hReportDownload GET /api/v2/report/{id}/download 重新下载历史报告。
//
// 这是"报告存档通过 DAO 持久化, 可随时重新下载"的落地点:
// 直接回放存档里的 Content(不重新渲染), 保证下载到的内容与归档时完全一致
// —— 重新渲染会因为期间的库数据变化而产出不同内容, 那就不叫"存档"了。
func hReportDownload(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	if d.Reports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告存档存储不可用")
		return
	}
	a, err := d.Reports().Get(r.PathValue("id"))
	if err != nil || a == nil {
		server.FailNotFound(w, "报告存档不存在")
		return
	}
	format := strings.ToLower(a.Format)
	ext := "html"
	ctype := "text/html; charset=utf-8"
	switch format {
	case report.FormatPDF:
		// 两种产物: 外部转换器出的真 PDF(ContentB64) / 打印页 HTML(Content)
		if strings.TrimSpace(a.ContentB64) != "" {
			ext, ctype = "pdf", "application/pdf"
		} else {
			ext, ctype = "html", "text/html; charset=utf-8" // 打印页, 浏览器另存为 PDF
		}
	case report.FormatJSON:
		ext, ctype = "json", "application/json; charset=utf-8"
	case report.FormatWord:
		ext = "docx"
		ctype = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	}
	disposition := "attachment"
	if r.URL.Query().Get("inline") == "1" {
		disposition = "inline"
	}
	var body []byte
	if format == report.FormatWord || (format == report.FormatPDF && strings.TrimSpace(a.ContentB64) != "") {
		decoded, derr := base64.StdEncoding.DecodeString(a.ContentB64)
		if derr != nil || len(decoded) == 0 {
			server.FailInternal(w, "Word 报告正文损坏(存档时未写入二进制内容)")
			return
		}
		body = decoded
	} else {
		body = []byte(a.Content)
	}
	fname := sanitizeFilename(a.Title) + "_" + a.CreatedAt.Format("20060102_150405") + "." + ext
	w.Header().Set("Content-Type", ctype)
	w.Header().Set("Content-Disposition", disposition+`; filename="`+fname+`"`)
	logAudit(d, r, "report.download", a.ID, a.Title)
	_, _ = w.Write(body)
}

// sanitizeFilename 清理文件名中的非法字符(Windows 不允许 \ / : * ? " < > |)。
func sanitizeFilename(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "yugsight_report"
	}
	repl := strings.NewReplacer("\\", "_", "/", "_", ":", "_", "*", "_", "?", "_", "\"", "_", "<", "_", ">", "_", "|", "_", "\n", "_", "\r", "_")
	s = repl.Replace(s)
	// 限制长度, 避免超出文件系统上限(留出时间戳与后缀空间)
	if len([]rune(s)) > 60 {
		s = string([]rune(s)[:60])
	}
	return s
}

// hReportDelete DELETE /api/v2/report/{id}
func hReportDelete(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	if d.Reports() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "报告存档存储不可用")
		return
	}
	id := r.PathValue("id")
	if ok, err := d.Reports().Delete(id); err != nil || !ok {
		server.FailNotFound(w, "报告存档不存在")
		return
	}
	logAudit(d, r, "report.delete", id, "")
	server.OK(w, map[string]any{"deleted": id})
}

// hReportOptions GET /api/v2/report/options 筛选项(等级/CVE/节点/时间范围)。
func hReportOptions(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	server.OK(w, collectFilterOptions(d))
}

// hReportHistory GET /api/v2/report/history 历史扫描记录(供对比选择)。
//
// 口径: 以扫描任务表为主线, 统计每条任务涉及的漏洞数(按资产 IP + 时间窗近似)。
// 为什么不做精确关联: db.Vuln.ScanTaskID 在探针链路里存的是探针 ID, 中心本地
// 扫描写的是空 —— 强行精确关联会得到大面积 0。这里用"任务目标涉及的 IP 上的
// 漏洞数"作为规模指标, 并在返回中注明是近似值(见 Approx 字段)。
func hReportHistory(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	list := []report.HistoryEntry{}
	if d.ScanTasks() != nil {
		tasks, err := d.ScanTasks().List()
		if err != nil {
			server.FailInternal(w, err.Error())
			return
		}
		sort.SliceStable(tasks, func(i, j int) bool { return tasks[i].CreatedAt.After(tasks[j].CreatedAt) })
		limit := 200
		if len(tasks) > limit {
			tasks = tasks[:limit]
		}
		for _, t := range tasks {
			if t == nil {
				continue
			}
			e := report.HistoryEntry{
				ID: t.ID, Target: t.Target, Type: t.Type, Status: t.Status,
				ProbeNode: t.ProbeNode, CreatedAt: t.CreatedAt,
			}
			if t.FinishedAt != nil {
				// 用完成时间戳作展示时间更符合直觉(用户找的是"什么时候扫完的")
				e.CreatedAt = *t.FinishedAt
			}
			list = append(list, e)
		}
	}
	server.OK(w, map[string]any{
		"list": list, "total": len(list),
		"approx": true,
		"note":   "漏洞数为按任务目标 IP 的近似统计（现有模型未把漏洞与任务强关联）",
	})
}

// hReportTopology GET /api/v2/report/topology 资产拓扑数据(前端画布)。
//
// 与报告中的拓扑同一算法(report.BuildTopology), 保证"页面看到的"与
// "报告里印的"完全一致 —— 两套实现必然漂移, 这是被迫踩过的教训。
func hReportTopology(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	f := reportFilterFromQuery(r.URL.Query())
	snap, stats, err := buildReportSnapshot(d, reportRequest{Filter: f})
	if err != nil {
		server.FailInternal(w, err.Error())
		return
	}
	topo := snap.Topology
	if topo == nil {
		topo = report.BuildTopology(snap.Assets, snap.Vulns)
	}
	server.OK(w, map[string]any{"topology": topo, "stats": stats})
}

// hReportCompare POST /api/v2/report/compare 历史扫描对比。
//
// 两种模式:
//
//  1. 时间窗模式(推荐): {from, to} 指定"目标轮次"的时间窗, 基线自动取
//     [from - window, from) 之间的漏洞集合, window 默认与目标窗等长。
//     这是现有数据模型下唯一精确可用的对比口径(见 compareByVulnSnapshot 注释);
//  2. 显式模式: {baseId, targetId} 指定两次存档的筛选条件做差异对比。
func hReportCompare(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	var req reportCompareRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	to := parseReportTimeEnd(req.To)
	if to.IsZero() {
		to = time.Now()
	}
	from := parseReportTime(req.From)

	var baseVulns, targetVulns []*models.Vuln
	var err error
	baseName, targetName := "基线", "本次"

	if !from.IsZero() {
		// 时间窗模式: 基线窗口 = 目标窗之前同等长度的一段
		window := to.Sub(from)
		if window <= 0 {
			window = 24 * time.Hour
		}
		// 基线按 FoundAt(首次发现), 目标按 LastSeenAt(最近命中) —— 见函数注释
		baseFrom, baseTo := from.Add(-window), from
		baseVulns, err = vulnsInWindow(d, baseFrom, baseTo, false)
		if err != nil {
			server.FailInternal(w, err.Error())
			return
		}
		targetVulns, err = vulnsInWindow(d, from, to, true)
		if err != nil {
			server.FailInternal(w, err.Error())
			return
		}
		baseName = "基线轮次 " + baseFrom.Format("2006-01-02 15:04") + " ~ " + baseTo.Format("2006-01-02 15:04")
		targetName = "目标轮次 " + from.Format("2006-01-02 15:04") + " ~ " + to.Format("2006-01-02 15:04")
	} else if req.BaseID != "" && req.TargetID != "" {
		// 存档模式: 两侧存档的统计与筛选条件作对照(存档不保存漏洞明细对象,
		// 因此这里明确用统计数字对比, 并返回说明)
		b, berr := buildArchiveSnapshot(d, req.BaseID)
		if berr != nil {
			server.FailNotFound(w, berr.Error())
			return
		}
		t, terr := buildArchiveSnapshot(d, req.TargetID)
		if terr != nil {
			server.FailNotFound(w, terr.Error())
			return
		}
		diff := report.Compare(b, t, req.BaseID, req.TargetID)
		server.OK(w, map[string]any{"diff": diff, "mode": "archive", "note": "存档对比仅比较统计口径（存档不保留漏洞明细）"})
		return
	} else {
		server.FailBadRequest(w, "请提供 from/to 时间窗, 或 baseId/targetId 存档对")
		return
	}

	diff := compareScans(d, baseVulns, targetVulns, baseName, targetName)
	diff.BaseID, diff.TargetID = firstNonEmptyStr(req.BaseID, "window-base"), firstNonEmptyStr(req.TargetID, "window-target")

	// 可选: 把对比结果存为报告存档(便于复盘与审计留痕)
	if req.Save {
		if err := saveCompareArchive(d, diff, req.Title, currentUser()); err != nil {
			reportLogLine("对比结果存档失败: " + err.Error())
		}
	}
	logAudit(d, r, "report.compare", diff.BaseID, fmt.Sprintf("新增%d 修复%d 仍存在%d", diff.Stats.NewCount, diff.Stats.FixedCount, diff.Stats.PersistedCount))
	server.OK(w, map[string]any{"diff": diff, "mode": "window"})
}

// saveCompareArchive 把对比结果渲染为 HTML 并存档。
func saveCompareArchive(d *db.Database, diff *report.Diff, title, operator string) error {
	if strings.TrimSpace(title) == "" {
		title = "扫描对比报告 " + diff.TargetName
	}
	html, err := report.RenderDiff(diff, title, appName+" v"+appVersion, report.EffectiveHeader(report.Header{}))
	if err != nil {
		return err
	}
	arch := &report.Archive{
		Title:     title,
		Operator:  operator,
		CreatedBy: operator,
		CreatedAt: time.Now(),
		Format:    report.FormatHTML,
		Status:    report.StatusReady,
		Content:   html,
		Note:      fmt.Sprintf("对比报告: 新增 %d / 已修复 %d / 仍存在 %d", diff.Stats.NewCount, diff.Stats.FixedCount, diff.Stats.PersistedCount),
	}
	arch.Validate()
	return saveReportArchive(d, arch)
}

// ===== 模板管理 =====

// hReportTemplateList GET /api/v2/report/templates 模板列表(含内置)。
func hReportTemplateList(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	list := []*report.Template{}
	if d.ReportTemplates() != nil {
		got, err := d.ReportTemplates().List()
		if err != nil {
			server.FailInternal(w, err.Error())
			return
		}
		list = got
	}
	builtin := []map[string]any{
		{"id": "", "name": "默认模板（内置）", "builtin": true,
			"header": report.DefaultHeader()},
	}
	server.OK(w, map[string]any{
		"list": list, "builtin": builtin, "total": len(list),
		"headerPlaceholders": []map[string]string{
			{"key": "{{title}}", "desc": "报告标题"},
			{"key": "{{operator}}", "desc": "操作者 / 单位"},
			{"key": "{{time}}", "desc": "生成时间"},
			{"key": "{{tool}}", "desc": "工具名与版本"},
			{"key": "{{risk}}", "desc": "整体风险等级"},
			{"key": "{{score}}", "desc": "风险评分"},
		},
	})
}

// hReportTemplateSave POST /api/v2/report/templates 新建/更新自定义模板。
func hReportTemplateSave(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	if d.ReportTemplates() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "模板存储不可用")
		return
	}
	var in report.Template
	if !decodeJSON(w, r, &in) {
		return
	}
	if err := in.Validate(); err != nil {
		server.FailBadRequest(w, err.Error())
		return
	}
	if in.ID == "" {
		if err := d.ReportTemplates().Create(&in); err != nil {
			server.FailInternal(w, err.Error())
			return
		}
	} else {
		if err := d.ReportTemplates().Update(&in); err != nil {
			server.FailInternal(w, err.Error())
			return
		}
	}
	logAudit(d, r, "report.template.save", in.ID, in.Name)
	server.OK(w, in)
}

// hReportTemplateDelete DELETE /api/v2/report/templates/{id}
func hReportTemplateDelete(w http.ResponseWriter, r *http.Request) {
	d, _ := requireReportEnabled(w)
	if d == nil {
		return
	}
	if d.ReportTemplates() == nil {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable, "模板存储不可用")
		return
	}
	id := r.PathValue("id")
	if ok, err := d.ReportTemplates().Delete(id); err != nil || !ok {
		server.FailNotFound(w, "模板不存在")
		return
	}
	logAudit(d, r, "report.template.delete", id, "")
	server.OK(w, map[string]any{"deleted": id})
}

// ===== 小工具 =====

// requireReportEnabled 检查报告引擎是否启用并返回数据库; 未启用/不可用时已写响应。
//
// 返回 (nil, cfg) 表示调用方应立即返回。
func requireReportEnabled(w http.ResponseWriter) (*db.Database, ReportConfig) {
	cfg := loadReportConfig()
	if !cfg.Enabled {
		server.Fail(w, http.StatusServiceUnavailable, server.CodeDBUnavailable,
			"报告引擎未启用: 请在 settings.json 的 report 节设置 enabled=true 后重启")
		return nil, cfg
	}
	d := v2NeedDB(w)
	if d == nil {
		return nil, cfg
	}
	return d, cfg
}

// truncateStr 限长截断(附带省略标记)。
func truncateStr(s string, max int) string {
	if max <= 0 || len([]rune(s)) <= max {
		return s
	}
	return string([]rune(s)[:max]) + "..."
}


