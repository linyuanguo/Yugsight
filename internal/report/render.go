package report

import (
	"bytes"
	"html/template"
	"strings"
	"time"

	"yugsight/internal/models"
)

// DefaultTool 报告中的工具署名(装配层会覆盖为 "Yugsight v1.0.0")。
const DefaultTool = "Yugsight"

// Render 渲染报告 HTML(自包含单文件: 内联样式 + 内联 SVG 图表, 无外部资源)。
//
// 为什么必须自包含:
//
//	报告要能离线交付(邮件附件/U盘拷贝/内网无外网环境打开)。任何外链
//	(CDN 图表库/字体/图片)都会在离线环境里变成空白块, 直接毁掉报告观感。
//	因此图表全部用内联 SVG + CSS 条形绘制, 不引入任何 JS 图表库。
func Render(s *Snapshot, st SnapshotStats, h Header, tpl *Template) (string, error) {
	data := buildViewData(s, st, h, tpl)
	var buf bytes.Buffer
	if err := reportTemplate.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// viewData 模板数据(全部字段首字母大写, 模板内直接 .Field 访问)。
type viewData struct {
	Title      string
	Operator   string
	Tool       string
	Time       string
	TimeISO    string
	RiskLevel  string
	RiskScore  int
	Accent     string
	LogoText   string
	Subtitle   string
	Disclaimer string

	Header Header
	Stats  SnapshotStats

	Scans    []ScanInfo
	Assets   []*models.Asset
	Vulns    []*vulnView
	Penta    []pentaView // 阶段 5: 渗透验证结果章节(空 = 不渲染)
	Topology *Topology
	Summary  template.HTML

	// TopoAssets 拓扑资产节点及其端口子节点(模板语言无法按父子关系聚合,
	// 因此在 Go 侧预先铺平成"资产 + 端口列表"两级结构供模板直接 range)。
	TopoAssets []topoAssetView

	ShowTopology bool
	ShowEvidence bool
	ShowRaw      bool
	ShowPcap     bool
	HasPcap      bool

	// 图表数据
	SevBars   []barView
	SourceBars []barView
	ProbeBars []barView

	// 章节编号(模板里手写数字会在章节开关后错位, 故统一在这里算)
	SecTopology int
	SecAssets   int
	SecVulns    int
	SecPenta    int // 阶段 5: 渗透验证章节(无数据时为 0, 模板不渲染)
	SecEvidence int
	SecAdvice   int
}

// topoAssetView 拓扑视图中的资产节点(含其端口子节点)。
type topoAssetView struct {
	IP        string
	Hostname  string
	OS        string
	Risk      string
	RiskName  string
	Online    bool
	Unknown   bool
	VulnCount int
	ProbeNode string
	Ports     []TopoNode
}

// vulnView 模板中单条漏洞的视图(预计算 CVE 与修复建议, 模板不支持函数调用链)。
type vulnView struct {
	Index      int
	Severity   string
	SevName    string
	Title      string
	CVE        string
	CVELink    string
	AssetIP    string
	Port       int
	Protocol   string
	Confidence int
	// ConfidenceNote 置信度含义(报告要能让非技术读者看懂"100 分"意味着什么)
	ConfidenceNote string
	Source         string
	Status         string
	StatusName     string
	FoundAt        string
	Description    string
	Evidence       string
	Requests       []rawPair
	Fix            string
	PcapFile       string
	FP             bool
	FPNote         string
	// PentaExploit 渗透验证结论(阶段 5: 空 = 未验证)
	PentaExploit string
}

// rawPair 一组原始请求/响应(多来源证据合并后可能有多组)。
type rawPair struct {
	Source   string
	Request  string
	Response string
	FoundAt  string
}

// pentaView 模板中单条渗透验证记录的视图。
type pentaView struct {
	Target         string
	Title          string
	CVE            string
	Exploitability string // 结论文案(可利用/部分利用/不可利用)
	RiskLevel      string
	Summary        string
	Operator       string
	VerifiedAt     string
}

// barView 条形图一行。
type barView struct {
	Label string
	Name  string
	Count int
	Pct   int
	Class string
}

// buildViewData 组装模板数据。
func buildViewData(s *Snapshot, st SnapshotStats, h Header, tpl *Template) *viewData {
	now := time.Now()
	if s != nil && !s.CreatedAt.IsZero() {
		now = s.CreatedAt
	}
	d := &viewData{
		Tool:       DefaultTool,
		Time:       now.Format("2006-01-02 15:04:05"),
		TimeISO:    now.Format(time.RFC3339),
		RiskLevel:  st.RiskLevel,
		RiskScore:  st.RiskScore,
		Accent:     "#4f46e5",
		LogoText:   "YUGSIGHT · 网络扫描探测工具",
		Subtitle:   "网络安全扫描与漏洞评估报告",
		Stats:      st,
		Header:     h,
		ShowTopology: true,
		ShowEvidence: true,
		ShowRaw:      false,
	}
	if s != nil {
		d.Title = s.Title
		d.Operator = s.Operator
		d.Scans = s.Scans
		d.Assets = s.Assets
		d.Topology = s.Topology
		if strings.TrimSpace(s.Tool) != "" {
			d.Tool = s.Tool
		}
	}
	if tpl != nil {
		if strings.TrimSpace(tpl.Accent) != "" {
			d.Accent = tpl.Accent
		}
		if strings.TrimSpace(tpl.LogoText) != "" {
			d.LogoText = tpl.LogoText
		}
		if strings.TrimSpace(tpl.Subtitle) != "" {
			d.Subtitle = tpl.Subtitle
		}
		if tpl.ShowTopology != nil {
			d.ShowTopology = *tpl.ShowTopology
		}
		if tpl.ShowEvidence != nil {
			d.ShowEvidence = *tpl.ShowEvidence
		}
		if tpl.ShowRaw != nil {
			d.ShowRaw = *tpl.ShowRaw
		}
		h = mergeHeader(h, tpl.Header)
		d.Header = h
	}
	d.Title = firstNonEmptyStr(d.Title, "Yugsight 安全扫描报告")

	// 拓扑为 nil 时按资产+漏洞兜底构建(装配层通常已构建)
	if d.Topology == nil && s != nil {
		d.Topology = BuildTopology(s.Assets, s.Vulns)
	}
	d.TopoAssets = buildTopoViews(d.Topology)

	// ---- 漏洞视图 ----
	if s != nil {
		for i, v := range s.Vulns {
			if v == nil {
				continue
			}
			d.Vulns = append(d.Vulns, makeVulnView(i+1, v, d.ShowRaw))
			if strings.TrimSpace(v.PcapFile) != "" {
				d.HasPcap = true
			}
		}
	}

	// ---- 图表 ----
	d.SevBars = severityBars(st)
	d.SourceBars = mapBars(st.BySource, "lg-blue")
	d.ProbeBars = mapBars(st.ByProbe, "lg-purple")

	// ---- 渗透验证(阶段 5: 整合报告"扫描+渗透验证") ----
	if s != nil {
		for _, p := range s.Penta {
			d.Penta = append(d.Penta, pentaView{
				Target:         p.Target,
				Title:          firstNonEmptyStr(p.Title, "渗透验证"),
				CVE:            p.CVE,
				Exploitability: pentaExploitName(p.Exploitability),
				RiskLevel:      sevName(p.RiskLevel),
				Summary:        p.Summary,
				Operator:       firstNonEmptyStr(p.Operator, "-"),
				VerifiedAt:     p.VerifiedAt.Format("2006-01-02 15:04:05"),
			})
		}
	}

	// ---- 章节编号(按开关动态计算, 避免"五、总体建议"前面只剩三章) ----
	n := 0
	if d.ShowTopology {
		n++
		d.SecTopology = n
	}
	n++
	d.SecAssets = n
	n++
	d.SecVulns = n
	if len(d.Penta) > 0 {
		n++
		d.SecPenta = n
	}
	if d.ShowEvidence {
		n++
		d.SecEvidence = n
	}
	n++
	d.SecAdvice = n

	// ---- 页眉页脚占位符展开 ----
	d.Header = expandHeader(d.Header, d)

	// ---- 总体结论 ----
	if s != nil && strings.TrimSpace(s.Summary) != "" {
		d.Summary = template.HTML(s.Summary) // 摘要由本包或装配层生成, 视为可信 HTML
	} else {
		d.Summary = template.HTML(SummaryText(st, d.Tool, d.Time))
	}
	return d
}

// makeVulnView 单条漏洞视图。
func makeVulnView(idx int, v *models.Vuln, withRaw bool) *vulnView {
	cve := CVEOf(v)
	vv := &vulnView{
		Index:          idx,
		Severity:       models.NormalizeSeverity(v.Severity),
		SevName:        sevName(v.Severity),
		Title:          v.Title,
		CVE:            cve,
		CVELink:        cveLink(cve),
		AssetIP:        models.NormIP(v.AssetIP),
		Port:           v.Port,
		Protocol:       v.Protocol,
		Confidence:     v.Confidence,
		ConfidenceNote: confidenceNote(v.Confidence),
		Source:         v.Source,
		Status:         v.Status,
		StatusName:     statusName(v.Status),
		Description:    v.Description,
		Evidence:       v.Evidence,
		Fix:            FixOf(v),
		PcapFile:       pcapHint(v),
		FP:             v.FalsePositive,
		FPNote:         v.FPNote,
	}
	if v.PentaResult != "" {
		vv.PentaExploit = pentaExploitName(v.PentaResult)
	}
	if !v.FoundAt.IsZero() {
		vv.FoundAt = v.FoundAt.Format("2006-01-02 15:04:05")
	}
	// 证据: 主证据 + 多来源记录(全部保留, 不截断丢弃)
	if r := strings.TrimSpace(v.Request); r != "" || strings.TrimSpace(v.Response) != "" {
		vv.Requests = append(vv.Requests, rawPair{Source: v.Source, Request: v.Request, Response: v.Response})
	}
	if withRaw {
		for _, er := range v.EvidenceRecords {
			if strings.TrimSpace(er.Request) == "" && strings.TrimSpace(er.Response) == "" {
				continue
			}
			p := rawPair{Source: er.Source, Request: er.Request, Response: er.Response}
			if !er.FoundAt.IsZero() {
				p.FoundAt = er.FoundAt.Format("2006-01-02 15:04:05")
			}
			vv.Requests = append(vv.Requests, p)
		}
	}
	return vv
}

// buildTopoViews 把扁平拓扑铺平成"资产 -> 端口"两级视图。
//
// 为什么要铺平: html/template 无法按条件筛选并聚合子节点(没有自定义函数时
// 只能 range 整表), 在模板里做两次嵌套 range 会输出全部节点的笛卡尔积。
func buildTopoViews(t *Topology) []topoAssetView {
	if t == nil {
		return nil
	}
	byIP := map[string]*topoAssetView{}
	var order []string
	for _, n := range t.Nodes {
		if n.Kind != KindAsset {
			continue
		}
		if _, ok := byIP[n.IP]; !ok {
			byIP[n.IP] = &topoAssetView{
				IP: n.IP, Hostname: n.Hostname, OS: n.OS,
				Risk: n.Risk, RiskName: riskName(n.Risk),
				Online: n.Online, Unknown: n.Unknown,
				VulnCount: n.VulnCount, ProbeNode: n.ProbeNode,
			}
			order = append(order, n.IP)
		}
	}
	for _, n := range t.Nodes {
		if n.Kind != KindPort {
			continue
		}
		if a, ok := byIP[n.IP]; ok {
			a.Ports = append(a.Ports, n)
		}
	}
	out := make([]topoAssetView, 0, len(order))
	for _, ip := range order {
		out = append(out, *byIP[ip])
	}
	return out
}

// riskName 风险等级中文名(none 单独给"无风险")。
func riskName(risk string) string {
	if risk == "" || risk == RiskNone {
		return "无风险"
	}
	return sevName(risk)
}

// confidenceNote 置信度含义说明。
//
// 依据 scanctl/scoring.go 的打分口径: 100 = POC 主动验证成功(唯一满分);
// 70-99 = 精确版本匹配; 40-69 = 版本范围匹配; <40 = 仅关键字命中(可疑)。
func confidenceNote(c int) string {
	switch {
	case c >= 100:
		return "POC 主动验证成功，可直接处置"
	case c >= 70:
		return "版本精确匹配，建议核实后处置"
	case c >= 40:
		return "版本范围匹配，需人工确认"
	case c > 0:
		return "仅关键字命中，存在误报可能，请人工核实"
	default:
		return "未评分"
	}
}

// severityBars 等级分布条形图(固定顺序: 严重 -> 信息, 避免地图顺序抖动)。
func severityBars(st SnapshotStats) []barView {
	rows := []struct {
		key, name, class string
		n                int
	}{
		{models.SeverityCritical, "严重", "lg-critical", st.Critical},
		{models.SeverityHigh, "高危", "lg-red", st.High},
		{models.SeverityMedium, "中危", "lg-orange", st.Medium},
		{models.SeverityLow, "低危", "lg-yellow", st.Low},
		{models.SeverityInfo, "信息", "lg-blue", st.Info},
	}
	max := 1
	for _, r := range rows {
		if r.n > max {
			max = r.n
		}
	}
	out := make([]barView, 0, len(rows))
	for _, r := range rows {
		out = append(out, barView{Label: r.key, Name: r.name, Count: r.n, Pct: r.n * 100 / max, Class: r.class})
	}
	return out
}

// mapBars map 分布条形图(按数量降序, 最多 12 项避免图太长)。
func mapBars(m map[string]int, class string) []barView {
	if len(m) == 0 {
		return nil
	}
	type kv struct {
		k string
		n int
	}
	list := make([]kv, 0, len(m))
	max := 1
	for k, n := range m {
		list = append(list, kv{k, n})
		if n > max {
			max = n
		}
	}
	for i := 0; i < len(list); i++ {
		for j := i + 1; j < len(list); j++ {
			if list[j].n > list[i].n || (list[j].n == list[i].n && list[j].k < list[i].k) {
				list[i], list[j] = list[j], list[i]
			}
		}
	}
	if len(list) > 12 {
		list = list[:12]
	}
	out := make([]barView, 0, len(list))
	for _, it := range list {
		out = append(out, barView{Label: it.k, Name: it.k, Count: it.n, Pct: it.n * 100 / max, Class: class})
	}
	return out
}

// sevName 等级中文名。
func sevName(sev string) string {
	switch models.NormalizeSeverity(sev) {
	case models.SeverityCritical:
		return "严重"
	case models.SeverityHigh:
		return "高危"
	case models.SeverityMedium:
		return "中危"
	case models.SeverityLow:
		return "低危"
	default:
		return "信息"
	}
}

// pentaExploitName 渗透验证结论中文名(与 penta 包口径一致; report 不依赖 penta,
// 取值域封闭在三个常量, 本地实现无漂移风险)。
func pentaExploitName(s string) string {
	switch s {
	case "exploitable":
		return "可利用"
	case "partial":
		return "部分利用"
	case "not_exploitable":
		return "不可利用"
	}
	return "未验证"
}

// statusName 漏洞状态中文名。
func statusName(s string) string {
	switch s {
	case models.VulnStatusNew:
		return "新发现"
	case models.VulnStatusDuplicate:
		return "重复出现"
	case models.VulnStatusFixed:
		return "已修复"
	}
	if s == "" {
		return "新发现"
	}
	return s
}

// mergeHeader 模板页眉页脚与调用方传入的头部合并(调用方字段优先, 非空覆盖模板)。
func mergeHeader(a, b Header) Header {
	out := b
	if a.HeaderLeft != "" {
		out.HeaderLeft = a.HeaderLeft
	}
	if a.HeaderCenter != "" {
		out.HeaderCenter = a.HeaderCenter
	}
	if a.HeaderRight != "" {
		out.HeaderRight = a.HeaderRight
	}
	if a.FooterLeft != "" {
		out.FooterLeft = a.FooterLeft
	}
	if a.FooterCenter != "" {
		out.FooterCenter = a.FooterCenter
	}
	if a.FooterRight != "" {
		out.FooterRight = a.FooterRight
	}
	if a.Disclaimer != "" {
		out.Disclaimer = a.Disclaimer
	}
	if a.ShowPageNumber != nil {
		out.ShowPageNumber = a.ShowPageNumber
	}
	return out
}

// expandHeader 展开页眉页脚中的 {{占位符}}。
func expandHeader(h Header, d *viewData) Header {
	rep := func(s string) string {
		r := strings.NewReplacer(
			"{{title}}", d.Title,
			"{{operator}}", firstNonEmptyStr(d.Operator, "-"),
			"{{time}}", d.Time,
			"{{tool}}", d.Tool,
			"{{risk}}", d.RiskLevel,
			"{{score}}", itoa(d.RiskScore),
		)
		return r.Replace(s)
	}
	h.HeaderLeft = rep(h.HeaderLeft)
	h.HeaderCenter = rep(h.HeaderCenter)
	h.HeaderRight = rep(h.HeaderRight)
	h.FooterLeft = rep(h.FooterLeft)
	h.FooterCenter = rep(h.FooterCenter)
	h.FooterRight = rep(h.FooterRight)
	h.Disclaimer = rep(h.Disclaimer)
	return h
}

// DefaultHeader 内置默认页眉页脚。
func DefaultHeader() Header {
	showPage := true
	return Header{
		HeaderLeft:     "{{title}}",
		HeaderRight:    "{{tool}}",
		FooterLeft:     "操作者: {{operator}}",
		FooterCenter:   "生成时间: {{time}}",
		ShowPageNumber: &showPage,
		Disclaimer:     "免责声明：本工具仅可用于扫描自己拥有或已获书面授权的目标系统，未经授权对他人系统扫描可能违反《中华人民共和国网络安全法》及相关法律法规。",
	}
}

// EffectiveHeader 返回生效的页眉页脚(零值 Header 回落到默认)。
func EffectiveHeader(h Header) Header {
	def := DefaultHeader()
	out := h
	if out.HeaderLeft == "" {
		out.HeaderLeft = def.HeaderLeft
	}
	if out.HeaderRight == "" {
		out.HeaderRight = def.HeaderRight
	}
	if out.FooterLeft == "" {
		out.FooterLeft = def.FooterLeft
	}
	if out.FooterCenter == "" {
		out.FooterCenter = def.FooterCenter
	}
	if out.Disclaimer == "" {
		out.Disclaimer = def.Disclaimer
	}
	if out.ShowPageNumber == nil {
		out.ShowPageNumber = def.ShowPageNumber
	}
	return out
}

// PrintHTML 把报告 HTML 包成"自动唤起打印"的页面(PDF 导出通道)。
//
// 为什么要这层包装而不是直接返回报告 HTML:
//
//	用户点"导出 PDF"时期望的是"立刻拿到 PDF 文件", 而不是"一个网页然后自己
//	按 Ctrl+P"。自动唤起打印对话框能把这一步补齐, 体验接近真正的导出按钮。
//	同时页面顶部给出明确提示, 避免用户以为浏览器卡住了。
//
// 安全说明: 报告 HTML 已由 html/template 转义渲染, 此处只是原样拼接,
// 不引入新的注入面。
func PrintHTML(reportHTML, title string) string {
	var b strings.Builder
	b.WriteString("<!DOCTYPE html>\n<html lang=\"zh-CN\">\n<head>\n<meta charset=\"UTF-8\">\n<title>")
	b.WriteString(template.HTMLEscapeString(title))
	b.WriteString("</title>\n<style>\n")
	b.WriteString("#print-tip{position:fixed;left:0;right:0;top:0;z-index:9999;background:#4f46e5;color:#fff;")
	b.WriteString("font:13px/1.6 'Microsoft YaHei',sans-serif;padding:10px 16px;text-align:center;}\n")
	b.WriteString("#print-tip button{margin-left:12px;padding:3px 12px;border:1px solid #fff;background:transparent;color:#fff;border-radius:6px;cursor:pointer;font:inherit;}\n")
	b.WriteString("#print-tip button:hover{background:rgba(255,255,255,.15);}\n")
	b.WriteString("@media print{#print-tip{display:none !important;}}\n")
	b.WriteString("</style>\n</head>\n<body>\n")
	b.WriteString("<div id=\"print-tip\">正在准备 PDF 导出，若未弹出打印窗口请点右侧按钮，在打印目标中选择“另存为 PDF”。")
	b.WriteString("<button onclick=\"window.print()\">打印 / 保存为 PDF</button></div>\n")
	// 报告本体去掉 <html>/<head>/<body> 外壳后嵌入(避免嵌套文档结构破坏样式)
	b.WriteString(stripDocShell(reportHTML))
	b.WriteString("\n<script>window.addEventListener('load',function(){setTimeout(function(){window.print();},350);});</script>\n")
	b.WriteString("</body>\n</html>\n")
	return b.String()
}

// stripDocShell 剥离 HTML 文档外壳, 保留 <style> 与正文(用于嵌套进打印页)。
func stripDocShell(s string) string {
	out := s
	// 取 <style>...</style> 全部片段
	var styles strings.Builder
	rest := out
	for {
		i := strings.Index(strings.ToLower(rest), "<style")
		if i < 0 {
			break
		}
		j := strings.Index(strings.ToLower(rest), "</style>")
		if j < 0 || j < i {
			break
		}
		styles.WriteString(rest[i : j+len("</style>")])
		styles.WriteString("\n")
		rest = rest[j+len("</style>"):]
	}
	// 正文: <body ...> 之后到 </body> 之前
	body := rest
	lower := strings.ToLower(rest)
	if i := strings.Index(lower, "<body"); i >= 0 {
		if k := strings.Index(rest[i:], ">"); k >= 0 {
			body = rest[i+k+1:]
		}
	}
	if j := strings.LastIndex(strings.ToLower(body), "</body>"); j >= 0 {
		body = body[:j]
	}
	return styles.String() + body
}

// itoa 小整数转字符串(避免为一个转换引入 strconv 到模板数据构造链)。
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// firstNonEmptyStr 返回首个非空字符串。
func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}
