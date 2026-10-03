package report

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"yugsight/internal/models"
)

// ===== 章节(封面之后, 全部以 Heading1 分章) =====
//
// 章节可被"可视化排版编辑器"(report_tpl_visual_api.go)选择与排序 —— 编辑器产出
// 的 .visual.json 存的就是本节 key 列表。key 集合与默认顺序由 SectionList()
// 单点定义, 前端/后端/测试共用。

// SectionMeta 章节元信息(可视化排版编辑器的数据源)。
type SectionMeta struct {
	Key   string `json:"key"`
	Title string `json:"title"`
	// Optional 章节无数据时自动省略(如渗透验证无数据就不出章节); 恒有数据的章节为 false
	Optional bool `json:"optional"`
}

// sectionOrder 章节 key 的默认顺序(渲染顺序 = 编号顺序)。
// 2026-09-25 用户要求加版权声明: 版权信息固定压尾(报告的法律落款, 不参与
// 排版取舍; 用户在可视化编辑器里删掉也会被强制补回, 见 SectionBlocksWithOptions)。
var sectionOrder = []string{
	"summary", "risk", "assets", "vulns", "vulnfix", "penta", "scans", "fix", "disclaimer", "copyright",
}

// sectionTitles 各章节的固定标题(编号由渲染顺序动态生成)。
var sectionTitles = map[string]string{
	"summary":    "总体概况",
	"risk":       "风险等级分布",
	"assets":     "资产清单",
	"vulns":      "漏洞明细",
	"vulnfix":    "漏洞描述与修复建议",
	"penta":      "渗透验证结果",
	"scans":      "扫描范围",
	"fix":        "重点修复建议",
	"disclaimer": "免责声明",
	"copyright":  "版权信息",
}

// SectionList 章节清单(默认顺序, 供可视化排版编辑器回显与校验)。
// Optional=false 的章节是核心章节: 渲染时若被用户的顺序删掉也会强制补回
// (总体概况/风险/资产/漏洞明细是报告骨架, 版权信息是法律落款, 都不该被裁掉)。
func SectionList() []SectionMeta {
	out := make([]SectionMeta, 0, len(sectionOrder))
	for _, k := range sectionOrder {
		out = append(out, SectionMeta{
			Key:      k,
			Title:    sectionTitles[k],
			Optional: k == "vulnfix" || k == "penta" || k == "scans" || k == "fix" || k == "disclaimer",
		})
	}
	return out
}

// SectionOptions 章节选择与排序(nil 或空 Order = 默认全量默认顺序)。
// Order 里的未知 key 忽略(向前兼容: 旧配置在新增章节后不会整体失效)。
type SectionOptions struct {
	Order []string
	// Replace 章节 key -> 自定义正文块(非 nil 时覆盖默认正文; 空切片 = 该章节
	// 无正文)。2026-09-25 模板编辑器: 版权信息/免责声明支持富文本(用户自写
	// 文案+格式), 应用层把片段解析成 Run 后从这里注入。
	Replace map[string][]Block
	// Skip 显式省略的章节 key(优先于 Replace; 对 copyright 的"强制补回末尾"
	// 兜底同样生效 —— 用户在模板里删掉版权 = 有意不出, 不再补)。
	Skip []string
	// Styles 逐章节字体样式(2026-09-25 用户要求: 逐章节字体颜色/底色/格式,
	// 只改观感不改内容)。key = 章节 key, 未知 key 忽略(与 Order 同口径)。
	Styles map[string]SectionStyle
}

// SectionStyle 单个章节的字体样式(全空 = 该章保持默认渲染)。
// 颜色字段均为 6 位十六进制不带 #, 与 Run.Color 同口径; 两个出口(docx/HTML)
// 共用同一份数据, 在 SectionBlocksWithOptions 里烤进块序列(见 styleSectionBody)。
type SectionStyle struct {
	// TitleColor 章节标题字体色; 空 = 默认(docx Heading1 深灰 / HTML #111827)
	TitleColor string `json:"titleColor,omitempty"`
	// TitleBg 章节标题底色(字符底纹)
	TitleBg string `json:"titleBg,omitempty"`
	// FontColor 章节正文字体色。只作用于未显式设色的 run —— 级别列等自带
	// 颜色的 run 保留原色(否则报告的风险视觉层级被冲掉)。
	FontColor string `json:"fontColor,omitempty"`
	// Bg 章节底色(段落/表格整块底纹, 全宽)
	Bg string `json:"bg,omitempty"`
	// Bold 章节正文加粗
	Bold bool `json:"bold,omitempty"`
	// Size 章节正文字号(半点: 21=10.5pt 小五, 24=12pt 小四, 28=14pt 四号,
	// 32=16pt 小三); 0 = 继承默认
	Size int `json:"size,omitempty"`
}

// styleSectionBody 把逐章节样式烤进正文块序列(2026-09-25 "逐章节字体颜色/
// 底色/格式")。只改观感, 一个字节的文本都不动:
//
//	Bg        → 块级底纹 Block.Shd(段落全宽底纹 / 表格底色, 两出口都渲染)
//	FontColor → 仅未显式设色的 run(级别列等自带颜色的保留)
//	Bold      → run 加粗(已有加粗不变)
//	Size      → 仅未设字号的 run
//
// 返回新切片(不改动调用方切片); 块内 Run 就地改 —— body 是每次渲染现构造
// 的(summaryBody 等), 无跨调用共享。
func styleSectionBody(body []Block, st SectionStyle) []Block {
	if st.TitleColor == "" && st.TitleBg == "" && st.FontColor == "" && st.Bg == "" && !st.Bold && st.Size == 0 {
		return body // 未设样式 = 原序列, 零差异
	}
	applyRun := func(r *Run) {
		if r.MediaName != "" || r.PageBreak {
			return // 图片/分页 run 无文本, 不套样式
		}
		if st.FontColor != "" && r.Color == "" {
			r.Color = st.FontColor
		}
		if st.Size > 0 && r.Size == 0 {
			r.Size = st.Size
		}
		if st.Bold {
			r.Bold = true
		}
	}
	out := make([]Block, 0, len(body))
	for _, blk := range body {
		if st.Bg != "" {
			blk.Shd = st.Bg
		}
		switch blk.Kind {
		case "p":
			for i := range blk.Runs {
				applyRun(&blk.Runs[i])
			}
		case "tbl":
			for ri := range blk.Rows {
				for ci := range blk.Rows[ri].Cells {
					c := &blk.Rows[ri].Cells[ci]
					for ii := range c.Runs {
						applyRun(&c.Runs[ii])
					}
				}
			}
		}
		out = append(out, blk)
	}
	return out
}

// SectionBlocks 默认全量章节(既有调用与测试的入口, 行为 = 默认顺序全渲染)。
func SectionBlocks(s *Snapshot, st SnapshotStats, disclaimer string) []Block {
	return SectionBlocksWithOptions(s, st, disclaimer, nil)
}

// SectionBlocksWithOptions 按 opts 的顺序/选择渲染章节; 编号按实际渲染顺序
// 一、二、三… 连续(与旧行为一致: 旧实现是前四章硬编码 + 后续 nextSec,
// 默认顺序下两者完全等价)。
func SectionBlocksWithOptions(s *Snapshot, st SnapshotStats, disclaimer string, opts *SectionOptions) []Block {
	vulnByIP := map[string][]*models.Vuln{}
	for _, v := range s.Vulns {
		if v == nil {
			continue
		}
		vulnByIP[models.NormIP(v.AssetIP)] = append(vulnByIP[models.NormIP(v.AssetIP)], v)
	}

	type sec struct {
		key  string
		body []Block
		skip bool
	}
	mk := func(key string, optional bool, blk []Block) sec {
		return sec{key: key, body: blk, skip: optional && len(blk) == 0}
	}

	// 是否被显式 Skip(模板里删掉 = 有意不出)
	skipKey := map[string]bool{}
	if opts != nil {
		for _, k := range opts.Skip {
			skipKey[k] = true
		}
	}

	secs := []sec{
		mk("summary", false, summaryBody(st)),
		mk("risk", false, riskBody(st)),
		mk("assets", false, assetsBody(s, vulnByIP)),
		mk("vulns", false, vulnsBody(s.Vulns)),
		// 漏洞描述与修复建议: 逐条给描述+修复方案(2026-09-25 用户口径:
		// 漏洞明细只有标题看不出严重性, 也要说明怎么修); 无漏洞时整章省略
		mk("vulnfix", true, vulnfixBody(s.Vulns)),
		mk("penta", true, pentaBody(s.Penta)),
		mk("scans", true, scansBody(s.Scans)),
		mk("fix", true, fixBody(s.Vulns)),
		mk("disclaimer", true, disclaimerBody(disclaimer)),
		// 版权信息(2026-09-25 用户要求): 无数据也必出 —— 是报告落款不是数据章节
		mk("copyright", false, copyrightBody()),
	}
	// Replace: 应用层注入的自定义正文(富文本版权/免责声明); 按索引改切片元素
	// (sec 是值类型, 直接改副本不会写回)
	if opts != nil {
		for k, body := range opts.Replace {
			for i := range secs {
				if secs[i].key == k {
					secs[i].body = body
					secs[i].skip = len(body) == 0 // 显式空正文 = 该章不出
					break
				}
			}
		}
	}

	order := sectionOrder
	if opts != nil && len(opts.Order) > 0 {
		order = opts.Order
	}
	byKey := make(map[string]sec, len(secs))
	for _, x := range secs {
		byKey[x.key] = x
	}

	var out []Block
	n := 0
	seen := map[string]bool{}
	addSec := func(key string) {
		x := byKey[key]
		seen[key] = true
		st := SectionStyle{}
		if opts != nil {
			st = opts.Styles[key]
		}
		if key != "disclaimer" { // 免责声明沿用旧行为: 无标题小字
			n++
			h := heading(1, cnNum(n)+"、"+sectionTitles[key])
			if key == "copyright" {
				h.ID = "copyright" // HTML 出口 "版权信息" 跳转锚点
			}
			// 标题样式: 字色/底色(heading 的 run 无自带色, 直接覆盖)
			if st.TitleColor != "" || st.TitleBg != "" {
				for i := range h.Runs {
					if st.TitleColor != "" {
						h.Runs[i].Color = st.TitleColor
					}
					if st.TitleBg != "" {
						h.Runs[i].Bg = st.TitleBg
					}
				}
			}
			out = append(out, h)
		}
		out = append(out, styleSectionBody(x.body, st)...)
	}
	for _, key := range order {
		if skipKey[key] {
			continue // 显式 Skip(模板里删掉 = 有意不出)
		}
		x, ok := byKey[key]
		if !ok || x.skip {
			continue
		}
		addSec(key)
	}
	// 版权信息兜底: 用户自定义顺序删掉/漏掉时强制补到末尾(编号续接)。
	// 只强制版权 —— 它是报告的法律落款, 不是排版选择(2026-09-25 用户口径
	// "版权声明加一下"); 其余章节(含核心章节)尊重用户顺序, 保持旧行为。
	// 显式 Skip 的版权不补(2026-09-25 二轮: 版权信息也可在模板里删除)。
	if !skipKey["copyright"] {
		if x, ok := byKey["copyright"]; ok && !seen["copyright"] && !x.skip {
			addSec("copyright")
		}
	}
	return out
}

func cnNum(n int) string {
	if n <= 10 {
		// 按 rune 切: 汉字 3 字节, 直接按字节下标会切出乱码
		s := []rune("一二三四五六七八九十")
		return string(s[n-1 : n])
	}
	return fmt.Sprintf("%d", n)
}

// ---------- 各章节 body ----------

func summaryBody(st SnapshotStats) []Block {
	line1 := fmt.Sprintf("共发现漏洞 %d 项(严重 %d / 高危 %d / 中危 %d / 低危 %d / 提示 %d)。",
		st.VulnTotal, st.Critical, st.High, st.Medium, st.Low, st.Info)
	line2 := fmt.Sprintf("综合风险评分 %d/100(风险等级: %s); 涉及资产 %d 台(在线 %d 台), 开放端口 %d 个。",
		st.RiskScore, orDash(st.RiskLevel), st.AssetTotal, st.AssetAlive, st.PortTotal)
	return []Block{
		{Kind: "p", Runs: []Run{{Text: line1, Size: 24}}},
		{Kind: "p", Runs: []Run{{Text: line2, Size: 24}}},
	}
}

func riskBody(st SnapshotStats) []Block {
	rows := [][]string{
		{"严重", fmt.Sprintf("%d", st.Critical)},
		{"高危", fmt.Sprintf("%d", st.High)},
		{"中危", fmt.Sprintf("%d", st.Medium)},
		{"低危", fmt.Sprintf("%d", st.Low)},
		{"提示", fmt.Sprintf("%d", st.Info)},
	}
	return []Block{tableBlock([]string{"等级", "数量"}, rows)}
}

func assetsBody(s *Snapshot, vulnByIP map[string][]*models.Vuln) []Block {
	var rows [][]string
	for _, a := range s.Assets {
		if a == nil {
			continue
		}
		risk := "-"
		if vs := vulnByIP[models.NormIP(a.IP)]; len(vs) > 0 {
			risk = sevName(maxSeverity(vs))
		}
		rows = append(rows, []string{
			models.NormIP(a.IP),
			orDash(a.Hostname),
			orDash(a.OS),
			fmt.Sprintf("%d", len(a.Ports)),
			orDash(a.Service),
			aliveLabel(a.Alive),
			risk,
			fmt.Sprintf("%d", len(vulnByIP[models.NormIP(a.IP)])),
		})
	}
	return []Block{tableBlock(
		[]string{"IP", "主机名", "系统", "端口数", "服务", "在线", "风险", "漏洞数"}, rows)}
}

// sevColor 等级着色(与 HTML 报告的 b91c1c/ea580c/... 徽章同色系)。
func sevColor(sev string) string {
	switch models.NormalizeSeverity(sev) {
	case "critical":
		return "B91C1C"
	case "high":
		return "EA580C"
	case "medium":
		return "CA8A04"
	case "low":
		return "2563EB"
	default:
		return "64748B"
	}
}

// vulnsBody 漏洞明细表。列布局(级别/标题/CVE/资产/端口/协议/置信度/状态/
// 发现时间/渗透验证)是既有测试按列下标断言的契约(如 Cells[7]=状态), 勿重排。
func vulnsBody(vs []*models.Vuln) []Block {
	v := sortedVulns(vs)
	b := Block{Kind: "tbl"}
	var hr Row
	for _, h := range []string{"级别", "标题", "CVE", "资产", "端口", "协议", "置信度", "状态", "发现时间", "渗透验证"} {
		hr.Cells = append(hr.Cells, Cell{Runs: []Run{{Text: h, Bold: true}}, Shd: "F3F4F6"})
	}
	b.Rows = append(b.Rows, hr)
	for _, item := range v {
		if item == nil {
			continue
		}
		port := "-"
		if item.Port > 0 {
			port = fmt.Sprintf("%d", item.Port)
		}
		verdict := "-"
		if item.PentaResult != "" {
			verdict = pentaExploitName(item.PentaResult)
		}
		row := Row{}
		// 级别列着色 + 加粗: 长表格里第一列是扫读锚点, 纯黑文字找高危要数行
		row.Cells = append(row.Cells, Cell{Runs: []Run{{Text: sevName(item.Severity), Bold: true, Color: sevColor(item.Severity)}}})
		for _, c := range []string{
			item.Title,
			orDash(item.CVE),
			models.NormIP(item.AssetIP),
			port,
			orDash(item.Protocol),
			fmt.Sprintf("%d", item.Confidence),
			statusLabel(item.Status),
			timeLabel(item.FoundAt),
			verdict,
		} {
			row.Cells = append(row.Cells, Cell{Runs: []Run{{Text: c}}})
		}
		b.Rows = append(b.Rows, row)
	}
	out := []Block{}
	if len(v) == 0 {
		out = append(out, pRun("未发现漏洞。"))
	}
	return append(out, b)
}

// vulnfixBody 逐条漏洞的"描述 + 修复建议" —— 2026-09-25 新增(用户口径:
// 漏洞明细表只有标题看不出严重性, 也要说明怎么修)。描述截断 500 字防止
// 个别超长 description 把文档撑爆; 修复建议来自 FixOf 三轮匹配
// (关键字 > 端口规则 > CVE 前缀兜底)。
func vulnfixBody(vs []*models.Vuln) []Block {
	v := sortedVulns(vs)
	if len(v) == 0 {
		return nil
	}
	var out []Block
	i := 0
	for _, item := range v {
		if item == nil {
			continue
		}
		if i >= 200 { // 与漏洞明细表同上限
			break
		}
		i++
		loc := fmt.Sprintf("(资产 %s", models.NormIP(item.AssetIP))
		if item.Port > 0 {
			loc += fmt.Sprintf(":%d", item.Port)
		}
		loc += ")"
		if item.CVE != "" {
			loc += " " + item.CVE
		}
		out = append(out, pBold(fmt.Sprintf("%d. [%s] %s %s", i, sevName(item.Severity), item.Title, loc)))
		desc := strings.TrimSpace(item.Description)
		if desc == "" {
			desc = "(该漏洞无描述信息)"
		}
		out = append(out, pMuted("描述: "+clipText(desc, 500)))
		out = append(out, pMuted("修复建议: "+FixOf(item)))
	}
	return out
}

func pentaBody(entries []PentaEntry) []Block {
	if len(entries) == 0 {
		return nil
	}
	var rows [][]string
	for _, p := range entries {
		// 未做定级修正时显示 "-", 不能直接走 sevName: 它对空串返回"低危",
		// 会把"未修正"读成"修正成了低危"
		level := "-"
		if strings.TrimSpace(p.RiskLevel) != "" {
			level = sevName(p.RiskLevel)
		}
		rows = append(rows, []string{
			orDash(p.Target),
			orDash(p.Title),
			orDash(p.CVE),
			pentaExploitName(p.Exploitability),
			level,
			orDash(p.Summary),
			timeLabel(p.VerifiedAt),
			orDash(p.Operator),
		})
	}
	out := []Block{tableBlock(
		[]string{"目标", "验证对象", "CVE", "验证结论", "定级", "摘要", "验证时间", "操作者"}, rows)}
	out = append(out, pSmallGray("验证结论来自渗透工作台(仅对已授权目标实施, 操作全程审计留痕)。「可利用」= 验证过程中实际观测到漏洞行为; 完整命令日志与响应证据留存于平台渗透工作台。"))
	return out
}

func scansBody(scans []ScanInfo) []Block {
	if len(scans) == 0 {
		return nil
	}
	var rows [][]string
	for _, sc := range scans {
		rows = append(rows, []string{
			timeLabel(sc.CreatedAt),
			orDash(sc.Target),
			orDash(sc.Type),
			orDash(sc.Status),
			orDash(sc.ProbeNode),
		})
	}
	return []Block{tableBlock([]string{"时间", "目标", "类型", "状态", "节点"}, rows)}
}

// fixBody 重点修复建议(严重+高危, 每级最多 10 条) —— 管理层视角的摘要;
// 逐条的详细修复在"漏洞描述与修复建议"章节。
func fixBody(vs []*models.Vuln) []Block {
	v := sortedVulns(vs)
	var top []*models.Vuln
	counts := map[string]int{}
	for _, item := range v {
		if item == nil {
			continue
		}
		sv := models.NormalizeSeverity(item.Severity)
		if sv != models.SeverityCritical && sv != models.SeverityHigh {
			break // sortedVulns 已按严重度升序, 之后不会再是 critical/high
		}
		if counts[sv] >= 10 {
			continue
		}
		counts[sv]++
		top = append(top, item)
	}
	if len(top) == 0 {
		return nil
	}
	var out []Block
	i := 0
	for _, item := range top {
		i++
		loc := fmt.Sprintf("(资产 %s", models.NormIP(item.AssetIP))
		if item.Port > 0 {
			loc += fmt.Sprintf(":%d", item.Port)
		}
		loc += ")"
		if item.CVE != "" {
			loc += " " + item.CVE
		}
		out = append(out, pBold(fmt.Sprintf("%d. [%s] %s %s", i, sevName(item.Severity), item.Title, loc)))
		out = append(out, pRun(FixOf(item)))
	}
	return out
}

func disclaimerBody(text string) []Block {
	if strings.TrimSpace(text) == "" {
		return nil
	}
	return []Block{pSmallGray(text)}
}

// CopyrightLine 版权声明统一口径(2026-09-24 用户明确: 作者是 yugo, Yugsight 是产品名;
// 与 LICENSE / 图标 LegalCopyright 同一文案来源, 报告里的落款不得漂移)。
const CopyrightLine = "Copyright © 2026 yugo. 版权所有。"

// copyrightBody 「版权信息」章节(2026-09-25 用户要求"版权声明加一下"):
// 固定压尾、无数据也必出(核心章节, 见 SectionBlocksWithOptions 的兜底逻辑)。
func copyrightBody() []Block {
	return []Block{
		pSmallGray(CopyrightLine),
		pSmallGray("本报告由 Yugsight(御视)安全运维一体化平台自动生成, 报告内容仅限内部安全运维使用。"),
		pSmallGray("未经著作权人书面许可, 不得复制、传播本报告全部或部分内容。"),
	}
}

// ---------- 共享辅助 ----------

// sortedVulns 按 严重度→资产→端口 稳定排序(明细表/逐条修复/重点修复共用,
// 保证几处顺序一致)。
func sortedVulns(vs []*models.Vuln) []*models.Vuln {
	out := make([]*models.Vuln, len(vs))
	copy(out, vs)
	sort.SliceStable(out, func(i, j int) bool {
		ri, rj := sevRankOf(out[i].Severity), sevRankOf(out[j].Severity)
		if ri != rj {
			return ri < rj
		}
		if out[i].AssetIP != out[j].AssetIP {
			return out[i].AssetIP < out[j].AssetIP
		}
		return out[i].Port < out[j].Port
	})
	return out
}

var sevRankMap = map[string]int{
	models.SeverityCritical: 0,
	models.SeverityHigh:     1,
	models.SeverityMedium:   2,
	models.SeverityLow:      3,
	models.SeverityInfo:     4,
}

func sevRankOf(sev string) int {
	if r, ok := sevRankMap[models.NormalizeSeverity(sev)]; ok {
		return r
	}
	return 5
}

// maxSeverity 取一组漏洞中的最高等级(资产风险标注用)。
func maxSeverity(vs []*models.Vuln) string {
	best := ""
	bestRank := 99
	for _, v := range vs {
		r := sevRankOf(v.Severity)
		if r < bestRank {
			bestRank, best = r, v.Severity
		}
	}
	return best
}

func orDash(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "-"
	}
	return s
}

func aliveLabel(alive bool) string {
	if alive {
		return "在线"
	}
	return "离线"
}

func statusLabel(status string) string {
	switch status {
	case "fixed":
		return "已修复"
	case "duplicate":
		return "重复"
	default:
		return "未修复"
	}
}

func timeLabel(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format("2006-01-02 15:04")
}

func pMuted(text string) Block {
	return Block{Kind: "p", Runs: []Run{{Text: text, Color: "374151"}}}
}

// clipText 按 rune 截断(超长 description 会带多字节, 按字节切会切出坏字)。
func clipText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
