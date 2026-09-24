// docx_template.go Word 模板操作: 占位符替换 / 章节注入 / 内置模板 / 占位符取值。
//
// 模板约定(用户可在 Word 里自由排版, 只需遵守两条):
//
//  1. 文本里用 {{key}} 占位 —— 生成时替换为报告数据:
//     {{title}} 报告标题 / {{operator}} 报告人 / {{subtitle}} 副标题 /
//     {{tool}} 工具与版本 / {{time}} 生成时间 / {{risk}} 风险等级 / {{score}} 风险评分
//  2. 放一个段落只写 {{content}} —— 引擎把"概况/风险分布/资产/漏洞/扫描范围/
//     修复建议"等章节插入到该段位置; 模板没有该标记则追加到文末。
//
// 占位符被 Word 拆 run 的处理: 见 docx.go 头注释(先拼整段再替换)。
package report

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// BuiltinWordTemplateName 内置 Word 模板的名称(模板下拉框固定项)。
const BuiltinWordTemplateName = "builtin"

// ContentMarker 章节注入标记。
const ContentMarker = "{{content}}"

// BuiltinWordTemplate 内置 Word 模板: 封面(标题/副标题/报告人/工具/时间/风险)
// + {{content}} 章节注入位。用户不上传任何模板时的默认来源。
func BuiltinWordTemplate() []Block {
	return []Block{
		{Kind: "p", Style: "Title", Align: "center", Runs: []Run{{Text: "{{title}}", Size: 44}}},
		{Kind: "p", Align: "center", Runs: []Run{{Text: "{{subtitle}}", Color: "6B7280"}}},
		{Kind: "p", Runs: []Run{}},
		{Kind: "p", Align: "center", Runs: []Run{{Text: "报告人: {{operator}}"}}},
		{Kind: "p", Align: "center", Runs: []Run{{Text: "检测工具: {{tool}}"}}},
		{Kind: "p", Align: "center", Runs: []Run{{Text: "生成时间: {{time}}"}}},
		{Kind: "p", Align: "center", Runs: []Run{{Text: "整体风险: {{risk}} (评分 {{score}}/100)", Bold: true}}},
		{Kind: "p", Runs: []Run{}},
		{Kind: "p", Runs: []Run{{Text: ContentMarker, Color: "9CA3AF"}}},
	}
}

// ReplacePlaceholders 替换所有段落(含表格单元格)里的 {{key}} 占位符。
//
// 含占位符的段落会被重写为单个 run(沿用首个有文本 run 的格式) —— Word 会把
// 文本拆成多个 run, 只有"整段拼接后替换"才能可靠命中; 代价是该段 run 间的
// 局部格式差异丢失(模板工具可接受, 章节标题等按整段统一格式排版)。
func ReplacePlaceholders(blocks []Block, values map[string]string) []Block {
	out := make([]Block, 0, len(blocks))
	for _, b := range blocks {
		nb := b
		if b.Kind == "tbl" {
			rows := make([]Row, len(b.Rows))
			for i, row := range b.Rows {
				cells := make([]Cell, len(row.Cells))
				for j, c := range row.Cells {
					cells[j] = Cell{Width: c.Width, Runs: replaceRuns(c.Runs, values)}
				}
				rows[i] = Row{Cells: cells}
			}
			nb.Rows = rows
		} else {
			nb.Runs = replaceRuns(b.Runs, values)
		}
		out = append(out, nb)
	}
	return out
}

func replaceRuns(runs []Run, values map[string]string) []Run {
	var full strings.Builder
	for _, r := range runs {
		full.WriteString(r.Text)
	}
	text := full.String()
	if !strings.Contains(text, "{{") {
		return runs
	}
	replaced := text
	for k, v := range values {
		replaced = strings.ReplaceAll(replaced, "{{"+k+"}}", v)
	}
	if replaced == text {
		return runs // 该段没有命中任何占位符, 原样保留(格式零损伤)
	}
	base := Run{Text: replaced}
	for _, r := range runs {
		if r.Text != "" {
			base = r // 沿用首个有文本 run 的格式
			break
		}
	}
	base.Text = replaced
	return []Run{base}
}

// InsertSections 把章节块注入模板: 替换 {{content}} 所在段落; 模板没有该标记
// 时追加到文末(用户模板不写标记也能用, 只是章节排在模板内容之后)。
func InsertSections(blocks, sections []Block) []Block {
	for i, b := range blocks {
		if b.Kind == "p" && strings.Contains(b.Text(), ContentMarker) {
			out := make([]Block, 0, len(blocks)+len(sections))
			out = append(out, blocks[:i]...)
			out = append(out, sections...)
			out = append(out, blocks[i+1:]...)
			return out
		}
	}
	return append(blocks, sections...)
}

// PlaceholderValues 生成标准占位符取值(装配层可再补 {{subtitle}} 等自定义项)。
func PlaceholderValues(s *Snapshot, st SnapshotStats) map[string]string {
	var t time.Time
	if s != nil {
		t = s.CreatedAt
	}
	if t.IsZero() {
		t = time.Now()
	}
	return map[string]string{
		"title":    s.Title,
		"operator": s.Operator,
		"tool":     s.Tool,
		"time":     t.Format("2006-01-02 15:04"),
		"risk":     st.RiskLevel,
		"score":    strconv.Itoa(st.RiskScore),
	}
}

// ExpandHeaderValues 用占位符取值展开页眉页脚模板(与 Header 的 {{...}} 约定一致)。
func ExpandHeaderValues(h Header, values map[string]string) Header {
	expand := func(s string) string {
		for k, v := range values {
			s = strings.ReplaceAll(s, "{{"+k+"}}", v)
		}
		return s
	}
	h.HeaderLeft = expand(h.HeaderLeft)
	h.HeaderCenter = expand(h.HeaderCenter)
	h.HeaderRight = expand(h.HeaderRight)
	h.FooterLeft = expand(h.FooterLeft)
	h.FooterCenter = expand(h.FooterCenter)
	h.FooterRight = expand(h.FooterRight)
	return h
}

// 以下小工具供章节生成(docx_sections.go)与测试使用。

func pRun(text string) Block {
	return Block{Kind: "p", Runs: []Run{{Text: text}}}
}

func pBold(text string) Block {
	return Block{Kind: "p", Runs: []Run{{Text: text, Bold: true}}}
}

func pSmallGray(text string) Block {
	return Block{Kind: "p", Runs: []Run{{Text: text, Color: "6B7280", Size: 18}}}
}

func heading(level int, text string) Block {
	return Block{Kind: "p", Style: fmt.Sprintf("Heading%d", level), Runs: []Run{{Text: text}}}
}

func tableBlock(header []string, rows [][]string) Block {
	b := Block{Kind: "tbl"}
	if len(header) > 0 {
		var hr Row
		for _, h := range header {
			hr.Cells = append(hr.Cells, Cell{Runs: []Run{{Text: h, Bold: true}}})
		}
		b.Rows = append(b.Rows, hr)
	}
	for _, r := range rows {
		var row Row
		for _, c := range r {
			row.Cells = append(row.Cells, Cell{Runs: []Run{{Text: c}}})
		}
		b.Rows = append(b.Rows, row)
	}
	return b
}
