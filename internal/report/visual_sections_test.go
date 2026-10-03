package report

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

// TestSectionOptionsOrderAndOmit 守"可视化排版编辑器"的章节选择/排序契约:
// .visual.json 存的是章节 key 顺序, 生成报告必须按它渲染并连续编号。
// 改坏这里 = 用户辛苦排好的版式在生成时静默回退到默认顺序。
func TestSectionOptionsOrderAndOmit(t *testing.T) {
	snap := sampleSnapshot()
	st := ComputeStats(snap)

	headings := func(b []Block) []string {
		var hs []string
		for _, b := range b {
			if b.Style == "Heading1" {
				hs = append(hs, b.Text())
			}
		}
		return hs
	}

	// 1) 重排序: 漏洞明细放第一 -> 编号跟着变(一、漏洞明细);
	//    版权信息不在用户顺序里 → 强制补到末尾(编号续接)
	reordered := SectionBlocksWithOptions(snap, st, "", &SectionOptions{
		Order: []string{"vulns", "summary", "risk", "assets"},
	})
	hs := headings(reordered)
	if len(hs) != 5 {
		t.Fatalf("4 个自选章节 + 强制版权信息应为 5 章: %v", hs)
	}
	if hs[0] != "一、漏洞明细" || hs[1] != "二、总体概况" || hs[2] != "三、风险等级分布" || hs[3] != "四、资产清单" || hs[4] != "五、版权信息" {
		t.Fatalf("重排序未按指定顺序渲染: %v", hs)
	}

	// 2) 省略: 有扫描数据但 order 不含 scans -> 不出该章节
	noScans := SectionBlocksWithOptions(snap, st, "", &SectionOptions{
		Order: []string{"summary", "risk", "assets", "vulns"},
	})
	for _, h := range headings(noScans) {
		if strings.Contains(h, "扫描范围") {
			t.Fatalf("order 不含 scans 时不应渲染扫描范围: %v", headings(noScans))
		}
	}

	// 3) 未知 key 忽略(向前兼容: 旧配置遇到新增章节不整体失效);
	//    版权信息仍强制压尾
	withUnknown := SectionBlocksWithOptions(snap, st, "", &SectionOptions{
		Order: []string{"summary", "not-a-real-section", "risk"},
	})
	hs3 := headings(withUnknown)
	if len(hs3) != 3 || hs3[0] != "一、总体概况" || hs3[1] != "二、风险等级分布" || hs3[2] != "三、版权信息" {
		t.Fatalf("未知章节 key 应被忽略且编号连续: %v", hs3)
	}

	// 4) 无数据的可选章节自动省略(penta/scans/fix/vulnfix 全空)
	empty := &Snapshot{Title: "空报告"}
	st2 := ComputeStats(empty)
	def := SectionBlocksWithOptions(empty, st2, "", nil)
	for _, h := range headings(def) {
		for _, bad := range []string{"渗透验证", "扫描范围", "重点修复", "漏洞描述与修复建议"} {
			if strings.Contains(h, bad) {
				t.Fatalf("无数据时可选章节应省略, 却出现 %q: %v", bad, headings(def))
			}
		}
	}
}

// TestVulnFixSection 逐条"描述+修复建议"章节的契约:
// 有漏洞必出(用户口径: 漏洞要详细、要有解法), 无漏洞不占章节。
func TestVulnFixSection(t *testing.T) {
	snap := sampleSnapshot()
	st := ComputeStats(snap)
	blocks := SectionBlocksWithOptions(snap, st, "", nil)
	var found bool
	for i, b := range blocks {
		if b.Style == "Heading1" && strings.Contains(b.Text(), "漏洞描述与修复建议") {
			found = true
			// 章节后应有 3 条(样例 3 个漏洞), 每条 = 标题行 + 描述行 + 修复行
			if i+6 >= len(blocks) {
				t.Fatalf("逐条修复内容不完整: %d 块", len(blocks)-i-1)
			}
			head := blocks[i+1].Text()
			if !strings.Contains(head, "严重漏洞甲") {
				t.Fatalf("逐条修复首条应为最高严重度: %q", head)
			}
			desc := blocks[i+2].Text()
			fix := blocks[i+3].Text()
			if !strings.HasPrefix(desc, "描述:") || !strings.HasPrefix(fix, "修复建议:") {
				t.Fatalf("描述/修复行格式: %q / %q", desc, fix)
			}
			break
		}
	}
	if !found {
		t.Fatal("有漏洞时缺少「漏洞描述与修复建议」章节")
	}

	empty := &Snapshot{Title: "空报告"}
	st2 := ComputeStats(empty)
	for _, b := range SectionBlocksWithOptions(empty, st2, "", nil) {
		if b.Style == "Heading1" && strings.Contains(b.Text(), "漏洞描述与修复建议") {
			t.Fatal("无漏洞时不应渲染逐条修复章节")
		}
	}
}

// TestBuiltinTemplatePageBreakAndShd 内置 Word 模板的排版契约:
// 封面与正文之间必须分页(否则首屏封面+章节挤一页 = "好难看"的直接原因),
// 表头必须有底纹(纯白表格在 Word 里无结构)。
func TestBuiltinTemplatePageBreakAndShd(t *testing.T) {
	tpl := BuiltinWordTemplate()
	breakCount := 0
	for _, b := range tpl {
		for _, r := range b.Runs {
			if r.PageBreak {
				breakCount++
			}
		}
	}
	if breakCount != 1 {
		t.Fatalf("封面后应有且仅有一个分页符: %d", breakCount)
	}

	// docx XML 侧
	data, err := WriteDocx(tpl, DocxMeta{Title: "t"})
	if err != nil {
		t.Fatalf("WriteDocx: %v", err)
	}
	if !docxContains(data, `<w:br w:type="page"/>`) {
		t.Fatal("docx XML 缺分页符")
	}

	// 表格底纹
	tbl := vulnsBody(sampleSnapshot().Vulns)
	data2, err := WriteDocx([]Block{tbl[0]}, DocxMeta{Title: "t2"})
	if err != nil {
		t.Fatalf("WriteDocx: %v", err)
	}
	if !docxContains(data2, `w:fill="F3F4F6"`) {
		t.Fatal("漏洞明细表头缺底纹(排版契约)")
	}
}

// TestCopyrightSection 守"版权声明"契约(2026-09-25 用户要求):
// 版权信息是报告落款, ① 默认必出且压尾 ② 用户自定义顺序漏掉/删掉时强制补回
// ③ HTML 出口的"版权信息"跳转入口依赖章节标题携带 #copyright 锚点。
func TestCopyrightSection(t *testing.T) {
	snap := sampleSnapshot()
	st := ComputeStats(snap)

	headings := func(b []Block) []string {
		var hs []string
		for _, b := range b {
			if b.Style == "Heading1" {
				hs = append(hs, b.Text())
			}
		}
		return hs
	}

	// ① 默认顺序: 版权信息在末位(免责声明是末尾小字无标题, 不算章节)
	def := SectionBlocksWithOptions(snap, st, "", nil)
	hs := headings(def)
	last := hs[len(hs)-1]
	if !strings.Contains(last, "版权信息") {
		t.Fatalf("默认顺序末章应为版权信息: %v", hs)
	}
	copyrightIdx := -1
	for i, h := range hs {
		if strings.Contains(h, "版权信息") {
			copyrightIdx = i
		}
	}
	found := false
	for _, b := range def {
		if strings.Contains(b.Text(), "yugo") && strings.Contains(b.Text(), "Copyright") {
			found = true
		}
	}
	if !found {
		t.Fatal("版权章节缺少版权声明文案(Copyright © 2026 yugo)")
	}
	if copyrightIdx < 0 {
		t.Fatal("未找到版权信息章节")
	}

	// ② 用户顺序删掉 copyright → 强制补回到末尾(只强制版权, 其余章节
	//    尊重用户顺序; summary 被删不补回)
	trimmed := SectionBlocksWithOptions(snap, st, "", &SectionOptions{
		Order: []string{"risk", "assets", "vulns"},
	})
	hs2 := headings(trimmed)
	if len(hs2) != 4 {
		t.Fatalf("3 个自选章节 + 补回的版权信息应为 4 章: %v", hs2)
	}
	if !strings.Contains(hs2[3], "版权信息") {
		t.Fatalf("补回的版权信息应在末尾: %v", hs2)
	}
	for _, h := range hs2[:3] {
		if strings.Contains(h, "总体概况") {
			t.Fatalf("非版权章节不应被强制补回: %v", hs2)
		}
	}

	// ③ HTML 锚点: 版权章节标题块带 ID=copyright
	var anchorOK bool
	for _, b := range def {
		if b.ID == "copyright" {
			anchorOK = true
		}
	}
	if !anchorOK {
		t.Fatal("版权章节标题缺 #copyright 锚点(HTML 出口'版权信息'跳转依赖)")
	}
}

// TestReplacePlaceholdersKeepsCellShd 守"排版装饰不被占位符替换洗掉"的契约:
// 报告生成必过 ReplacePlaceholders(封面 {{title}}/{{time}} 替换), 它重建每个
// 单元格 —— 若漏抄 Shd, 全报告表格底纹静默丢失(用户只见"Word 好难看"查不到
// 原因, 2026-09-25 实机排查坐实的 bug: 单测直出有底纹, 生成的报告没有)。
func TestReplacePlaceholdersKeepsCellShd(t *testing.T) {
	blocks := []Block{
		{Kind: "p", Runs: []Run{{Text: "{{title}}"}}},
		{Kind: "tbl", Rows: []Row{{Cells: []Cell{
			{Runs: []Run{{Text: "级别", Bold: true}}, Shd: "F3F4F6"},
			{Runs: []Run{{Text: "无占位符"}}, Shd: "E5E7EB"},
		}}}},
	}
	out := ReplacePlaceholders(blocks, map[string]string{"title": "T"})

	cell0 := out[1].Rows[0].Cells[0]
	if cell0.Shd != "F3F4F6" {
		t.Fatalf("占位符替换后表头底纹丢失: %q", cell0.Shd)
	}
	if len(cell0.Runs) != 1 || !cell0.Runs[0].Bold {
		t.Fatalf("表头格式应保留: %+v", cell0.Runs)
	}
	cell1 := out[1].Rows[0].Cells[1]
	if cell1.Shd != "E5E7EB" || cell1.Runs[0].Text != "无占位符" {
		t.Fatalf("无占位符单元格应零损伤: %+v", cell1)
	}
}

// TestSectionStylesApplied 守"逐章节字体颜色/底色/格式"契约(2026-09-25 用户
// 要求, 内容不可改只改观感)。改坏这里 = 用户在模板里配的章节样式在报告生成
// 时静默丢失, 两出口(docx/HTML)拿到的块序列与配置不符。
func TestSectionStylesApplied(t *testing.T) {
	snap := sampleSnapshot()
	st := ComputeStats(snap)
	opts := &SectionOptions{
		Order: []string{"summary", "risk", "assets", "vulns"},
		Styles: map[string]SectionStyle{
			"summary": {TitleColor: "B91C1C", TitleBg: "FEE2E2", FontColor: "1F2937", Bg: "F5F3FF", Bold: true, Size: 24},
			"vulns":   {FontColor: "0B5394"},
			// 未知 key 忽略(与 Order 向前兼容同口径), 不应 panic 也不应影响他章
			"not-a-section": {Bg: "FFFF00"},
		},
	}
	blocks := SectionBlocksWithOptions(snap, st, "", opts)

	// 1) 标题字色/底色: 落到 Heading1 的 run 上
	var sumHead, vulnHead int
	for i, b := range blocks {
		if b.Style == "Heading1" {
			switch {
			case strings.Contains(b.Text(), "总体概况"):
				sumHead = i
			case strings.Contains(b.Text(), "漏洞明细"):
				vulnHead = i
			}
		}
	}
	if sumHead < 0 || vulnHead < 0 {
		t.Fatalf("未找到章节标题: %v", blocks)
	}
	r := blocks[sumHead].Runs[0]
	if r.Color != "B91C1C" || r.Bg != "FEE2E2" {
		t.Fatalf("summary 标题样式未应用: %+v", r)
	}
	// 未设样式的章节标题保持默认(无字色)
	if blocks[vulnHead].Runs[0].Color != "" || blocks[vulnHead].Runs[0].Bg != "" {
		t.Fatalf("未设 TitleColor 的标题不应带字色: %+v", blocks[vulnHead].Runs[0])
	}

	// 2) 章节底色: 段落与表格都拿 Block.Shd
	sumBody := blocks[sumHead+1]
	if sumBody.Kind != "p" || sumBody.Shd != "F5F3FF" {
		t.Fatalf("summary 正文段落缺章节底色: %+v", sumBody)
	}
	// 正文字色/加粗/字号只作用于未显式设值的 run
	if sumBody.Runs[0].Color != "1F2937" || !sumBody.Runs[0].Bold || sumBody.Runs[0].Size != 24 {
		t.Fatalf("summary 正文格式未应用: %+v", sumBody.Runs[0])
	}

	// 3) 正文字色不冲掉自带颜色的 run: 漏洞明细"级别"列是严重度着色
	//    (报告风险视觉层级), 套了 FontColor 后必须保留原色
	var vulnsTbl int
	for i, b := range blocks {
		if b.Kind == "tbl" && i > vulnHead {
			vulnsTbl = i
			break
		}
	}
	if vulnsTbl < 0 {
		t.Fatal("未找到漏洞明细表")
	}
	tbl := blocks[vulnsTbl]
	if len(tbl.Rows) < 2 || len(tbl.Rows[1].Cells) < 2 {
		t.Fatalf("漏洞明细表不完整: %d 行", len(tbl.Rows))
	}
	sevRun := tbl.Rows[1].Cells[0].Runs[0]
	if sevRun.Color == "" || sevRun.Color == "0B5394" {
		t.Fatalf("级别列严重度着色被章节字色冲掉: %+v", sevRun)
	}
	// 其余未设色 run(标题列)应套上章节字色
	if got := tbl.Rows[1].Cells[1].Runs[0].Color; got != "0B5394" {
		t.Fatalf("漏洞明细普通单元格未套章节字色: %+v", got)
	}

	// 4) 未设样式的章节零差异: 全空 Styles 与不带 opts 的块序列完全一致
	none := SectionBlocksWithOptions(snap, st, "", &SectionOptions{
		Order:  []string{"summary", "risk", "assets", "vulns"},
		Styles: map[string]SectionStyle{},
	})
	def := SectionBlocksWithOptions(snap, st, "", &SectionOptions{
		Order: []string{"summary", "risk", "assets", "vulns"},
	})
	if a, b := mustJSON(t, none), mustJSON(t, def); a != b {
		t.Fatalf("空样式配置必须与无配置零差异:\n%s\n%s", a, b)
	}
}

// TestBlockShdRoundTrip 守"块级底纹跨 WriteDocx/ReadDocx 往返不丢"的契约:
// 可视化模板保存 = 生成 .docx, 手动上传模板 = ReadDocx 解析后重新 WriteDocx,
// 两条链路都依赖往返保真。改坏这里 = 章节底色/单元格底纹在"保存→生成"或
// "上传→生成"时静默消失, Word 里看不出配置生效。
func TestBlockShdRoundTrip(t *testing.T) {
	blocks := []Block{
		{Kind: "p", Runs: []Run{{Text: "带底纹段落"}}, Shd: "F5F3FF"},
		{Kind: "p", Style: "Heading1", Runs: []Run{{Text: "一、章节", Color: "B91C1C", Bg: "FEE2E2"}}, Shd: "EDE9FE"},
		{Kind: "tbl", Shd: "EFF6FF", Rows: []Row{{Cells: []Cell{
			{Runs: []Run{{Text: "表头", Bold: true}}, Shd: "F3F4F6"},
			{Runs: []Run{{Text: "正文格"}}, Shd: "DBEAFE"},
		}}}},
	}
	data, err := WriteDocx(blocks, DocxMeta{Title: "t"})
	if err != nil {
		t.Fatalf("WriteDocx: %v", err)
	}
	got, err := ReadDocx(data)
	if err != nil {
		t.Fatalf("ReadDocx: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("往返后块数变化: %d", len(got))
	}
	if got[0].Shd != "F5F3FF" {
		t.Fatalf("段落底纹丢失: %+v", got[0])
	}
	hr := got[1].Runs[0]
	if got[1].Shd != "EDE9FE" || hr.Color != "B91C1C" || hr.Bg != "FEE2E2" {
		t.Fatalf("标题段底纹/字符底纹丢失: %+v", got[1])
	}
	if got[2].Shd != "EFF6FF" {
		t.Fatalf("表格底色丢失: %+v", got[2])
	}
	if got[2].Rows[0].Cells[0].Shd != "F3F4F6" || got[2].Rows[0].Cells[1].Shd != "DBEAFE" {
		t.Fatalf("单元格底纹丢失: %+v", got[2].Rows[0].Cells)
	}
}

// TestBlockShdHTML 守"同一份块序列两出口观感一致"的契约: 块级底纹在 HTML
// 出口必须渲染成背景色(段落 + 表格 + 单元格), 否则 Word 里有色、HTML 里全白,
// 用户"预览/打印"看到的效果与下载的 Word 不符。
func TestBlockShdHTML(t *testing.T) {
	blocks := []Block{
		{Kind: "p", Runs: []Run{{Text: "带底纹段落"}}, Shd: "F5F3FF"},
		{Kind: "tbl", Shd: "EFF6FF", Rows: []Row{{Cells: []Cell{
			{Runs: []Run{{Text: "表头"}}, Shd: "F3F4F6"},
		}}}},
	}
	html := BlocksToHTML(blocks)
	if !strings.Contains(html, `background-color:#F5F3FF`) {
		t.Fatalf("HTML 出口缺段落底纹: %s", html)
	}
	if !strings.Contains(html, `<table style="background-color:#EFF6FF">`) {
		t.Fatalf("HTML 出口缺表格底色: %s", html)
	}
	if !strings.Contains(html, `<th style="background-color:#F3F4F6">`) {
		t.Fatalf("HTML 出口缺单元格底纹: %s", html)
	}
}

// mustJSON 块序列的确定性序列化(测试对比用)。
func mustJSON(t *testing.T, blocks []Block) string {
	t.Helper()
	b, err := json.Marshal(blocks)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(b)
}

// docxContains 在 docx zip 的 document.xml 里找子串。
func docxContains(docx []byte, sub string) bool {
	zr, err := zip.NewReader(bytes.NewReader(docx), int64(len(docx)))
	if err != nil {
		return false
	}
	for _, f := range zr.File {
		if f.Name != "word/document.xml" {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return false
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		return strings.Contains(string(data), sub)
	}
	return false
}
