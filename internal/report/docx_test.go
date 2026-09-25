package report

import (
	"archive/zip"
	"bytes"
	"encoding/xml"
	"io"
	"strings"
	"testing"
	"time"

	"yugsight/internal/models"
)

// TestDocxRoundTrip docx 写出→读回, 文本/样式/对齐/表格结构不丢。
//
// 契约价值: 模板"上传→生成→再解析"整条链路的保真度; 若写出侧 XML 有缺漏
// (如漏 pStyle), 用户模板里的章节标题在生成物里会静默降级为正文。
func TestDocxRoundTrip(t *testing.T) {
	blocks := []Block{
		{Kind: "p", Style: "Title", Align: "center", Runs: []Run{{Text: "测试报告", Size: 44}}},
		{Kind: "p", Runs: []Run{{Text: "普通段 "}, {Text: "加粗部分", Bold: true}}},
		{Kind: "p", Style: "Heading1", Runs: []Run{{Text: "章节一"}}},
		{Kind: "tbl", Rows: []Row{
			{Cells: []Cell{{Runs: []Run{{Text: "列A", Bold: true}}}, {Runs: []Run{{Text: "列B", Bold: true}}}}},
			{Cells: []Cell{{Runs: []Run{{Text: "1"}}}, {Runs: []Run{{Text: "2&<3>"}}}}},
		}},
	}
	data, err := WriteDocx(blocks, DocxMeta{Title: "测试", Author: "tester"})
	if err != nil {
		t.Fatalf("WriteDocx: %v", err)
	}
	got, err := ReadDocx(data)
	if err != nil {
		t.Fatalf("ReadDocx: %v", err)
	}
	if len(got) != 4 {
		t.Fatalf("块数量: 期望 4, 实际 %d", len(got))
	}
	// 标题段
	if got[0].Style != "Title" || got[0].Align != "center" || got[0].Text() != "测试报告" {
		t.Errorf("标题段不保真: %+v", got[0])
	}
	if got[0].Runs[0].Size != 44 {
		t.Errorf("字号不保真: %d", got[0].Runs[0].Size)
	}
	// 普通段: run 拼接
	if got[1].Text() != "普通段 加粗部分" {
		t.Errorf("普通段文本: %q", got[1].Text())
	}
	if !got[1].Runs[1].Bold {
		t.Errorf("加粗 run 不保真: %+v", got[1].Runs[1])
	}
	// 章节
	if got[2].Style != "Heading1" || got[2].Text() != "章节一" {
		t.Errorf("章节段不保真: %+v", got[2])
	}
	// 表格
	if got[3].Kind != "tbl" || len(got[3].Rows) != 2 {
		t.Fatalf("表格不保真: %+v", got[3])
	}
	if got[3].Rows[1].Cells[1].Text() != "2&<3>" {
		t.Errorf("表格转义不保真: %q", got[3].Rows[1].Cells[1].Text())
	}
}

// TestWriteDocxStructure 产物是合法 zip 且必需部件齐全, document.xml 可解析 ——
// 任一缺失 Word 都会报"文件已损坏"(用户现象: 下载下来打不开)。
func TestWriteDocxStructure(t *testing.T) {
	data, err := WriteDocx([]Block{{Kind: "p", Runs: []Run{{Text: "x"}}}}, DocxMeta{})
	if err != nil {
		t.Fatalf("WriteDocx: %v", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("产物不是合法 zip: %v", err)
	}
	var names []string
	for _, f := range zr.File {
		names = append(names, f.Name)
	}
	for _, want := range []string{"[Content_Types].xml", "_rels/.rels", "word/document.xml", "word/styles.xml", "docProps/core.xml"} {
		if !contains(names, want) {
			t.Errorf("缺少必需部件 %s: %v", want, names)
		}
	}
	// document.xml 必须是合法 XML
	var docData []byte
	for _, f := range zr.File {
		if f.Name == "word/document.xml" {
			rc, _ := f.Open()
			docData, _ = readAllRC(rc)
			rc.Close()
		}
	}
	if docData == nil {
		t.Fatal("未找到 word/document.xml")
	}
	var probe struct {
		XMLName xml.Name
	}
	if err := xml.Unmarshal(docData, &probe); err != nil {
		t.Fatalf("document.xml 非法 XML: %v", err)
	}
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func readAllRC(rc io.Reader) ([]byte, error) {
	return io.ReadAll(rc)
}

// TestReadDocxRejectsNonDocx 垃圾文件/非 docx zip 必须报错(上传校验依赖它)。
func TestReadDocxRejectsNonDocx(t *testing.T) {
	if _, err := ReadDocx([]byte("not a zip")); err == nil {
		t.Fatal("垃圾字节应被拒绝")
	}
	// 合法 zip 但没有 word/document.xml
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	f, _ := zw.Create("readme.txt")
	f.Write([]byte("hi"))
	zw.Close()
	if _, err := ReadDocx(buf.Bytes()); err == nil {
		t.Fatal("无 document.xml 的 zip 应被拒绝")
	}
}

// TestReplacePlaceholdersSplitRuns Word 会把 "{{title}}" 拆到多个 run ——
// 必须"整段拼接后再替换", 否则真实模板上占位符永远替换不掉(静默残留 {{...}})。
func TestReplacePlaceholdersSplitRuns(t *testing.T) {
	blocks := []Block{
		{Kind: "p", Runs: []Run{{Text: "报告: {{"}, {Text: "title}} 生成于"}}},
		{Kind: "p", Runs: []Run{{Text: "无占位符段落(含 { 单括号)"}}},
	}
	got := ReplacePlaceholders(blocks, map[string]string{"title": "季度安全报告"})
	if got[0].Text() != "报告: 季度安全报告 生成于" {
		t.Fatalf("拆分 run 的占位符未替换: %q", got[0].Text())
	}
	if got[1].Text() != "无占位符段落(含 { 单括号)" {
		t.Fatalf("无占位符段被误改: %q", got[1].Text())
	}
}

// TestInsertSections 章节注入: 有标记替换标记段, 无标记追加到文末。
func TestInsertSections(t *testing.T) {
	tpl := []Block{
		{Kind: "p", Runs: []Run{{Text: "封面"}}},
		{Kind: "p", Runs: []Run{{Text: ContentMarker}}},
		{Kind: "p", Runs: []Run{{Text: "尾页"}}},
	}
	sections := []Block{{Kind: "p", Runs: []Run{{Text: "章节A"}}}}
	got := InsertSections(tpl, sections)
	// 标记段被替换为章节: [封面, 章节A, 尾页]
	if len(got) != 3 || got[1].Text() != "章节A" {
		t.Fatalf("标记注入位置错误: %v", gotTexts(got))
	}
	if got[0].Text() != "封面" || got[2].Text() != "尾页" {
		t.Fatalf("标记注入破坏前后内容: %v", gotTexts(got))
	}
	// 无标记: 追加文末
	noMark := []Block{{Kind: "p", Runs: []Run{{Text: "封面"}}}}
	got2 := InsertSections(noMark, sections)
	if len(got2) != 2 || got2[1].Text() != "章节A" {
		t.Fatalf("无标记应追加文末: %v", gotTexts(got2))
	}
}

func gotTexts(blocks []Block) []string {
	out := make([]string, len(blocks))
	for i, b := range blocks {
		out[i] = b.Text()
	}
	return out
}

// TestBuiltinWordTemplate 内置模板必须含章节注入标记与封面占位符 ——
// 它是一切"不上传模板"场景的默认来源, 缺标记会导致章节永远追加到页尾之外。
func TestBuiltinWordTemplate(t *testing.T) {
	blocks := BuiltinWordTemplate()
	var hasMarker, hasTitle, hasTime bool
	for _, b := range blocks {
		txt := b.Text()
		if strings.Contains(txt, ContentMarker) {
			hasMarker = true
		}
		if strings.Contains(txt, "{{title}}") {
			hasTitle = true
		}
		if strings.Contains(txt, "{{time}}") {
			hasTime = true
		}
	}
	if !hasMarker || !hasTitle || !hasTime {
		t.Fatalf("内置模板缺关键元素: marker=%v title=%v time=%v", hasMarker, hasTitle, hasTime)
	}
}

// sampleSnapshot 报告测试共用样例: 2 资产 3 漏洞(严重/高/低), 含端口。
func sampleSnapshot() *Snapshot {
	now := time.Now()
	return &Snapshot{
		Title: "样例报告", Operator: "tester", Tool: "Yugsight v1.0",
		CreatedAt: now,
		Assets: []*models.Asset{
			{IP: "192.168.1.10", Hostname: "web-01", OS: "Windows Server 2022", Alive: true,
				Ports: []int{80, 443}, Service: "http"},
			{IP: "192.168.1.11", Alive: false},
		},
		Vulns: []*models.Vuln{
			{ID: "v1", AssetIP: "192.168.1.10", Port: 443, Protocol: "https",
				Severity: models.SeverityCritical, Title: "严重漏洞甲", CVE: "CVE-2026-0001",
				Confidence: 100, Status: "new", FoundAt: now},
			{ID: "v2", AssetIP: "192.168.1.10", Port: 80, Protocol: "http",
				Severity: models.SeverityHigh, Title: "高危漏洞乙",
				Confidence: 75, Status: "fixed", FoundAt: now},
			{ID: "v3", AssetIP: "192.168.1.11",
				Severity: models.SeverityLow, Title: "低危漏洞丙",
				Confidence: 30, Status: "new", FoundAt: now},
		},
		Scans: []ScanInfo{
			{Target: "192.168.1.0/24", Type: "port", Status: "success", CreatedAt: now},
		},
	}
}

// TestSectionBlocks 章节内容契约: 漏洞按严重度排序(严重在前)、资产风险标注、
// 等级分布合计正确 —— 若排序/计数被改坏, 报告首屏数据静默错乱。
func TestSectionBlocks(t *testing.T) {
	snap := sampleSnapshot()
	st := ComputeStats(snap)
	blocks := SectionBlocks(snap, st, "免责: 样例")

	var headings []string
	var vulnTable *Block
	var assetTable *Block
	var distTable *Block
	for i, b := range blocks {
		if b.Style == "Heading1" {
			headings = append(headings, b.Text())
		}
		if b.Kind == "tbl" {
			hdr := b.Rows[0].Cells[0].Text()
			switch hdr {
			case "级别":
				vulnTable = &blocks[i]
			case "IP":
				assetTable = &blocks[i]
			case "等级":
				distTable = &blocks[i]
			}
		}
	}
	for _, want := range []string{"一、总体概况", "二、风险等级分布", "三、资产清单", "四、漏洞明细"} {
		if !contains(headings, want) {
			t.Fatalf("缺章节 %s: %v", want, headings)
		}
	}
	if vulnTable == nil || len(vulnTable.Rows) != 4 { // 表头 + 3 条
		t.Fatalf("漏洞表行数错误: %+v", vulnTable)
	}
	if vulnTable.Rows[1].Cells[1].Text() != "严重漏洞甲" {
		t.Errorf("漏洞未按严重度排序: 首行=%q", vulnTable.Rows[1].Cells[1].Text())
	}
	if vulnTable.Rows[1].Cells[7].Text() != "未修复" || vulnTable.Rows[2].Cells[7].Text() != "已修复" {
		t.Errorf("状态标注错误: %q / %q", vulnTable.Rows[1].Cells[7].Text(), vulnTable.Rows[2].Cells[7].Text())
	}
	if assetTable == nil || len(assetTable.Rows) != 3 { // 表头 + 2 资产
		t.Fatalf("资产表行数错误: %+v", assetTable)
	}
	if assetTable.Rows[1].Cells[6].Text() != "严重" {
		t.Errorf("资产风险标注错误: %q", assetTable.Rows[1].Cells[6].Text())
	}
	if distTable == nil || distTable.Rows[1].Cells[1].Text() != "1" {
		t.Errorf("等级分布严重数错误: %+v", distTable)
	}
	// 免责声明末段
	last := blocks[len(blocks)-1]
	if !strings.Contains(last.Text(), "免责: 样例") {
		t.Errorf("免责声明缺失: %q", last.Text())
	}
}

// TestBlocksToHTMLEscapes 数据里的 HTML 特殊字符必须转义 ——
// 资产/漏洞标题来自外部输入, 不转义则报告 HTML 可被注入脚本。
func TestBlocksToHTMLEscapes(t *testing.T) {
	cellA := Cell{Runs: []Run{{Text: "<img src=x>"}}}
	cellB := Cell{Runs: []Run{{Text: "正常"}}}
	blocks := []Block{
		{Kind: "p", Runs: []Run{{Text: `<script>alert(1)</script> & "引号"`}}},
		{Kind: "tbl", Rows: []Row{{Cells: []Cell{cellA, cellB}}}},
	}
	html := BlocksToHTML(blocks)
	if strings.Contains(html, "<script>alert") || strings.Contains(html, "<img src=x>") {
		t.Fatalf("HTML 未转义:\n%s", html)
	}
	if !strings.Contains(html, "&lt;script&gt;") {
		t.Fatalf("应含转义实体: %s", html)
	}
}

// TestRenderWordReport 完整 HTML 文档: 自包含(无外部资源) + 页眉页脚 + 正文。
func TestRenderWordReport(t *testing.T) {
	snap := sampleSnapshot()
	st := ComputeStats(snap)
	tpl := BuiltinWordTemplate()
	values := PlaceholderValues(snap, st)
	full := report2Blocks(tpl, snap, st, values)
	page := WordPage{Title: snap.Title, Header: ExpandHeaderValues(DefaultHeader(), values), Accent: "#4f46e5"}
	html := RenderWordReport(full, page)
	for _, want := range []string{"<!DOCTYPE html>", "text-align:center", "一、总体概况", "严重漏洞甲", "print-header"} {
		if !strings.Contains(html, want) {
			t.Errorf("HTML 缺 %q", want)
		}
	}
	if strings.Contains(html, "http://") || strings.Contains(html, "https://") {
		t.Errorf("自包含 HTML 不应引用外部资源")
	}
	// 占位符已展开
	if strings.Contains(html, "{{title}}") || strings.Contains(html, ContentMarker) {
		t.Errorf("占位符未展开干净")
	}
}

func report2Blocks(tpl []Block, snap *Snapshot, st SnapshotStats, values map[string]string) []Block {
	full := InsertSections(tpl, SectionBlocks(snap, st, ""))
	return ReplacePlaceholders(full, values)
}
