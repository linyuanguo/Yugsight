package report

import (
	"strings"
	"testing"
	"time"

	"yugsight/models"
)

// TestRenderPentaSection 阶段 5 整合报告: 有渗透验证数据时渲染"渗透验证结果"
// 章节(含三态结论与风险定级), 无数据时章节整体不出现(编号不错位)。
func TestRenderPentaSection(t *testing.T) {
	snap := &Snapshot{
		Title:     "测试报告",
		CreatedAt: time.Now(),
		Penta: []PentaEntry{
			{
				TaskID: "pt_1", Target: "10.0.0.5", Title: "Redis 未授权访问",
				CVE: "CVE-1", Exploitability: "exploitable", RiskLevel: "critical",
				Summary: "验证命中", Operator: "admin", VerifiedAt: time.Now(),
			},
			{
				TaskID: "pt_2", Target: "10.0.0.6", Title: "目录列举",
				Exploitability: "not_exploitable", RiskLevel: "low",
				Operator: "admin", VerifiedAt: time.Now(),
			},
		},
	}
	stats := ComputeStats(snap)
	html, err := Render(snap, stats, DefaultHeader(), nil)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{"渗透验证结果", "可利用", "不可利用", "10.0.0.5", "验证命中"} {
		if !strings.Contains(html, want) {
			t.Fatalf("报告缺少 %q", want)
		}
	}

	// 无渗透数据: 章节不出现(否则模板里手写编号会错位成"0、渗透验证结果")
	snap2 := &Snapshot{Title: "测试报告 2", CreatedAt: time.Now()}
	html2, err := Render(snap2, ComputeStats(snap2), DefaultHeader(), nil)
	if err != nil {
		t.Fatalf("render2: %v", err)
	}
	if strings.Contains(html2, "渗透验证结果") {
		t.Fatal("无渗透数据时不应渲染渗透验证章节")
	}
}

// TestSectionBlocksPenta Word 报告(默认交付格式)必须包含渗透验证章节 ——
// 这条容易被漏: report/render.go 是旧 HTML 路径, 实际报告中心默认走 Word
// 渲染(SectionBlocks), 只改 theme.go 用户根本看不到整合章节。
func TestSectionBlocksPenta(t *testing.T) {
	now := time.Now()
	newSnap := func(penta []PentaEntry) *Snapshot {
		return &Snapshot{
			CreatedAt: now,
			Penta:     penta,
			Scans:     []ScanInfo{{ID: "sc1", Target: "10.0.0.0/24", Type: "port", Status: "done", CreatedAt: now}},
		}
	}
	headings := func(s *Snapshot) []string {
		var out []string
		for _, b := range SectionBlocks(s, ComputeStats(s), "") {
			if b.Kind == "p" && b.Style == "Heading1" && len(b.Runs) > 0 {
				out = append(out, b.Runs[0].Text)
			}
		}
		return out
	}
	tableByFirstHeader := func(s *Snapshot, key string) *Block {
		blocks := SectionBlocks(s, ComputeStats(s), "")
		for i := range blocks {
			if blocks[i].Kind != "tbl" || len(blocks[i].Rows) == 0 || len(blocks[i].Rows[0].Cells) == 0 {
				continue
			}
			if strings.TrimSpace(blocks[i].Rows[0].Cells[0].Text()) == key {
				return &blocks[i]
			}
		}
		return nil
	}

	// 有渗透数据: 章节插入在漏洞明细之后, 后续编号顺延(不跳号)
	penta := []PentaEntry{{
		Target: "10.0.0.5", Title: "Redis 未授权访问", CVE: "CVE-1",
		Exploitability: "exploitable", RiskLevel: "critical",
		Summary: "验证命中", Operator: "admin", VerifiedAt: now,
	}}
	s1 := newSnap(penta)
	hs := headings(s1)
	want := []string{"一、总体概况", "二、风险等级分布", "三、资产清单", "四、漏洞明细", "五、渗透验证结果", "六、扫描范围"}
	if len(hs) != len(want) {
		t.Fatalf("章节=%v 期望 %v", hs, want)
	}
	for i := range want {
		if hs[i] != want[i] {
			t.Fatalf("章节[%d]=%q 期望 %q", i, hs[i], want[i])
		}
	}
	tbl := tableByFirstHeader(s1, "目标")
	if tbl == nil {
		t.Fatal("未渲染渗透验证结果表")
	}
	row := tbl.Rows[1]
	if row.Cells[0].Text() != "10.0.0.5" || row.Cells[3].Text() != "可利用" || row.Cells[4].Text() != "严重" {
		t.Fatalf("渗透行内容错误: target=%s verdict=%s level=%s",
			row.Cells[0].Text(), row.Cells[3].Text(), row.Cells[4].Text())
	}

	// 无渗透数据: 章节整体不出现, 扫描范围直接顺位到五(编号连续)
	hs2 := headings(newSnap(nil))
	if len(hs2) != 5 || hs2[4] != "五、扫描范围" {
		t.Fatalf("无渗透数据时章节应连续: %v", hs2)
	}

	// 漏洞明细表新增"渗透验证"列(values from vuln pentaResult);
	// 未验证的漏洞显示 "-", 已回传的显示中文结论。
	vulnSnap := newSnap(nil)
	vulnSnap.Vulns = []*models.Vuln{
		{ID: "v1", AssetIP: "10.0.0.5", Severity: "high", Status: "new", Title: "已验证漏洞", PentaResult: "partial"},
		{ID: "v2", AssetIP: "10.0.0.6", Severity: "low", Status: "new", Title: "未验证漏洞"},
	}
	vt := tableByFirstHeader(vulnSnap, "级别")
	if vt == nil {
		t.Fatal("未渲染漏洞明细表")
	}
	if got := vt.Rows[0].Cells[9].Text(); got != "渗透验证" {
		t.Fatalf("表头第 10 列=%q 期望 渗透验证", got)
	}
	if got := vt.Rows[1].Cells[9].Text(); got != "部分利用" {
		t.Fatalf("已回传漏洞的验证列=%q 期望 部分利用", got)
	}
	if got := vt.Rows[2].Cells[9].Text(); got != "-" {
		t.Fatalf("未验证漏洞的验证列=%q 期望 -", got)
	}
}

// TestFilterPenta 报告筛选: 渗透记录与资产同口径(IP/网段维度), 不按风险等级过滤。
func TestFilterPenta(t *testing.T) {
	snap := &Snapshot{
		CreatedAt: time.Now(),
		Penta: []PentaEntry{
			{Target: "10.0.0.5", Exploitability: "exploitable", RiskLevel: "critical", VerifiedAt: time.Now()},
			{Target: "192.168.1.9", Exploitability: "partial", VerifiedAt: time.Now()},
		},
	}
	// IP 维度: 只留 10.0.0.5
	f := Filter{IP: "10.0.0.5"}
	out, _ := f.Apply(snap)
	if len(out.Penta) != 1 || out.Penta[0].Target != "10.0.0.5" {
		t.Fatalf("IP 筛选: %+v", out.Penta)
	}
	// CIDR 维度
	f = Filter{CIDR: "192.168.0.0/16"}
	out, _ = f.Apply(snap)
	if len(out.Penta) != 1 || out.Penta[0].Target != "192.168.1.9" {
		t.Fatalf("CIDR 筛选: %+v", out.Penta)
	}
	// 风险等级维度: 渗透记录不受影响(与资产口径一致)
	f = Filter{Severity: []string{"critical"}}
	out, _ = f.Apply(snap)
	if len(out.Penta) != 2 {
		t.Fatalf("风险筛选不应过滤渗透记录: %+v", out.Penta)
	}
}
