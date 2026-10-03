package main

import (
	"strings"
	"testing"

	"yugsight/internal/db"
	"yugsight/internal/models"
	"yugsight/internal/report"
)

// 2026-09-26 报告中心改造的契约守卫:
//  1. 模板预览与真实生成章节口径一致(版权三态) —— 修"不勾版权预览仍显示"bug;
//  2. 多任务并集圈定(漏洞 ScanTaskID / 资产 Jobs) —— 多选任务不静默漏数据;
//  3. 存档对比按条件重建出漏洞级明细 —— 不再"只比统计"。

// TestSectionOptionsFromVisualCopyright 守"版权三态 → Skip/Replace"契约:
// nil(默认文案, 不 Skip 不 Replace) / 显式空(用户删掉, Skip) / 非空(富文本, Replace)。
// 这是修"模板预览不勾版权仍显示"bug 的核心 —— 预览与生成共用 sectionOptionsFromVisual。
func TestSectionOptionsFromVisualCopyright(t *testing.T) {
	empty := ""
	custom := "Copyright © 2026 测试"
	cases := []struct {
		name     string
		co       *string
		wantSkip bool
		wantRepl bool
	}{
		{"nil-默认文案", nil, false, false},
		{"空-不显示", &empty, true, false},
		{"自定义-富文本", &custom, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			opts := sectionOptionsFromVisual(&VisualTpl{Copyright: c.co})
			skipped := false
			for _, k := range opts.Skip {
				if k == "copyright" {
					skipped = true
				}
			}
			replaced := false
			if _, ok := opts.Replace["copyright"]; ok {
				replaced = true
			}
			if skipped != c.wantSkip {
				t.Fatalf("skip=%v, 期望 %v (Skip=%v)", skipped, c.wantSkip, opts.Skip)
			}
			if replaced != c.wantRepl {
				t.Fatalf("replace=%v, 期望 %v (Replace=%v)", replaced, c.wantRepl, opts.Replace)
			}
		})
	}
}

// TestNormalizeJobIDs 守"单值 + 多值合并去重去空"契约(多任务生成入口)。
func TestNormalizeJobIDs(t *testing.T) {
	got := normalizeJobIDs("a", []string{"b", "a", "", " c ", "c"})
	want := []string{"a", "b", "c"}
	if len(got) != len(want) {
		t.Fatalf("len=%d got=%v want=%v", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got=%v want=%v", got, want)
		}
	}
}

// TestHasAnyJob 守"资产 Jobs 与作业集合有交集"契约(多选任务取并集)。
func TestHasAnyJob(t *testing.T) {
	set := map[string]bool{"jobA": true, "jobB": true}
	if !hasAnyJob([]string{"jobC", "jobA"}, set) {
		t.Fatal("含 jobA 应命中")
	}
	if hasAnyJob([]string{"jobC", "jobD"}, set) {
		t.Fatal("都不在集合应不命中")
	}
	if hasAnyJob(nil, set) {
		t.Fatal("空 Jobs 应不命中")
	}
}

// TestStripJobPrefix 守"漏洞 ScanTaskID 去掉 job- 前缀"契约(报告按作业过滤时
// ScanTaskID 存的是 "job-<任务名>")。
func TestStripJobPrefix(t *testing.T) {
	if got := stripJobPrefix("job-任务名"); got != "任务名" {
		t.Fatalf("got=%q", got)
	}
	if got := stripJobPrefix("plain"); got != "plain" {
		t.Fatalf("无前缀应原样, got=%q", got)
	}
}

// TestReportGenerateMultiJob 守"多选任务 = 各作业结果并集"契约(端到端)。
// 若 hasAnyJob/stripJobPrefix 写错, 多任务报告会静默漏掉部分任务的漏洞 ——
// 这是"改坏会静默失效"的典型, 必须守。
func TestReportGenerateMultiJob(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	// 两个任务(登记簿 ID = 任务名)
	for _, name := range []string{"任务甲", "任务乙"} {
		j := &db.ScanJob{ID: name, Name: name, Target: "10.0.0.1", Status: db.JobStatusSuccess}
		if _, err := d.Jobs().Upsert(j); err != nil {
			t.Fatalf("seed job %s: %v", name, err)
		}
	}
	// 漏洞: 甲任务 1 条 + 乙任务 1 条(ScanTaskID="job-<任务名>")
	va := db.NewVuln("10.0.0.1", "甲任务漏洞", models.SeverityHigh)
	va.ScanTaskID = "job-任务甲"
	if _, err := d.Vulns().Upsert(va); err != nil {
		t.Fatalf("seed vuln A: %v", err)
	}
	vb := db.NewVuln("10.0.0.1", "乙任务漏洞", models.SeverityMedium)
	vb.ScanTaskID = "job-任务乙"
	if _, err := d.Vulns().Upsert(vb); err != nil {
		t.Fatalf("seed vuln B: %v", err)
	}

	// 多选两个任务: 报告应含两条(并集)
	w := doReq(t, h, "POST", "/api/v2/report/generate",
		`{"format":"html","jobIds":["任务甲","任务乙"]}`)
	if w.Code != 200 {
		t.Fatalf("generate status=%d body=%s", w.Code, w.Body.String())
	}
	id, _ := jsonPath(w.Body.String(), "report.id")
	body := doReq(t, h, "GET", "/api/v2/report/"+id+"/download", "").Body.String()
	if !strings.Contains(body, "甲任务漏洞") || !strings.Contains(body, "乙任务漏洞") {
		t.Fatalf("多任务报告应含两个任务的漏洞(并集): %.300s", body)
	}

	// 只选甲: 只含甲, 不含乙
	w2 := doReq(t, h, "POST", "/api/v2/report/generate", `{"format":"html","jobIds":["任务甲"]}`)
	id2, _ := jsonPath(w2.Body.String(), "report.id")
	body2 := doReq(t, h, "GET", "/api/v2/report/"+id2+"/download", "").Body.String()
	if !strings.Contains(body2, "甲任务漏洞") {
		t.Fatalf("只选甲应含甲的漏洞")
	}
	if strings.Contains(body2, "乙任务漏洞") {
		t.Fatalf("只选甲不应含乙的漏洞")
	}
}

// TestCompareArchiveRebuild 守"存档对比 = 按各自条件重建出漏洞级明细"契约(2026-09-26:
// 历史对比从"只比统计"升级为"按存档条件重建漏洞级对比")。若 rebuildArchiveSnapshot
// 退化回 Vulns:nil, 对比就只剩统计、看不到具体新增哪些漏洞 —— 静默失效, 必须守。
func TestCompareArchiveRebuild(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	// 两条不同 IP 的漏洞
	va := db.NewVuln("10.0.0.1", "漏洞A", models.SeverityHigh)
	if _, err := d.Vulns().Upsert(va); err != nil {
		t.Fatalf("seed A: %v", err)
	}
	vb := db.NewVuln("10.0.0.2", "漏洞B", models.SeverityMedium)
	if _, err := d.Vulns().Upsert(vb); err != nil {
		t.Fatalf("seed B: %v", err)
	}
	// 基线存档: Filter 只圈 10.0.0.1(重建时只含 A)
	baseArch, err := generateReport(d, reportRequest{Title: "基线", Filter: report.Filter{IP: "10.0.0.1"}}, "tester")
	if err != nil {
		t.Fatalf("gen base: %v", err)
	}
	if err := saveReportArchive(d, baseArch); err != nil {
		t.Fatalf("save base: %v", err)
	}
	// 目标存档: 全量(重建时含 A + B)
	tgtArch, err := generateReport(d, reportRequest{Title: "目标"}, "tester")
	if err != nil {
		t.Fatalf("gen target: %v", err)
	}
	if err := saveReportArchive(d, tgtArch); err != nil {
		t.Fatalf("save target: %v", err)
	}

	// 存档对比: 应出漏洞级 diff(新增漏洞B, A 仍存在), 而非"只比统计"
	w := doReq(t, h, "POST", "/api/v2/report/compare",
		`{"baseId":"`+baseArch.ID+`","targetId":"`+tgtArch.ID+`"}`)
	if w.Code != 200 {
		t.Fatalf("compare status=%d body=%s", w.Code, w.Body.String())
	}
	body := w.Body.String()
	if !strings.Contains(body, `"mode":"archive"`) {
		t.Fatalf("应为 archive 模式: %.300s", body)
	}
	if !strings.Contains(body, "漏洞B") {
		t.Fatalf("存档对比应含漏洞级明细(新增漏洞B): %.300s", body)
	}
}
