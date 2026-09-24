package report

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// mkRaw 构造一份最小原始报告(测试用)。
func mkRaw(t *testing.T, module, id string, assets []string, tags []string, items int, when time.Time) *RawReport {
	t.Helper()
	p, err := json.Marshal(map[string]any{"module": module, "n": items})
	if err != nil {
		t.Fatal(err)
	}
	return &RawReport{
		ID:        id,
		Module:    module,
		Title:     module + "报告-" + id,
		CreatedAt: when,
		Assets:    assets,
		Tags:      tags,
		Stats:     RawStats{Items: items},
		Payload:   p,
	}
}

// TestMergeGroupsByModule 合并契约: 按模块分组(固定顺序) / 资产并集 / 标签并集 /
// SourceIDs / 统计加法 —— 这些都是"改坏会静默产生错误汇总"的口径。
func TestMergeGroupsByModule(t *testing.T) {
	base := time.Date(2026, 9, 23, 10, 0, 0, 0, time.Local)
	r1 := mkRaw(t, RawModScan, "rr-a", []string{"10.0.0.1"}, []string{"日常"}, 3, base)
	r2 := mkRaw(t, RawModCapture, "rr-b", []string{"10.0.0.2"}, []string{"专项"}, 100, base.Add(time.Hour))
	r3 := mkRaw(t, RawModScan, "rr-c", []string{"10.0.0.1", "10.0.0.3"}, nil, 5, base.Add(2*time.Hour))

	m, err := MergeRawReports([]*RawReport{r3, r1, r2}, "合并-测试", []string{"周汇总"}, "admin")
	if err != nil {
		t.Fatalf("merge: %v", err)
	}
	if m.Module != RawModMerged || m.Operator != "admin" {
		t.Fatalf("module=%s op=%s", m.Module, m.Operator)
	}
	if len(m.SourceIDs) != 3 {
		t.Fatalf("sourceIds=%v", m.SourceIDs)
	}
	// 资产并集去重: 10.0.0.1 出现两次只留一个
	wantAssets := map[string]bool{"10.0.0.1": true, "10.0.0.2": true, "10.0.0.3": true}
	if len(m.Assets) != 3 {
		t.Fatalf("assets=%v", m.Assets)
	}
	for _, ip := range m.Assets {
		if !wantAssets[ip] {
			t.Fatalf("多余资产 %s", ip)
		}
	}
	// 标签并集: 用户标签在前
	if len(m.Tags) != 3 || m.Tags[0] != "周汇总" {
		t.Fatalf("tags=%v", m.Tags)
	}
	// 统计: 条目加法 + 各模块计数
	if m.Stats.Items != 108 {
		t.Fatalf("items=%d, 期望 108", m.Stats.Items)
	}
	if m.Stats.ByModule[RawModScan] != 2 || m.Stats.ByModule[RawModCapture] != 1 {
		t.Fatalf("byModule=%v", m.Stats.ByModule)
	}
	if !strings.Contains(m.Summary, "扫描作业 2") || !strings.Contains(m.Summary, "实时抓包 1") {
		t.Fatalf("summary=%s", m.Summary)
	}

	// 正文结构: sections 按固定模块顺序(capture 在 scan 前), 各章报告数正确
	var mp mergedPayload
	if err := json.Unmarshal(m.Payload, &mp); err != nil {
		t.Fatalf("payload 解析: %v", err)
	}
	if len(mp.Sections) != 2 {
		t.Fatalf("sections=%d, 期望 2", len(mp.Sections))
	}
	if mp.Sections[0].Module != RawModCapture || mp.Sections[0].Count != 1 {
		t.Fatalf("section[0]=%+v (应按模块固定顺序, capture 在前)", mp.Sections[0])
	}
	if mp.Sections[1].Module != RawModScan || mp.Sections[1].Count != 2 {
		t.Fatalf("section[1]=%+v", mp.Sections[1])
	}
	// 同模块内按时间升序: rr-a(10:00) 在 rr-c(12:00) 前
	var first json.RawMessage
	_ = json.Unmarshal(mp.Sections[1].Reports[0], &first)
	if !strings.Contains(string(first), `"module":"scan"`) {
		t.Fatalf("scan 章节原文应照搬源报告正文: %s", first)
	}
	if len(mp.MergedFrom) != 3 {
		t.Fatalf("mergedFrom=%d, 期望 3", len(mp.MergedFrom))
	}
}

// TestMergeRejectsDegenerate 少于 2 份有效报告(含重复 ID/nil)应拒绝,
// 而不是静默透传单份。
func TestMergeRejectsDegenerate(t *testing.T) {
	base := time.Now()
	r1 := mkRaw(t, RawModScan, "rr-1", nil, nil, 1, base)
	if _, err := MergeRawReports([]*RawReport{r1}, "", nil, ""); err == nil {
		t.Fatal("单份合并应报错")
	}
	// 两份但同 ID(去重后只剩 1 份)
	if _, err := MergeRawReports([]*RawReport{r1, r1, nil}, "", nil, ""); err == nil {
		t.Fatal("重复 ID 去重后不足 2 份应报错")
	}
}

// TestMergePayloadSizeGuard 大正文合并超限应报错(防 JSONL 单行膨胀)。
func TestMergePayloadSizeGuard(t *testing.T) {
	big := make(json.RawMessage, RawPayloadMaxSize/2+1)
	r1 := &RawReport{ID: "rr-big1", Module: RawModScan, Title: "大", CreatedAt: time.Now(), Payload: big}
	r2 := &RawReport{ID: "rr-big2", Module: RawModCapture, Title: "大", CreatedAt: time.Now(), Payload: big}
	if _, err := MergeRawReports([]*RawReport{r1, r2}, "", nil, ""); err == nil {
		t.Fatal("两半上限的正文合并应超限报错")
	}
}

// TestRawReportValidateDefaults 缺省补全与必填校验。
func TestRawReportValidateDefaults(t *testing.T) {
	// module 必填(报告中心按模块归类的核心维度)
	if err := (&RawReport{}).Validate(); err == nil {
		t.Fatal("缺 module 应报错")
	}
	r := &RawReport{Module: "  scan ", CreatedAt: time.Time{}}
	if err := r.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	if r.Module != "scan" || r.Title == "" || r.CreatedAt.IsZero() {
		t.Fatalf("缺省补全: %+v", r)
	}
	// 正文超限
	r2 := &RawReport{Module: RawModScan, Payload: make(json.RawMessage, RawPayloadMaxSize+1)}
	if err := r2.Validate(); err == nil {
		t.Fatal("正文超限应报错")
	}
}

// TestRawModuleLabel 未知模块原样返回(新模块先于中心端升级时不丢数据)。
func TestRawModuleLabel(t *testing.T) {
	if RawModuleLabel(RawModMerged) != "合并报告" {
		t.Fatal("merged 标签")
	}
	if RawModuleLabel("future-mod") != "future-mod" {
		t.Fatal("未知模块应原样返回")
	}
	if !IsKnownRawModule(RawModWeakPass) || IsKnownRawModule("nope") {
		t.Fatal("IsKnownRawModule 口径")
	}
}
