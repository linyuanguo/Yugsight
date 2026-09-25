package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/report"
)

// newRawTestEnv 原始报告测试环境: v2 测试库 + 报告配置(防真实配置干扰)。
func newRawTestEnv(t *testing.T) (http.Handler, *db.Database) {
	t.Helper()
	h, d := newV2TestEnv(t)
	setReportConfig(ReportConfig{Enabled: true, MaxRaw: 500})
	t.Cleanup(func() { resetReportConfigForTest() })
	return h, d
}

// seedRaw 直接向测试库写入一份原始报告(模拟业务模块的自动存档)。
func seedRaw(t *testing.T, d *db.Database, module, title string, assets, tags []string, createdAt time.Time) *report.RawReport {
	t.Helper()
	rr := &report.RawReport{
		Module:    module,
		Title:     title,
		CreatedAt: createdAt,
		Assets:    assets,
		Tags:      tags,
		Stats:     report.RawStats{Items: 3},
		Payload:   json.RawMessage(`{"module":"` + module + `","n":3}`),
	}
	if err := saveRawReport(d, rr); err != nil {
		t.Fatalf("seed %s: %v", title, err)
	}
	return rr
}

// rawListItems 调列表接口, 返回 (条目, total)。
func rawListItems(t *testing.T, h http.Handler, query string) ([]map[string]any, int) {
	t.Helper()
	w := doReq(t, h, "GET", "/api/v2/raw/list?"+query, "")
	if w.Code != http.StatusOK {
		t.Fatalf("list?%s: %d %s", query, w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			List  []map[string]any `json:"list"`
			Total int              `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.List == nil {
		resp.Data.List = []map[string]any{}
	}
	return resp.Data.List, resp.Data.Total
}

// TestRawReportListFilters 列表契约: 时间倒序 + 五个筛选维度(模块/标签/资产/
// 时间/关键字)—— 报告中心的核心检索能力, 改坏会让前端"筛选没反应"。
func TestRawReportListFilters(t *testing.T) {
	h, d := newRawTestEnv(t)
	base := time.Date(2026, 9, 23, 9, 0, 0, 0, time.Local)
	seedRaw(t, d, report.RawModScan, "扫描报告A", []string{"10.0.0.1"}, []string{"日常"}, base)
	seedRaw(t, d, report.RawModCapture, "抓包报告B", []string{"10.0.0.2"}, []string{"专项"}, base.Add(time.Hour))
	seedRaw(t, d, report.RawModWeakPass, "弱口令报告C", []string{"10.0.0.1", "10.0.0.3"}, []string{"专项"}, base.Add(2*time.Hour))

	// 全量: 3 条且时间倒序(最晚的 C 在前)
	items, total := rawListItems(t, h, "")
	if total != 3 || len(items) != 3 {
		t.Fatalf("total=%d len=%d", total, len(items))
	}
	if items[0]["title"] != "弱口令报告C" {
		t.Fatalf("倒序第一条=%v", items[0]["title"])
	}

	// 模块筛选
	if items, total := rawListItems(t, h, "module=scan"); total != 1 || items[0]["title"] != "扫描报告A" {
		t.Fatalf("module=scan: %d %v", total, items)
	}
	// 标签筛选
	if _, total := rawListItems(t, h, "tag=专项"); total != 2 {
		t.Fatalf("tag=专项: total=%d", total)
	}
	// 资产筛选(子串容错: 输段前缀也能命中)
	if _, total := rawListItems(t, h, "asset=10.0.0.2"); total != 1 {
		t.Fatalf("asset=10.0.0.2: total=%d", total)
	}
	if _, total := rawListItems(t, h, "asset=10.0.0."); total != 3 {
		t.Fatalf("asset=10.0.0.: total=%d", total)
	}
	// 时间筛选: 当天含 3 条; 前一天 0 条
	if _, total := rawListItems(t, h, "from=2026-09-23&to=2026-09-23"); total != 3 {
		t.Fatalf("date range: total=%d", total)
	}
	if _, total := rawListItems(t, h, "to=2026-09-22"); total != 0 {
		t.Fatalf("to=2026-09-22: total=%d", total)
	}
	// 关键字(标题)
	if _, total := rawListItems(t, h, "keyword=抓包"); total != 1 {
		t.Fatalf("keyword: total=%d", total)
	}
	// 列表不回传 payload(轻量口径, 大体量正文只在详情接口出现)
	if _, ok := items[0]["payload"]; ok {
		t.Fatal("列表不应回传 payload")
	}
}

// TestRawReportDetailDelete 详情(含完整 payload)与删除。
func TestRawReportDetailDelete(t *testing.T) {
	h, d := newRawTestEnv(t)
	base := time.Date(2026, 9, 23, 9, 0, 0, 0, time.Local)
	rr := seedRaw(t, d, report.RawModScan, "详情测试", []string{"10.0.0.9"}, nil, base)

	w := doReq(t, h, "GET", "/api/v2/raw/"+rr.ID, "")
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"payload"`) {
		t.Fatalf("detail: %d %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "GET", "/api/v2/raw/rr-not-exist", "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("不存在应 404: %d", w.Code)
	}

	w = doReq(t, h, "DELETE", "/api/v2/raw/"+rr.ID, "")
	if w.Code != http.StatusOK {
		t.Fatalf("delete: %d %s", w.Code, w.Body.String())
	}
	if w := doReq(t, h, "GET", "/api/v2/raw/"+rr.ID, ""); w.Code != http.StatusNotFound {
		t.Fatalf("删除后应 404: %d", w.Code)
	}
}

// TestRawReportMerge 合并契约(API 层): 多模块合并 → 新合并报告, 源报告不删,
// SourceIDs 可下钻, 资产并集 —— 与 report.MergeRawReports 的纯函数契约互补
// (这里守住"接口层拿到的是库里真实记录"这条链)。
func TestRawReportMerge(t *testing.T) {
	h, d := newRawTestEnv(t)
	base := time.Date(2026, 9, 23, 9, 0, 0, 0, time.Local)
	r1 := seedRaw(t, d, report.RawModScan, "扫描1", []string{"10.0.0.1"}, []string{"日常"}, base)
	r2 := seedRaw(t, d, report.RawModCapture, "抓包1", []string{"10.0.0.2"}, []string{"专项"}, base.Add(time.Hour))

	body := `{"ids":["` + r1.ID + `","` + r2.ID + `"],"title":"合并测试","tags":["周汇总"]}`
	w := doReq(t, h, "POST", "/api/v2/raw/merge", body)
	if w.Code != http.StatusOK {
		t.Fatalf("merge: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID     string         `json:"id"`
			Report map[string]any `json:"report"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if resp.Data.ID == "" || resp.Data.Report["module"] != report.RawModMerged {
		t.Fatalf("merged: %+v", resp.Data)
	}
	// SourceIDs 下钻引用
	sids, _ := resp.Data.Report["sourceIds"].([]any)
	if len(sids) != 2 {
		t.Fatalf("sourceIds=%v", sids)
	}

	// 详情: 正文 sections 按模块分组 + 资产并集
	w = doReq(t, h, "GET", "/api/v2/raw/"+resp.Data.ID, "")
	var detWrap struct {
		Data struct {
			Module  string          `json:"module"`
			Assets  []string        `json:"assets"`
			Payload json.RawMessage `json:"payload"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &detWrap); err != nil {
		t.Fatalf("detail decode: %v", err)
	}
	det := detWrap.Data
	if det.Module != report.RawModMerged || len(det.Assets) != 2 {
		t.Fatalf("merged detail: %+v", det)
	}
	var mp struct {
		Sections []struct {
			Module  string            `json:"module"`
			Count   int               `json:"count"`
			Reports []json.RawMessage `json:"reports"`
		} `json:"sections"`
	}
	if err := json.Unmarshal(det.Payload, &mp); err != nil || len(mp.Sections) != 2 {
		t.Fatalf("sections: %v %+v", err, mp.Sections)
	}
	if mp.Sections[0].Module != report.RawModCapture || mp.Sections[1].Module != report.RawModScan {
		t.Fatalf("sections 顺序: %+v", mp.Sections)
	}

	// 源报告未被合并消耗(列表共 3 条: 2 源 + 1 合并)
	if _, total := rawListItems(t, h, ""); total != 3 {
		t.Fatalf("合并后总数=%d, 期望 3(源报告不删)", total)
	}
	if _, total := rawListItems(t, h, "module=merged"); total != 1 {
		t.Fatalf("merged 计数=%d", total)
	}
}

// TestRawReportMergeInvalid 合并的边界: 不足 2 份 / ID 不存在。
func TestRawReportMergeInvalid(t *testing.T) {
	h, d := newRawTestEnv(t)
	base := time.Date(2026, 9, 23, 9, 0, 0, 0, time.Local)
	r1 := seedRaw(t, d, report.RawModScan, "单份", nil, nil, base)

	// 单份应 400(而不是静默透传)
	w := doReq(t, h, "POST", "/api/v2/raw/merge", `{"ids":["`+r1.ID+`"]}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("单份合并应 400: %d", w.Code)
	}
	// 不存在的 ID 应 404
	w = doReq(t, h, "POST", "/api/v2/raw/merge", `{"ids":["`+r1.ID+`","rr-nope"]}`)
	if w.Code != http.StatusNotFound {
		t.Fatalf("不存在 ID 应 404: %d", w.Code)
	}
}

// TestRawReportTrim 存储上限: MaxRaw=2 时第 3 份写入自动淘汰最旧 ——
// 防 JSONL 无界增长(每次写都整文件重写, 无上限 = IO 随存量线性涨)。
func TestRawReportTrim(t *testing.T) {
	h, d := newRawTestEnv(t)
	setReportConfig(ReportConfig{Enabled: true, MaxRaw: 2})
	base := time.Date(2026, 9, 23, 9, 0, 0, 0, time.Local)
	r1 := seedRaw(t, d, report.RawModScan, "最旧", nil, nil, base)
	seedRaw(t, d, report.RawModScan, "中间", nil, nil, base.Add(time.Hour))
	seedRaw(t, d, report.RawModCapture, "最新", nil, nil, base.Add(2*time.Hour))

	if _, total := rawListItems(t, h, ""); total != 2 {
		t.Fatalf("trim 后 total=%d, 期望 2", total)
	}
	if w := doReq(t, h, "GET", "/api/v2/raw/"+r1.ID, ""); w.Code != http.StatusNotFound {
		t.Fatalf("最旧的应被淘汰: %d", w.Code)
	}
}

// TestRawReportSnapshot 手动快照: 只接受 monitor/collect; 无数据时 409
// (而不是 500 —— "没东西可存"是正常状态); 未知模块 400。
func TestRawReportSnapshot(t *testing.T) {
	h, _ := newRawTestEnv(t)
	w := doReq(t, h, "POST", "/api/v2/raw/snapshot", `{"module":"bogus"}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("未知模块应 400: %d", w.Code)
	}
	// 测试环境无监控目标/采集任务 → 无可存快照 → 409
	w = doReq(t, h, "POST", "/api/v2/raw/snapshot", `{"module":"collect"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("无数据应 409: %d %s", w.Code, w.Body.String())
	}
	w = doReq(t, h, "POST", "/api/v2/raw/snapshot", `{"module":"monitor"}`)
	if w.Code != http.StatusConflict {
		t.Fatalf("无数据应 409: %d %s", w.Code, w.Body.String())
	}
}

// TestRawReportOptions 筛选选项: 模块计数(固定五模块全量返回) / 标签并集 /
// 资产并集 / 时间范围。
func TestRawReportOptions(t *testing.T) {
	h, d := newRawTestEnv(t)
	base := time.Date(2026, 9, 20, 9, 0, 0, 0, time.Local)
	seedRaw(t, d, report.RawModScan, "扫描1", []string{"10.0.0.1"}, []string{"日常"}, base)
	seedRaw(t, d, report.RawModScan, "扫描2", []string{"10.0.0.2"}, []string{"专项"}, base.Add(time.Hour))
	seedRaw(t, d, report.RawModCapture, "抓包1", []string{"10.0.0.1"}, nil, base.Add(2*time.Hour))

	w := doReq(t, h, "GET", "/api/v2/raw/options", "")
	if w.Code != http.StatusOK {
		t.Fatalf("options: %d", w.Code)
	}
	var resp struct {
		Data struct {
			Modules []struct {
				ID    string `json:"id"`
				Count int    `json:"count"`
			} `json:"modules"`
			Tags      []string `json:"tags"`
			Assets    []string `json:"assets"`
			DateRange struct {
				From string `json:"from"`
				To   string `json:"to"`
			} `json:"dateRange"`
			Total int `json:"total"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// 固定五模块全量返回(空模块计数 0, 前端徽标稳定)
	if len(resp.Data.Modules) != len(report.RawModules) {
		t.Fatalf("modules=%d, 期望 %d", len(resp.Data.Modules), len(report.RawModules))
	}
	modCount := map[string]int{}
	for _, m := range resp.Data.Modules {
		modCount[m.ID] = m.Count
	}
	if modCount[report.RawModScan] != 2 || modCount[report.RawModCapture] != 1 || modCount[report.RawModMerged] != 0 {
		t.Fatalf("module counts: %v", modCount)
	}
	if len(resp.Data.Tags) != 2 || len(resp.Data.Assets) != 2 {
		t.Fatalf("tags=%v assets=%v", resp.Data.Tags, resp.Data.Assets)
	}
	if resp.Data.DateRange.From != "2026-09-20" || resp.Data.DateRange.To != "2026-09-20" {
		t.Fatalf("dateRange: %+v", resp.Data.DateRange)
	}
}
