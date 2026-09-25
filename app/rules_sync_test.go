package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// nvdSample21 与 NVD 2.1 真实响应同构的最小样本:
// 三条 CVE —— apache 无版本边界(全版本)、nginx 带版本区间、非可指纹产品(应被过滤)。
const nvdSample21 = `{
  "resultsPerPage": 2000,
  "startIndex": 0,
  "totalResults": 3,
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-41773",
        "descriptions": [{"lang": "en", "value": "Apache HTTP Server 2.4.49 stack-based buffer overflow"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
          {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*", "vulnerable": true}
        ]}]}]
      }
    },
    {
      "cve": {
        "id": "CVE-2021-23017",
        "descriptions": [{"lang": "en", "value": "nginx off-by-one"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.3}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
          {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": true,
           "versionStartIncluding": "1.0.0", "versionEndExcluding": "1.21.0"}
        ]}]}]
      }
    },
    {
      "cve": {
        "id": "CVE-2021-99999",
        "descriptions": [{"lang": "en", "value": "Some other product"}],
        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
        "configurations": [{"nodes": [{"cpeMatch": [
          {"criteria": "cpe:2.3:a:somevendor:someproduct:1.0", "vulnerable": true}
        ]}]}]
      }
    }
  ]
}`

// TestNVDPageParse 守 2.1 响应形态: vulnerabilities[].cve 双层结构 +
// totalResults(无 totalPages)。若有人把结构改回 2.0 的 items[], 此用例立刻失败 ——
// 2.0 与 2.1 字段名不同, 解析错位会静默同步出 0 条数据。
func TestNVDPageParse(t *testing.T) {
	var pg nvdPageSync
	if err := json.Unmarshal([]byte(nvdSample21), &pg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if pg.TotalResults != 3 || pg.ResultsPerPage != 2000 {
		t.Fatalf("顶层字段错位: total=%d size=%d", pg.TotalResults, pg.ResultsPerPage)
	}
	if len(pg.Vulnerabilities) != 3 {
		t.Fatalf("应有 3 条, 实际 %d", len(pg.Vulnerabilities))
	}
	if pg.Vulnerabilities[0].CVE.ID != "CVE-2021-41773" {
		t.Fatalf("CVE 编号应在 cve.id, 实际 %q", pg.Vulnerabilities[0].CVE.ID)
	}
}

// TestNVDProcessItem 单条过滤逻辑: 可指纹产品命中、非映射产品丢弃、
// 版本区间转成 ">= a, < b" 约束、minCVSS 门槛生效。
func TestNVDProcessItem(t *testing.T) {
	var pg nvdPageSync
	if err := json.Unmarshal([]byte(nvdSample21), &pg); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	prods := map[string]*nvdProductSync{}
	hits := 0
	for _, it := range pg.Vulnerabilities {
		if processNVDItemSync(it, prods, 0) {
			hits++
		}
	}
	if hits != 2 {
		t.Fatalf("应命中 2 条(apache/nginx), someproduct 不在映射表内, 实际 %d", hits)
	}
	pa := prods["apache"]
	if pa == nil || len(pa.CVEs) != 1 {
		t.Fatal("apache 应有 1 条 CVE")
	}
	// 无版本边界 = 全版本受影响, 不应写 constraints 字段
	if _, has := pa.CVEs[0]["constraints"]; has {
		t.Fatalf("无边界 CVE 不应带 constraints: %v", pa.CVEs[0])
	}
	pn := prods["nginx"]
	if pn == nil {
		t.Fatal("nginx 应命中")
	}
	want := ">= 1.0.0, < 1.21.0"
	// 直接调用路径(未经 JSON 往返)里 constraints 是 []string
	groups, ok := pn.CVEs[0]["constraints"].([]string)
	if !ok || len(groups) != 1 || groups[0] != want {
		t.Fatalf("版本约束应为 %q, 实际 %v", want, pn.CVEs[0]["constraints"])
	}

	// minCVSS 门槛: 7.0 以下全丢
	prods2 := map[string]*nvdProductSync{}
	if !processNVDItemSync(pg.Vulnerabilities[0], prods2, 7.0) {
		t.Fatal("CVSS 7.5 应通过 7.0 门槛")
	}
	if processNVDItemSync(pg.Vulnerabilities[2], prods2, 9.9) {
		t.Fatal("CVSS 9.8 不应通过 9.9 门槛")
	}
}

// TestNVDRateWindow 滑动窗口节流: 窗口内 limit 次立即放行, 第 limit+1 次必须
// 阻塞到最早一次出窗。用小窗口(300ms)避免真实 30 秒档拖慢测试。
func TestNVDRateWindow(t *testing.T) {
	r := &nvdRate{limit: 3, window: 300 * time.Millisecond}
	t0 := time.Now()
	r.wait()
	r.wait()
	r.wait()
	if elapsed := time.Since(t0); elapsed > 150*time.Millisecond {
		t.Fatalf("窗口内 3 次应立即放行, 实际耗时 %v", elapsed)
	}
	// 第 4 次: 必须等到第一次出窗(≥300ms - 容差)
	r.wait()
	if elapsed := time.Since(t0); elapsed < 250*time.Millisecond {
		t.Fatalf("第 4 次应阻塞到出窗(≥~300ms), 实际 %v —— 限流失效会撞 NVD 429", elapsed)
	}
	// 出窗后应立即放行
	t1 := time.Now()
	r.wait()
	if elapsed := time.Since(t1); elapsed > 100*time.Millisecond {
		t.Fatalf("出窗后应立即放行, 实际 %v", elapsed)
	}
}

// TestFetchNVDPage429 429 按 Retry-After 退避后重试成功(限流是正常状态,
// 不是失败 —— 同步任务不该因为一次 429 就整体报错退出)。
func TestFetchNVDPage429(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"totalResults":0,"vulnerabilities":[]}`))
	}))
	defer srv.Close()

	body, err := fetchNVDPage(srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("429 后应重试成功, 实际: %v", err)
	}
	if calls != 2 {
		t.Fatalf("应恰好 2 次(1 次 429 + 1 次成功), 实际 %d", calls)
	}
	if !strings.Contains(string(body), "totalResults") {
		t.Fatalf("重试后应拿到正文, 实际 %q", body)
	}
}

// TestFetchNVDPage403FailFast 403/404 是端点级错误(旧 2.0 地址退役即此),
// 重试无意义必须立即失败 —— 否则用户点一次同步要干等 8 次重试才看到 403。
func TestFetchNVDPage403FailFast(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	_, err := fetchNVDPage(srv.Client(), srv.URL)
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("403 应报 HTTP 403, 实际: %v", err)
	}
	if calls != 1 {
		t.Fatalf("403 不应重试, 实际请求 %d 次", calls)
	}
}

// TestNVDAPIKeyPersist Key 存取: 显式传入 → 落 settings.json 的 nvd 节;
// 留空 → 读回已存的。走 withTempExeDir/writeTestSettings 的共享独占路径。
func TestNVDAPIKeyPersist(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)

	if got := nvdAPIKey("TEST-KEY-123"); got != "TEST-KEY-123" {
		t.Fatalf("显式 Key 应原样返回, 实际 %q", got)
	}
	// 已持久化: 不传参时读回同一值
	if got := nvdAPIKey(""); got != "TEST-KEY-123" {
		t.Fatalf("应读回已保存的 Key, 实际 %q", got)
	}
	// 落盘内容在 nvd 节, 不污染其它节
	raw, _ := os.ReadFile(settingsFilePath())
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("settings.json 损坏: %v", err)
	}
	if _, ok := doc["nvd"]; !ok {
		t.Fatal("Key 应写入 nvd 节")
	}
}

// TestSyncNVDEndToEnd 假 NVD 服务跑完整同步: 分页解析 → 产品过滤 →
// 写 cpe/ 文件 → 状态回填。守"一键同步"整条链路的契约(离线, 不触真实 NVD)。
func TestSyncNVDEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(nvdSample21))
	}))
	defer srv.Close()

	prevBase := nvdBaseURL
	nvdBaseURL = srv.URL
	t.Cleanup(func() { nvdBaseURL = prevBase })

	// 清空同步状态(其它用例可能跑过)
	resetRulesSyncState()
	t.Cleanup(resetRulesSyncState)

	syncNVD(0, "", "")

	rulesSyncMu.Lock()
	st := rulesSyncState
	rulesSyncMu.Unlock()
	if st.Error != "" {
		t.Fatalf("同步应成功, 实际报错: %s", st.Error)
	}
	if st.TotalCVEs != 3 || st.KeptCVEs != 2 || st.Products != 2 {
		t.Fatalf("状态回填错误: total=%d kept=%d products=%d", st.TotalCVEs, st.KeptCVEs, st.Products)
	}
	if st.TotalPages != 1 {
		t.Fatalf("3 条 CVE 一页应装下, totalPages 应为 1, 实际 %d", st.TotalPages)
	}

	// 输出文件: vuln/cpe/ 下每个命中产品一个(2026-09-24 dist 目录整理: 规则库收进 vuln/)
	cpeDir := filepath.Join(exeDir(), "vuln", "cpe")
	t.Cleanup(func() { os.RemoveAll(cpeDir) })
	data, err := os.ReadFile(filepath.Join(cpeDir, "nvd-apache.json"))
	if err != nil {
		t.Fatalf("应写出 nvd-apache.json: %v", err)
	}
	if !strings.Contains(string(data), "CVE-2021-41773") {
		t.Fatal("apache 文件应含对应 CVE")
	}
}

// TestNVDSyncResultPersist 守"同步结果跨进程重启可恢复"契约(用户反馈:
// 同步完重启服务后页面像"从未同步过", 误以为要重新点一键同步):
//   - 收尾结果写入 settings.json 的 nvd 节, 且合并写不丢同节的 apiKey;
//   - 进程重启(内存状态清零)后, 恢复逻辑从盘上回填展示状态;
//   - 内存已有完成记录时不被旧结果覆盖(新同步优先)。
func TestNVDSyncResultPersist(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)

	// 前置: 同节已有 apiKey(模拟用户填过 Key)
	if got := nvdAPIKey("TEST-KEY-PERSIST"); got != "TEST-KEY-PERSIST" {
		t.Fatalf("前置: 保存 Key 应生效, 实际 %q", got)
	}

	finished := time.Date(2026, 9, 24, 21, 53, 0, 0, time.Local)
	rulesSyncMu.Lock()
	rulesSyncState.FinishedAt = finished
	rulesSyncState.Products = 17
	rulesSyncState.KeptCVEs = 3972
	rulesSyncState.TotalCVEs = 396964
	rulesSyncState.Files = []string{"nvd-apache.json", "nvd-nginx.json"}
	rulesSyncState.Source = "nvd"
	rulesSyncMu.Unlock()
	t.Cleanup(resetRulesSyncState)

	persistNVDLastSync()

	// 场景 1: 模拟进程重启 —— 内存清零后恢复逻辑读盘回填
	resetRulesSyncState()
	nvdRestoreOnce = &sync.Once{}
	t.Cleanup(func() { nvdRestoreOnce = &sync.Once{} })
	restoreNVDLastSync()

	rulesSyncMu.Lock()
	st := rulesSyncState
	rulesSyncMu.Unlock()
	if !st.FinishedAt.Equal(finished) {
		t.Fatalf("重启后应恢复完成时间, 实际 %v", st.FinishedAt)
	}
	if st.Products != 17 || st.KeptCVEs != 3972 || st.TotalCVEs != 396964 {
		t.Fatalf("重启后应恢复统计: products=%d kept=%d total=%d", st.Products, st.KeptCVEs, st.TotalCVEs)
	}
	if len(st.Files) != 2 || st.Files[0] != "nvd-apache.json" {
		t.Fatalf("重启后应恢复文件清单: %v", st.Files)
	}

	// 场景 2: 持久化是合并写 —— 同节的 apiKey 不能被抹掉
	if got := nvdAPIKey(""); got != "TEST-KEY-PERSIST" {
		t.Fatalf("持久化 lastSync 不应抹掉同节的 apiKey, 实际 %q", got)
	}

	// 场景 3: 内存已有完成记录(新同步跑过)时, 旧结果不得覆盖
	rulesSyncMu.Lock()
	rulesSyncState.FinishedAt = time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)
	rulesSyncMu.Unlock()
	nvdRestoreOnce = &sync.Once{}
	restoreNVDLastSync()
	rulesSyncMu.Lock()
	got := rulesSyncState.FinishedAt
	rulesSyncMu.Unlock()
	if !got.Equal(time.Date(2026, 10, 1, 12, 0, 0, 0, time.Local)) {
		t.Fatalf("已有完成记录时不应被旧结果覆盖: %v", got)
	}
}

// TestDecideSyncMode 增量默认决策: 有完成记录 → 增量(起点=上次完成日期);
// 显式 full/显式 since 优先; 无完成记录 → 全量(首次同步)。
func TestDecideSyncMode(t *testing.T) {
	withTempExeDir(t)

	// 无完成记录: 默认全量
	writeTestSettings(t, `{}`)
	if since, mode := decideSyncMode("", false); since != "" || mode != "full" {
		t.Fatalf("无完成记录应默认全量, 实际 since=%q mode=%q", since, mode)
	}

	// 有完成记录: 默认增量, 起点 = 上次完成日期(UTC)
	writeTestSettings(t, `{"nvd":{"lastSync":{"finishedAt":"2026-09-20T17:30:00+08:00"}}}`)
	since, mode := decideSyncMode("", false)
	if mode != "incremental" || since != "2026-09-20" {
		t.Fatalf("有完成记录应默认增量且起点=完成日期, 实际 since=%q mode=%q", since, mode)
	}

	// 失败记录(error 非空): 不能当增量基线 —— 失败那次 0 条数据, 拿失败
	// 时刻当起点会让默认增量在"日期查询被拦"的环境里永远失败
	writeTestSettings(t, `{"nvd":{"lastSync":{"finishedAt":"2026-09-24T23:15:58+08:00","error":"拉取第 1 页失败: HTTP 404"}}}`)
	if since, mode := decideSyncMode("", false); since != "" || mode != "full" {
		t.Fatalf("失败记录不应作增量基线, 实际 since=%q mode=%q", since, mode)
	}

	// 显式 full: 即使有完成记录也全量
	if _, mode := decideSyncMode("", true); mode != "full" {
		t.Fatal("显式 full 应走全量")
	}
	// 显式 since: 优先采用, 仍属增量
	if since, mode := decideSyncMode("2025-01-01", false); since != "2025-01-01" || mode != "incremental" {
		t.Fatalf("显式 since 应优先, 实际 since=%q mode=%q", since, mode)
	}
}

// TestNVDMergeUpsert upsert 按 CVE 号"新覆盖旧、未变化保留", 以及已有文件读回。
func TestNVDMergeUpsert(t *testing.T) {
	p := &nvdProductSync{Key: "apache", CVEs: []map[string]any{
		{"cve": "CVE-2021-41773", "title": "old", "cvss": 7.5},
		{"cve": "CVE-2020-11998", "title": "keep", "cvss": 9.8},
	}}
	// 同号替换
	upsertNVDVuln(p, map[string]any{"cve": "CVE-2021-41773", "title": "new", "cvss": 8.1})
	// 新号追加
	upsertNVDVuln(p, map[string]any{"cve": "CVE-2026-00001", "title": "x", "cvss": 5.5})
	if len(p.CVEs) != 3 {
		t.Fatalf("应 3 条(1 替换 + 1 保留 + 1 新增), 实际 %d", len(p.CVEs))
	}
	if p.CVEs[0]["title"] != "new" || p.CVEs[0]["cvss"] != 8.1 {
		t.Fatalf("同号应被新数据替换, 实际 %v", p.CVEs[0])
	}
	if p.CVEs[1]["title"] != "keep" {
		t.Fatalf("未变化的条目应原样保留, 实际 %v", p.CVEs[1])
	}
	if p.CVEs[2]["cve"] != "CVE-2026-00001" {
		t.Fatalf("新 CVE 应追加, 实际 %v", p.CVEs[2])
	}

	// 读回: 只认 nvd-*.json, 坏文件/无关文件跳过; 目录空返回 nil
	dir := t.TempDir()
	if got := loadExistingNVDSync(dir); got != nil {
		t.Fatal("空目录应返回 nil(触发全量回退)")
	}
	// 与真实输出同构的存量文件 + 干扰文件
	_ = os.WriteFile(filepath.Join(dir, "nvd-apache.json"),
		[]byte(`{"version":"nvd-sync 2026-09-20","products":[{"cpe":"cpe:2.3:a:apache:http_server","vendor":"apache","product":"apache","cves":[{"cve":"CVE-2020-11998","title":"keep","cvss":9.8}]}]}`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "nvd-nginx.json"), []byte(`{broken json`), 0o644)
	_ = os.WriteFile(filepath.Join(dir, "custom.json"), []byte(`{}`), 0o644)
	got := loadExistingNVDSync(dir)
	if got == nil || len(got) != 1 {
		t.Fatalf("应只读回 1 个有效产品(apache), 实际 %v", got)
	}
	if pa := got["apache"]; pa == nil || len(pa.CVEs) != 1 || pa.CVEs[0]["cve"] != "CVE-2020-11998" {
		t.Fatalf("读回内容错误: %v", pa)
	}
}

// TestSyncNVDEndToEndIncremental 端到端守增量合并契约: 全量同步后, 增量只拉
// "修改过的 CVE" 并合并进已有文件 —— 未变化的 CVE 不丢、同号 CVE 用新数据、
// 请求带 lastModStartDate。守"重开服务后又从头同步"修复的核心行为。
func TestSyncNVDEndToEndIncremental(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)

	// 增量批次: apache 的 CVE 更新(标题变), nginx 新增一条
	const nvdDelta = `{
  "resultsPerPage": 2000, "startIndex": 0, "totalResults": 2,
  "vulnerabilities": [
    {"cve": {"id": "CVE-2021-41773",
      "descriptions": [{"lang": "en", "value": "Apache HTTP Server 2.4.49 (updated)"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 8.1}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*", "vulnerable": true}
      ]}]}]}},
    {"cve": {"id": "CVE-2026-00001",
      "descriptions": [{"lang": "en", "value": "nginx new bug"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.0}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]}}
  ]
}`
	var gotDeltaParam string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if p := r.URL.Query().Get("lastModStartDate"); p != "" {
			gotDeltaParam = p
			_, _ = w.Write([]byte(nvdDelta))
			return
		}
		_, _ = w.Write([]byte(nvdSample21))
	}))
	defer srv.Close()

	prevBase := nvdBaseURL
	nvdBaseURL = srv.URL
	t.Cleanup(func() { nvdBaseURL = prevBase })
	resetRulesSyncState()
	t.Cleanup(resetRulesSyncState)
	cpeDir := filepath.Join(exeDir(), "vuln", "cpe")
	t.Cleanup(func() { os.RemoveAll(cpeDir) })

	// 1) 全量同步
	syncNVD(0, "", "")
	if gotDeltaParam != "" {
		t.Fatalf("全量同步不应带 lastModStartDate, 实际 %q", gotDeltaParam)
	}

	// 2) 模拟"上次同步完成": 落 lastSync 记录(与 handler 收尾同路径)
	finished := time.Date(2026, 9, 24, 12, 0, 0, 0, time.Local)
	rulesSyncMu.Lock()
	rulesSyncState.FinishedAt = finished
	rulesSyncState.Mode = "full"
	rulesSyncMu.Unlock()
	persistNVDLastSync()

	// 3) 增量同步: 决策应命中增量, 请求带 lastModStartDate
	since, mode := decideSyncMode("", false)
	if mode != "incremental" || since == "" {
		t.Fatalf("有完成记录应决策为增量, 实际 since=%q mode=%q", since, mode)
	}
	syncNVD(0, since, "")
	if gotDeltaParam == "" {
		t.Fatal("增量同步应在请求里带 lastModStartDate")
	}

	// 4) 合并结果: apache 同号被新数据替换(仍 1 条); nginx 旧 CVE 保留 + 新增 1 条
	apa, err := os.ReadFile(filepath.Join(cpeDir, "nvd-apache.json"))
	if err != nil {
		t.Fatalf("增量后 nvd-apache.json 应仍存在: %v", err)
	}
	if !strings.Contains(string(apa), "(updated)") || !strings.Contains(string(apa), "8.1") {
		t.Fatalf("apache 同号 CVE 应被新数据替换, 实际 %s", apa)
	}
	if strings.Count(string(apa), `"cve":`) != 1 {
		t.Fatalf("apache 应仍只有 1 条 CVE(替换而非追加), 实际 %s", apa)
	}
	ngx, err := os.ReadFile(filepath.Join(cpeDir, "nvd-nginx.json"))
	if err != nil {
		t.Fatalf("增量后 nvd-nginx.json 应仍存在: %v", err)
	}
	if !strings.Contains(string(ngx), "CVE-2021-23017") {
		t.Fatalf("未变化的 nginx CVE 不得丢失, 实际 %s", ngx)
	}
	if !strings.Contains(string(ngx), "CVE-2026-00001") {
		t.Fatalf("新增 CVE 应合并进 nginx 文件, 实际 %s", ngx)
	}
}

// resetRulesSyncState 同步状态复位(用例间共享的全局, 防相互污染)。
func resetRulesSyncState() {
	rulesSyncMu.Lock()
	defer rulesSyncMu.Unlock()
	rulesSyncState.Running = false
	rulesSyncState.TotalPages = 0
	rulesSyncState.CurrentPage = 0
	rulesSyncState.TotalCVEs = 0
	rulesSyncState.KeptCVEs = 0
	rulesSyncState.Products = 0
	rulesSyncState.StartedAt = time.Time{}
	rulesSyncState.FinishedAt = time.Time{}
	rulesSyncState.Error = ""
	rulesSyncState.Files = nil
	rulesSyncState.Source = ""
	rulesSyncState.MinCVSS = 0
	rulesSyncState.APIKeyConfigured = false
	rulesSyncState.Mode = ""
	rulesSyncState.Since = ""
	// 全量分批字段(2026-09-25): 不复位会让"上一用例留下的 batchIndex/resumable"
	// 渗进下一个用例的断言, 表现为单跑通过、全量跑失败。
	rulesSyncState.BatchIndex = 0
	rulesSyncState.BatchTotal = 0
	rulesSyncState.BatchFromPage = 0
	rulesSyncState.BatchToPage = 0
	rulesSyncState.Resumable = false
}

// ===== 全量分批续传(2026-09-25) =====
//
// 用户诉求: "同步中途关服务, 重开能不能续上"。守三条契约:
//   1) 切出来的批次不超过 NVD 的 120 天上限且首尾衔接(漏一天 = 漏一批 CVE);
//   2) 批次失败后进度停在"该批", 而不是回到第 1 批;
//   3) 重开后不重跑已完成的批, 且已落盘的前批数据不被后批覆盖。

// 两批用不同产品, 才能断言"前批没被后批冲掉"(同产品会被 upsert 合并, 看不出问题)。
const nvdBatchApache = `{
  "resultsPerPage": 2000, "startIndex": 0, "totalResults": 1,
  "vulnerabilities": [
    {"cve": {"id": "CVE-2000-0001",
      "descriptions": [{"lang": "en", "value": "apache old bug"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*", "vulnerable": true}
      ]}]}]}}
  ]
}`

const nvdBatchNginx = `{
  "resultsPerPage": 2000, "startIndex": 0, "totalResults": 1,
  "vulnerabilities": [
    {"cve": {"id": "CVE-2001-0002",
      "descriptions": [{"lang": "en", "value": "nginx old bug"}],
      "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 7.3}}]},
      "configurations": [{"nodes": [{"cpeMatch": [
        {"criteria": "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*", "vulnerable": true}
      ]}]}]}}
  ]
}`

func TestBatchPageRange(t *testing.T) {
	// 每批 10 页: 批 0 = 1-10, 批 1 = 11-20, 批 2 = 21-30
	from, to := batchPageRange(0, 10)
	if from != 1 || to != 10 {
		t.Fatalf("批 0 应为 1-10, 实际 %d-%d", from, to)
	}
	from, to = batchPageRange(1, 10)
	if from != 11 || to != 20 {
		t.Fatalf("批 1 应为 11-20, 实际 %d-%d", from, to)
	}
	from, to = batchPageRange(2, 10)
	if from != 21 || to != 30 {
		t.Fatalf("批 2 应为 21-30, 实际 %d-%d", from, to)
	}
	// 批size 非法时回退默认, 不能算出 0 区间(0 页会被当"拉到全部")
	from, to = batchPageRange(0, 0)
	if from != 1 || to != nvdBatchPages {
		t.Fatalf("非法 batchPages 应回退 %d 页一批, 实际 %d-%d", nvdBatchPages, from, to)
	}
}

func TestNVDResumeRoundTrip(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)

	if loadNVDResume() != nil {
		t.Fatal("初始状态不应有续传进度")
	}
	r := &nvdResume{Kind: "page", Mode: "full-batch", BatchPages: 10, Total: 5, Next: 2, NextPage: 21, MinCVSS: 3}
	saveNVDResume(r)
	got := loadNVDResume()
	if got == nil || got.Next != 2 || got.Total != 5 || got.MinCVSS != 3 || got.NextPage != 21 {
		t.Fatalf("续传进度读回错误: %+v", got)
	}
	// 跑完(Next >= Total)视为已完成, 不能再被当作"待续"
	r.Next = 5
	saveNVDResume(r)
	if loadNVDResume() != nil {
		t.Fatal("已完成的计划不应再被识别为未完成(否则每次都提示可续传)")
	}
	// 旧格式(按日期分窗, 无 kind)必须被丢弃 —— 日期分批已被实测证伪,
	// 沿用它会让同步再次空跑 109 批 0 条
	kv := nvdSectionKV()
	kv["resume"] = map[string]any{"mode": "full-batch", "fromDate": "2026-01-01", "windowDays": 90, "total": 109, "next": 31}
	if err := writeNVDSectionKV(kv); err != nil {
		t.Fatalf("写旧格式失败: %v", err)
	}
	if loadNVDResume() != nil {
		t.Fatal("旧格式(按日期分窗)的 resume 必须被丢弃, 不能续")
	}

	r = &nvdResume{Kind: "page", BatchPages: 10, Total: 5, Next: 1, NextPage: 11}
	saveNVDResume(r)
	clearNVDResume()
	if loadNVDResume() != nil {
		t.Fatal("清除后不应读到续传进度")
	}
}

// TestNVDBatchedResumeAfterInterrupt 守"中断 → 重开续跑"整条链路:
// 第 1 批(第 1-5 页)成功落盘 → 第 2 批失败(= 服务被停) → 重新读回进度 → 从
// 第 6 页继续, 且第 1 批既不被重跑也不被覆盖。
//
// 另一条同等重要的契约: **请求里不能出现任何日期参数**。本环境对带
// lastModStartDate / pubStartDate 的 NVD 请求一律 404(2026-09-25 实测), 一旦有人
// 把日期过滤加回来, 同步会静默变成"每批 0 条"—— 肉眼看上去还在正常推进。
func TestNVDBatchedResumeAfterInterrupt(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)
	resetRulesSyncState()
	t.Cleanup(resetRulesSyncState)
	cpeDir := filepath.Join(exeDir(), "vuln", "cpe")
	t.Cleanup(func() { os.RemoveAll(cpeDir) })

	const totalPages = 15 // 假库 15 页; 每批 5 页 → 3 批
	var mu sync.Mutex
	var seen []int          // 已请求过的页码(1 基)
	blocked := map[int]bool{} // 该页返回失败(模拟中断)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		for _, k := range []string{"lastModStartDate", "lastModEndDate", "pubStartDate", "pubEndDate"} {
			if v := q.Get(k); v != "" {
				mu.Lock()
				seen = append(seen, -1) // -1 标记"带了日期参数", 断言里会炸
				mu.Unlock()
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		idx, _ := strconv.Atoi(q.Get("startIndex"))
		page := idx/nvdPageSize + 1
		mu.Lock()
		seen = append(seen, page)
		mu.Unlock()
		if blocked[page] {
			// 403 在 fetchNVDPage 里是"立即失败不重试", 拿它当服务中断的替身;
			// 用 5xx 会触发 8 次重试, 把用例拖到十几秒。
			w.WriteHeader(http.StatusForbidden)
			return
		}
		// 前 5 页给 apache, 后面给 nginx: 两批产物不同, 才能验证"前批没被覆盖"
		body := nvdBatchNginx
		if page <= 5 {
			body = nvdBatchApache
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(strings.Replace(body, `"totalResults": 1`, fmt.Sprintf(`"totalResults": %d`, totalPages*nvdPageSize), 1)))
	}))
	defer srv.Close()
	prevBase := nvdBaseURL
	nvdBaseURL = srv.URL
	t.Cleanup(func() { nvdBaseURL = prevBase })

	// 第 2 批(第 6-10 页)失败 = 同步在此中断
	blocked[6] = true
	// 带 Key 走 50 次/30 秒的限速档, 15 页请求才不会被节流器拖住等待窗口
	r := &nvdResume{Kind: "page", Mode: "full-batch", BatchPages: 5, Total: 3, Next: 0, NextPage: 1, StartedAt: time.Now()}
	syncNVDBatched(0, "TEST-KEY", r)

	saved := loadNVDResume()
	if saved == nil {
		t.Fatal("中断后必须留下续传进度(否则重开只能从头)")
	}
	if saved.Next != 1 || saved.NextPage != 6 {
		t.Fatalf("断点应记在第 2 批(Next=1/NextPage=6), 实际 Next=%d NextPage=%d", saved.Next, saved.NextPage)
	}
	if _, err := os.Stat(filepath.Join(cpeDir, "nvd-apache.json")); err != nil {
		t.Fatalf("已完成的第 1 批必须已落盘: %v", err)
	}

	// ===== 模拟进程重启: 从盘上读回进度继续 =====
	delete(blocked, 6)
	mu.Lock()
	seen = nil
	mu.Unlock()

	r2 := loadNVDResume()
	if r2 == nil {
		t.Fatal("重启后应能读回续传进度")
	}
	syncNVDBatched(0, "TEST-KEY", r2)

	mu.Lock()
	got := append([]int(nil), seen...)
	mu.Unlock()
	for _, p := range got {
		if p == -1 {
			t.Fatal("分批同步的请求不得带任何日期参数(本环境一律 404, 会静默拉 0 条)")
		}
		if p <= 5 {
			t.Fatalf("已完成的第 1 批(第 1-5 页)不应重跑, 实际请求页: %v", got)
		}
	}
	has := func(want int) bool {
		for _, p := range got {
			if p == want {
				return true
			}
		}
		return false
	}
	if !has(6) || !has(11) {
		t.Fatalf("应从第 6 页继续并跑完剩余批次, 实际请求页: %v", got)
	}
	if loadNVDResume() != nil {
		t.Fatal("全部批次跑完应清除续传进度")
	}

	// 前批数据未被后批覆盖(写盘是整文件覆盖, 不读回已有文件就会丢)
	apache, err := os.ReadFile(filepath.Join(cpeDir, "nvd-apache.json"))
	if err != nil || !strings.Contains(string(apache), "CVE-2000-0001") {
		t.Fatalf("第 1 批的 apache 数据应保留: %v / %s", err, apache)
	}
	nginx, err := os.ReadFile(filepath.Join(cpeDir, "nvd-nginx.json"))
	if err != nil || !strings.Contains(string(nginx), "CVE-2001-0002") {
		t.Fatalf("后续批次的 nginx 数据应写入: %v / %s", err, nginx)
	}
}

// TestDecideSyncModeAfterBlockedDelta 守"日期被拦后不再白试增量":
// 上次因环境拦截日期参数而失败后, 本次必须直接走全量(否则每次点同步都要先
// 经历一次注定失败的增量请求)。
func TestDecideSyncModeAfterBlockedDelta(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)
	t.Cleanup(resetRulesSyncState)

	blockedErr := "拉取第 1 页失败: HTTP 404(响应体为空 —— 真 NVD 的 404 应带说明正文, 大概率是网络环境拦截了带日期参数的查询)"
	rulesSyncMu.Lock()
	rulesSyncState.FinishedAt = time.Date(2026, 9, 25, 4, 52, 0, 0, time.Local)
	rulesSyncState.Error = blockedErr
	rulesSyncMu.Unlock()
	persistNVDLastSync()

	since, mode := decideSyncMode("", false)
	if since != "" || mode != "full" {
		t.Fatalf("日期被拦后应直接走全量, 实际 since=%q mode=%q", since, mode)
	}

	// 对照: 成功完成的记录仍应走增量(没证据表明环境不支持时不要用全量代替)
	rulesSyncMu.Lock()
	rulesSyncState.Error = ""
	rulesSyncMu.Unlock()
	persistNVDLastSync()
	since, mode = decideSyncMode("", false)
	if mode != "incremental" || since == "" {
		t.Fatalf("成功记录应走增量, 实际 since=%q mode=%q", since, mode)
	}
}

// TestNVDAPIKeyPersistKeepsLastSync 守"写 Key 不抹同节其它键":
// 2026-09-25 前 nvdAPIKey 用 writeSection 整节覆盖, 保存 Key 会把 lastSync
// (上次同步完成记录)抹掉 → 用户填完 Key 后下次同步反而变成全量重跑。
func TestNVDAPIKeyPersistKeepsLastSync(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{}`)

	rulesSyncMu.Lock()
	rulesSyncState.FinishedAt = time.Date(2026, 9, 25, 10, 0, 0, 0, time.Local)
	rulesSyncState.Mode = "full-batch"
	rulesSyncMu.Unlock()
	t.Cleanup(resetRulesSyncState)
	persistNVDLastSync()

	if got := nvdAPIKey("KEY-AFTER-SYNC"); got != "KEY-AFTER-SYNC" {
		t.Fatalf("Key 应保存并原样返回, 实际 %q", got)
	}
	if last := loadNVDLastSync(); last == nil || last.FinishedAt.IsZero() {
		t.Fatal("保存 API Key 不应抹掉同节的 lastSync(否则下次同步回退全量)")
	}
	if got := nvdAPIKey(""); got != "KEY-AFTER-SYNC" {
		t.Fatalf("Key 应能读回, 实际 %q", got)
	}
}
