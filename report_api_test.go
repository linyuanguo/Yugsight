package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"yugsight/db"
	"yugsight/models"
	"yugsight/report"
	"yugsight/server"
)

// newReportTestEnv 构建报告模块测试环境。
//
// 关键点(踩坑预防):
//
//	reportConfigPath 是包级变量 —— 若不改指临时目录, 用例会读写开发机上真实的
//	report.json(scheduler_api.go 已有先例: 磁盘残留配置会冲掉注入配置,
//	日志表现为"已启用"变"未启用", 断言随环境漂移)。这里统一改指 t.TempDir()。
func newReportTestEnv(t *testing.T, enabled bool) (http.Handler, *db.Database) {
	t.Helper()
	prevPath := reportConfigPath
	reportConfigPath = func() string { return t.TempDir() + "/report.json" }
	t.Cleanup(func() { reportConfigPath = prevPath })

	setReportConfig(ReportConfig{
		Enabled:    enabled,
		MaxArchive: 50,
		Subtitle:   "测试报告",
		Accent:     "#4f46e5",
	})
	t.Cleanup(resetReportConfigForTest)

	h, d := newV2TestEnv(t)
	return h, d
}

// seedReportData 灌入报告测试数据。
func seedReportData(t *testing.T, d *db.Database) {
	t.Helper()
	a1 := db.NewAsset("10.0.0.1")
	a1.Hostname, a1.OS, a1.Ports, a1.Service = "web01", "Linux", []int{80, 443}, "80/http"
	a1.ProbeNode = "probe-a"
	if _, err := d.Assets().Upsert(a1); err != nil {
		t.Fatalf("seed asset: %v", err)
	}
	a2 := db.NewAsset("10.0.0.2")
	a2.Hostname, a2.OS, a2.Ports, a2.Service = "db01", "Linux", []int{6379}, "6379/redis"
	if _, err := d.Assets().Upsert(a2); err != nil {
		t.Fatalf("seed asset: %v", err)
	}

	mkV := func(ip, title, sev string, port int) *db.Vuln {
		v := db.NewVuln(ip, title, sev)
		v.Port = port
		v.Protocol = "tcp"
		v.Confidence = 80
		v.Source = "builtin"
		return v
	}
	v1 := mkV("10.0.0.1", "SQL 注入 (CVE-2024-1234)", models.SeverityCritical, 80)
	v2 := mkV("10.0.0.2", "Redis 未授权访问", models.SeverityHigh, 6379)
	for _, v := range []*db.Vuln{v1, v2} {
		if _, err := d.Vulns().Upsert(v); err != nil {
			t.Fatalf("seed vuln: %v", err)
		}
	}
}

// ===== 状态与开关 =====

func TestReportStatusAlwaysAccessible(t *testing.T) {
	// 未启用时 /status 也必须可用 —— 否则前端查不到"为什么没数据"
	h, _ := newReportTestEnv(t, false)
	w := doReq(t, h, "GET", "/api/v2/report/status", "")
	if w.Code != 200 {
		t.Fatalf("status 接口应可用, 实际 %d", w.Code)
	}
	out := decodeResp(t, w)
	if out.Code != server.CodeOK {
		t.Fatalf("resp=%+v", out)
	}
	if !strings.Contains(w.Body.String(), `"enabled":false`) {
		t.Fatalf("应返回 enabled=false: %s", w.Body.String())
	}
	if !strings.Contains(w.Body.String(), "hint") {
		t.Fatal("未启用时应给出开启提示")
	}
}

func TestReportDisabledReturns503(t *testing.T) {
	h, _ := newReportTestEnv(t, false)
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/api/v2/report/generate", `{}`},
		{"GET", "/api/v2/report/list", ""},
		{"GET", "/api/v2/report/topology", ""},
		{"GET", "/api/v2/report/templates", ""},
	} {
		w := doReq(t, h, c.method, c.path, c.body)
		if w.Code != http.StatusServiceUnavailable {
			t.Errorf("%s %s 未启用时应返回 503, 实际 %d", c.method, c.path, w.Code)
		}
	}
}

// ===== 报告生成与下载 =====

func TestReportGenerateAndDownload(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	w := doReq(t, h, "POST", "/api/v2/report/generate",
		`{"title":"季度安全报告","operator":"安全部","format":"html"}`)
	if w.Code != 200 {
		t.Fatalf("generate status=%d body=%s", w.Code, w.Body.String())
	}
	out := decodeResp(t, w)
	if out.Code != server.CodeOK {
		t.Fatalf("generate resp=%+v", out)
	}
	id, _ := jsonPath(w.Body.String(), "report.id")
	if id == "" {
		t.Fatal("未返回报告 ID")
	}
	// 生成响应不应带正文(体积)
	if strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Fatal("生成响应不应回传报告正文")
	}
	// 默认归档
	if n, _ := d.Reports().Count(); n != 1 {
		t.Fatalf("默认应归档 1 份, 实际 %d", n)
	}

	// 列表(不带正文)
	w = doReq(t, h, "GET", "/api/v2/report/list", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "季度安全报告") {
		t.Fatalf("list status=%d body=%.200s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Fatal("列表不应回传正文")
	}

	// 下载: 回放存档内容
	w = doReq(t, h, "GET", "/api/v2/report/"+id+"/download", "")
	if w.Code != 200 {
		t.Fatalf("download status=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "季度安全报告") || !strings.Contains(body, "SQL 注入") {
		t.Fatalf("下载内容不完整: %.400s", body)
	}
	if cd := w.Header().Get("Content-Disposition"); !strings.Contains(cd, "attachment") {
		t.Fatalf("下载应带附件头, 实际 %q", cd)
	}
	// 文件名不能含非法字符
	if cd := w.Header().Get("Content-Disposition"); strings.ContainsAny(cd, `\/:*?"<>|`) && !strings.Contains(cd, "_") {
		t.Fatalf("文件名未清理非法字符: %q", cd)
	}

	// 详情(不带正文)
	w = doReq(t, h, "GET", "/api/v2/report/"+id, "")
	if w.Code != 200 || strings.Contains(w.Body.String(), "<!DOCTYPE html>") {
		t.Fatalf("详情不应带正文, status=%d", w.Code)
	}

	// 删除
	w = doReq(t, h, "DELETE", "/api/v2/report/"+id, "")
	if w.Code != 200 {
		t.Fatalf("delete status=%d", w.Code)
	}
	if n, _ := d.Reports().Count(); n != 0 {
		t.Fatalf("删除后应为 0, 实际 %d", n)
	}
	w = doReq(t, h, "GET", "/api/v2/report/"+id, "")
	if w.Code != http.StatusNotFound {
		t.Fatalf("删除后查询应 404, 实际 %d", w.Code)
	}
}

func TestReportGenerateNoArchive(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	no := false
	_ = no
	w := doReq(t, h, "POST", "/api/v2/report/generate", `{"title":"临时报告","archive":false}`)
	if w.Code != 200 {
		t.Fatalf("generate status=%d", w.Code)
	}
	if n, _ := d.Reports().Count(); n != 0 {
		t.Fatalf("archive=false 不应落库, 实际 %d", n)
	}
}

func TestReportGeneratePDFFormat(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	w := doReq(t, h, "POST", "/api/v2/report/generate", `{"title":"PDF 报告","format":"pdf"}`)
	if w.Code != 200 {
		t.Fatalf("generate status=%d body=%s", w.Code, w.Body.String())
	}
	id, _ := jsonPath(w.Body.String(), "report.id")
	w = doReq(t, h, "GET", "/api/v2/report/"+id+"/download", "")
	body := w.Body.String()
	// PDF 通道 = 自动唤起打印的页面
	if !strings.Contains(body, "window.print()") {
		t.Fatalf("pdf 格式应产出可打印页面: %.300s", body)
	}
}

func TestReportPreviewInline(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	w := doReq(t, h, "POST", "/api/v2/report/preview", `{"title":"预览报告"}`)
	if w.Code != 200 {
		t.Fatalf("preview status=%d", w.Code)
	}
	if ct := w.Header().Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("预览应返回 HTML, Content-Type=%q", ct)
	}
	if !strings.Contains(w.Body.String(), "预览报告") {
		t.Fatal("预览内容不正确")
	}
	// 预览不落库
	if n, _ := d.Reports().Count(); n != 0 {
		t.Fatalf("预览不应归档, 实际 %d", n)
	}
}

// ===== 多维度筛选 =====

func TestReportFilterBySeverityAndNode(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)

	// 仅严重
	w := doReq(t, h, "POST", "/api/v2/report/generate",
		`{"title":"筛选报告","archive":false,"inline":true,"filter":{"severity":["critical"]}}`)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	arch := decodeArchiveList(t, d)
	if len(arch) != 0 {
		t.Fatal("archive=false 不应落库")
	}

	// 带归档 + 筛选, 校验统计口径
	w = doReq(t, h, "POST", "/api/v2/report/generate",
		`{"title":"仅严重","filter":{"severity":["critical"]}}`)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	out := decodeResp(t, w)
	data := out.Data.(map[string]any)
	rep := data["report"].(map[string]any)
	stats := rep["stats"].(map[string]any)
	if stats["critical"].(float64) != 1 {
		t.Fatalf("critical 应为 1, 实际 %v", stats["critical"])
	}
	if stats["high"].(float64) != 0 {
		t.Fatalf("按严重筛选后 high 应为 0, 实际 %v", stats["high"])
	}
}

func TestReportFilterCIDR(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	w := doReq(t, h, "POST", "/api/v2/report/generate",
		`{"title":"网段筛选","filter":{"cidr":"10.0.0.1/32"}}`)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	out := decodeResp(t, w)
	data := out.Data.(map[string]any)
	stats := data["report"].(map[string]any)["stats"].(map[string]any)
	if stats["assetTotal"].(float64) != 1 {
		t.Fatalf("CIDR 筛选后资产应为 1, 实际 %v", stats["assetTotal"])
	}
}

func TestReportFilterOptions(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	w := doReq(t, h, "GET", "/api/v2/report/options", "")
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	if !strings.Contains(body, "CVE-2024-1234") {
		t.Fatalf("筛选项应含库中 CVE: %.300s", body)
	}
	if !strings.Contains(body, "local") {
		t.Fatal("筛选项应含本地节点")
	}
}

// ===== 资产拓扑 =====

func TestReportTopology(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	w := doReq(t, h, "GET", "/api/v2/report/topology", "")
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	body := w.Body.String()
	// 资产节点 / 端口节点 / 服务节点 / 风险着色字段
	for _, want := range []string{"10.0.0.1", "10.0.0.2", `"kind":"asset"`, `"kind":"port"`, `"kind":"service"`, `"risk":"critical"`, `"online":true`} {
		if !strings.Contains(body, want) {
			t.Errorf("拓扑响应缺少: %s", want)
		}
	}
}

// ===== 历史对比 =====

// TestReportCompareWindow 时间窗对比: 基线窗口 = 目标窗口之前等长的一段。
//
// 数据构造严格对齐"每日轮扫"的真实节奏: 目标窗 = 最近 24h, 基线窗 = 前 24h,
// 因此各条漏洞的时间必须落在对应窗口内, 否则测的是别的东西(第一版就踩了这个坑:
// 把 FoundAt 写成 72h 前, 落在基线段之外, 断言全线错位)。
func TestReportCompareWindow(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	now := time.Now()
	// 基线窗 = [-48h, -24h), 目标窗 = [-24h, now]
	tBase := now.Add(-30 * time.Hour) // 基线窗内
	tTarget := now.Add(-2 * time.Hour)

	// 老漏洞 A: 基线首现, 目标窗口被重新命中(同稳定 ID 覆盖 -> FoundAt 保留, LastSeenAt 刷新)
	old := db.NewVuln("10.0.0.1", "老问题A", models.SeverityHigh)
	old.Port, old.Source = 80, "builtin"
	old.FoundAt, old.LastSeenAt = tBase, tBase
	if _, err := d.Vulns().Upsert(old); err != nil {
		t.Fatalf("seed: %v", err)
	}
	keep := db.NewVuln("10.0.0.1", "老问题A", models.SeverityHigh)
	keep.Port, keep.Source = 80, "builtin"
	keep.FoundAt, keep.LastSeenAt = old.FoundAt, tTarget
	if _, err := d.Vulns().Upsert(keep); err != nil {
		t.Fatalf("seed keep: %v", err)
	}

	// 已修复 B: 基线首现, 目标窗口未再命中(LastSeenAt 停在基线窗)
	gone := db.NewVuln("10.0.0.2", "已修复B", models.SeverityMedium)
	gone.Port, gone.Source = 6379, "builtin"
	gone.FoundAt, gone.LastSeenAt = tBase, tBase
	if _, err := d.Vulns().Upsert(gone); err != nil {
		t.Fatalf("seed gone: %v", err)
	}

	// 新增 C: 首次出现在目标窗口
	fresh := db.NewVuln("10.0.0.3", "新问题C", models.SeverityCritical)
	fresh.Port, fresh.Source = 443, "builtin"
	fresh.FoundAt, fresh.LastSeenAt = tTarget, tTarget
	if _, err := d.Vulns().Upsert(fresh); err != nil {
		t.Fatalf("seed fresh: %v", err)
	}

	from := now.Add(-24 * time.Hour).Format(time.RFC3339)
	to := now.Format(time.RFC3339)
	w := doReq(t, h, "POST", "/api/v2/report/compare", `{"from":"`+from+`","to":"`+to+`"}`)
	if w.Code != 200 {
		t.Fatalf("compare status=%d body=%.400s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"mode":"window"`) {
		t.Fatalf("应返回时间窗模式: %.200s", w.Body.String())
	}

	var resp struct {
		Data struct {
			Diff report.Diff `json:"diff"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	diff := resp.Data.Diff
	// 新增 = 只有 C(10.0.0.3)
	if diff.Stats.NewCount != 1 {
		t.Fatalf("新增应为 1, 实际 %d (%+v)", diff.Stats.NewCount, titlesOf(diff.New))
	}
	if diff.New[0].Title != "新问题C" {
		t.Fatalf("新增项应为 新问题C, 实际 %s", diff.New[0].Title)
	}
	if diff.Stats.NewCritical != 1 {
		t.Fatalf("新增严重应为 1, 实际 %d", diff.Stats.NewCritical)
	}
	// 仍然存在 = A(基线首现 + 目标窗口重新命中)
	if diff.Stats.PersistedCount != 1 || diff.Persisted[0].Title != "老问题A" {
		t.Fatalf("仍然存在应为 1 条(老问题A), 实际 %d (%+v)", diff.Stats.PersistedCount, titlesOf(diff.Persisted))
	}
	// 已修复 = B(基线首现, 目标窗口未命中)
	if diff.Stats.FixedCount != 1 || diff.Fixed[0].Title != "已修复B" {
		t.Fatalf("已修复应为 1 条(已修复B), 实际 %d (%+v)", diff.Stats.FixedCount, titlesOf(diff.Fixed))
	}
}

// titlesOf 提取差异条目标题(错误信息可读性)。
func titlesOf(items []*report.DiffItem) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Title)
	}
	return out
}

func TestReportCompareRequiresParams(t *testing.T) {
	h, _ := newReportTestEnv(t, true)
	w := doReq(t, h, "POST", "/api/v2/report/compare", `{}`)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("缺少参数应 400, 实际 %d", w.Code)
	}
}

func TestReportCompareSaveArchive(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	now := time.Now()
	v := db.NewVuln("10.0.0.9", "对比用漏洞", models.SeverityHigh)
	v.Port = 80
	v.FoundAt, v.LastSeenAt = now.Add(-1*time.Hour), now.Add(-1*time.Hour)
	if _, err := d.Vulns().Upsert(v); err != nil {
		t.Fatalf("seed: %v", err)
	}
	from := now.Add(-2 * time.Hour).Format(time.RFC3339)
	to := now.Format(time.RFC3339)
	w := doReq(t, h, "POST", "/api/v2/report/compare",
		`{"from":"`+from+`","to":"`+to+`","save":true,"title":"对比存档测试"}`)
	if w.Code != 200 {
		t.Fatalf("compare status=%d", w.Code)
	}
	list, _ := d.Reports().List()
	if len(list) != 1 {
		t.Fatalf("对比结果应归档 1 份, 实际 %d", len(list))
	}
	if !strings.Contains(list[0].Content, "差异总览") {
		t.Fatal("归档的对比报告内容不完整")
	}
}

func TestReportHistory(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	task := &db.ScanTask{Type: "port", Target: "10.0.0.0/24", Status: db.TaskSuccess}
	if err := d.ScanTasks().Create(task); err != nil {
		t.Fatalf("seed task: %v", err)
	}
	w := doReq(t, h, "GET", "/api/v2/report/history", "")
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "10.0.0.0/24") {
		t.Fatalf("历史列表应含扫描任务: %.300s", w.Body.String())
	}
}

// ===== 模板管理 =====

func TestReportTemplateCRUD(t *testing.T) {
	h, _ := newReportTestEnv(t, true)

	// 内置模板列表
	w := doReq(t, h, "GET", "/api/v2/report/templates", "")
	if w.Code != 200 {
		t.Fatalf("list status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "headerPlaceholders") {
		t.Fatal("应返回可用占位符说明")
	}

	// 新建
	w = doReq(t, h, "POST", "/api/v2/report/templates",
		`{"name":"公司模板","accent":"#ff0000","header":{"footerCenter":"{{operator}}"}}`)
	if w.Code != 200 {
		t.Fatalf("create status=%d body=%s", w.Code, w.Body.String())
	}
	id, _ := jsonPath(w.Body.String(), "id")
	if id == "" {
		t.Fatal("模板 ID 为空")
	}
	if !strings.Contains(w.Body.String(), "公司模板") {
		t.Fatal("模板未保存")
	}

	// 用该模板生成报告, 验证主题色与页脚生效
	w = doReq(t, h, "POST", "/api/v2/report/preview",
		`{"title":"模板报告","templateId":"`+id+`"}`)
	if w.Code != 200 {
		t.Fatalf("preview status=%d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "#ff0000") {
		t.Fatal("自定义模板主题色未生效")
	}

	// 删除
	w = doReq(t, h, "DELETE", "/api/v2/report/templates/"+id, "")
	if w.Code != 200 {
		t.Fatalf("delete status=%d", w.Code)
	}
	w = doReq(t, h, "GET", "/api/v2/report/templates", "")
	if strings.Contains(w.Body.String(), "公司模板") {
		t.Fatal("删除后模板仍存在")
	}
}

func TestReportTemplateInvalidIDFallsBack(t *testing.T) {
	// 模板 ID 不存在时应回落内置模板, 而不是生成失败
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	w := doReq(t, h, "POST", "/api/v2/report/preview", `{"title":"回落测试","templateId":"no-such-id"}`)
	if w.Code != 200 {
		t.Fatalf("模板缺失时应降级成功, 实际 %d", w.Code)
	}
	if !strings.Contains(w.Body.String(), "回落测试") {
		t.Fatal("降级后的报告内容不正确")
	}
}

// ===== 存档上限淘汰 =====

func TestReportArchiveEviction(t *testing.T) {
	h, d := newReportTestEnv(t, true)
	seedReportData(t, d)
	setReportConfig(ReportConfig{Enabled: true, MaxArchive: 3})

	for i := 0; i < 5; i++ {
		w := doReq(t, h, "POST", "/api/v2/report/generate",
			`{"title":"报告`+string(rune('A'+i))+`","note":"n"}`)
		if w.Code != 200 {
			t.Fatalf("第 %d 次生成失败: %d", i, w.Code)
		}
	}
	n, _ := d.Reports().Count()
	if n != 3 {
		t.Fatalf("超出上限后应保留 3 份, 实际 %d", n)
	}
}

// ===== 降级与健壮性 =====

func TestReportGenerateWithEmptyDB(t *testing.T) {
	// 库为空时生成报告不应失败(产出"无数据"报告, 而不是报错)
	h, _ := newReportTestEnv(t, true)
	w := doReq(t, h, "POST", "/api/v2/report/generate", `{"title":"空库报告"}`)
	if w.Code != 200 {
		t.Fatalf("空库生成应成功, 实际 %d body=%.300s", w.Code, w.Body.String())
	}
	id, _ := jsonPath(w.Body.String(), "report.id")
	w = doReq(t, h, "GET", "/api/v2/report/"+id+"/download", "")
	// 文案断言对齐 render.go 的当前口径(历史版本为"未发现风险/无资产记录",
	// 模板改版后断言未同步导致恒失败): 守住的是"空库报告必须明确说无数据"。
	if !strings.Contains(w.Body.String(), "未发现漏洞") && !strings.Contains(w.Body.String(), "无资产数据") {
		t.Fatal("空库报告应给出明确的无数据说明")
	}
}

func TestReportHandlerNoPanicOnBadBody(t *testing.T) {
	h, _ := newReportTestEnv(t, true)
	for _, body := range []string{`{`, `null`, `{"filter":{"severity":123}}`} {
		w := doReq(t, h, "POST", "/api/v2/report/generate", body)
		if w.Code != http.StatusBadRequest && w.Code != 200 {
			t.Errorf("畸形请求体 %q 应返回 400/200, 实际 %d", body, w.Code)
		}
	}
}

func TestSanitizeFilename(t *testing.T) {
	cases := map[string]string{
		"正常标题":         "正常标题",
		`a/b\c:d*e?f"g<h>i|j`: "a_b_c_d_e_f_g_h_i_j",
		"":               "yugsight_report",
	}
	for in, want := range cases {
		if got := sanitizeFilename(in); got != want {
			t.Errorf("sanitizeFilename(%q)=%q, 期望 %q", in, got, want)
		}
	}
	// 超长截断
	long := strings.Repeat("长", 200)
	if n := len([]rune(sanitizeFilename(long))); n > 60 {
		t.Errorf("超长文件名应被截断, 实际 %d", n)
	}
}

func TestParseReportTimeEnd(t *testing.T) {
	// 只给日期时应补到当天 23:59:59(否则当天扫描结果会被滤掉)
	got := parseReportTimeEnd("2026-09-17")
	if got.Hour() != 23 || got.Minute() != 59 || got.Second() != 59 {
		t.Fatalf("日期应补到当天末尾, 实际 %v", got)
	}
	if t2 := parseReportTimeEnd(""); !t2.IsZero() {
		t.Fatal("空串应返回零值")
	}
	// 非法输入静默忽略(不 panic、不返回奇怪值)
	if t3 := parseReportTimeEnd("乱码"); !t3.IsZero() {
		t.Fatalf("非法时间应返回零值, 实际 %v", t3)
	}
}

// decodeArchiveList 读取当前存档列表(辅助)。
func decodeArchiveList(t *testing.T, d *db.Database) []*report.Archive {
	t.Helper()
	list, err := d.Reports().List()
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	return list
}

// TestReportSourceLabel 验证来源标签规范化(支撑"按探针节点筛选")。
func TestReportSourceLabel(t *testing.T) {
	cases := []struct {
		source, node, want string
	}{
		{"", "", "local"},
		{"probe", "probe-a", "probe:probe-a"},
		{"", "probe-b", "probe:probe-b"},
		{"builtin", "probe-a", "builtin@probe-a"},
		{"builtin", "", "builtin"},
		{"probe:probe-a", "probe-a", "probe:probe-a"},
	}
	for _, c := range cases {
		if got := reportSourceLabel(c.source, c.node); got != c.want {
			t.Errorf("reportSourceLabel(%q,%q)=%q, 期望 %q", c.source, c.node, got, c.want)
		}
	}
}

// TestReportFilterNodeLocal 本地节点筛选口径。
//
// 数据构造: 一个探针资产(probe-x)上的漏洞 + 一个本地资产上的漏洞。
// 修复前的缺陷: 装配层给本地漏洞写入 Source="local", 给探针资产上的漏洞写入
// Source="builtin@probe-x"; 而筛选只按"资产 ProbeNode 是否为空"判断本地,
// 导致本地漏洞(资产无 ProbeNode 但 Source 非空)也被算作本地以外的项,
// 最终"仅本地"筛出 0 条或全量 —— 这里固化为回归用例。
func TestReportFilterNodeLocal(t *testing.T) {
	h, d := newReportTestEnv(t, true)

	a := db.NewAsset("10.1.0.1")
	a.ProbeNode = "probe-x"
	if _, err := d.Assets().Upsert(a); err != nil {
		t.Fatalf("seed: %v", err)
	}
	la := db.NewAsset("10.1.0.2")
	if _, err := d.Assets().Upsert(la); err != nil {
		t.Fatalf("seed: %v", err)
	}

	v1 := db.NewVuln("10.1.0.1", "探针漏洞", models.SeverityHigh)
	v1.Port = 80
	v2 := db.NewVuln("10.1.0.2", "本地漏洞", models.SeverityHigh)
	v2.Port = 80
	for _, v := range []*db.Vuln{v1, v2} {
		if _, err := d.Vulns().Upsert(v); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}

	// 仅本地
	w := doReq(t, h, "POST", "/api/v2/report/generate", `{"title":"本地筛选","filter":{"probeNode":"local"}}`)
	if w.Code != 200 {
		t.Fatalf("status=%d", w.Code)
	}
	stats := decodeStats(t, w)
	if stats["vulnTotal"].(float64) != 1 {
		t.Fatalf("本地筛选应保留 1 条, 实际 %v", stats["vulnTotal"])
	}

	// 仅指定探针节点
	w = doReq(t, h, "POST", "/api/v2/report/generate", `{"title":"探针筛选","filter":{"probeNode":"probe-x"}}`)
	stats = decodeStats(t, w)
	if stats["vulnTotal"].(float64) != 1 {
		t.Fatalf("探针筛选应保留 1 条, 实际 %v", stats["vulnTotal"])
	}

	// 不筛选: 全部
	w = doReq(t, h, "POST", "/api/v2/report/generate", `{"title":"全部"}`)
	stats = decodeStats(t, w)
	if stats["vulnTotal"].(float64) != 2 {
		t.Fatalf("不筛选应为 2 条, 实际 %v", stats["vulnTotal"])
	}
}

// decodeStats 从生成响应里取出统计对象。
func decodeStats(t *testing.T, w *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	out := decodeResp(t, w)
	if out.Code != server.CodeOK {
		t.Fatalf("generate 失败: %+v", out)
	}
	data, ok := out.Data.(map[string]any)
	if !ok {
		t.Fatalf("data 类型异常: %T", out.Data)
	}
	rep := data["report"].(map[string]any)
	return rep["stats"].(map[string]any)
}
