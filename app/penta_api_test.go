package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"yugsight/internal/db"
	"yugsight/internal/models"
)

// installPentaTestDB 注入临时库 + 免登录(与 weakpass_api_test 同手法)。
func installPentaTestDB(t *testing.T) *db.Database {
	t.Helper()
	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })
	v2DBProviderMu.Lock()
	prevProvider := v2DBProvider
	v2DBProvider = func() *db.Database { return d }
	v2DBProviderMu.Unlock()
	t.Cleanup(func() {
		v2DBProviderMu.Lock()
		v2DBProvider = prevProvider
		v2DBProviderMu.Unlock()
	})
	return d
}

// pentaTestRouter 构建与 main.go 同款的 penta 路由 mux(裸 handler, 不挂
// requireAuth —— 权限边界由 rbac 既有测试守; 但必须经真实 mux, 否则
// r.PathValue("id") 拿不到路径参数)。
func pentaTestRouter() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/penta/status", hPentaStatus)
	mux.HandleFunc("/api/v2/penta/tasks", hPentaTasks)
	mux.HandleFunc("/api/v2/penta/tasks/import", hPentaImport)
	mux.HandleFunc("/api/v2/penta/tasks/batch", hPentaBatch)
	mux.HandleFunc("/api/v2/penta/tasks/export", hPentaExport)
	mux.HandleFunc("/api/v2/penta/tasks/{id}", hPentaTaskManage)
	mux.HandleFunc("/api/v2/penta/tasks/{id}/run", hPentaRun)
	mux.HandleFunc("/api/v2/penta/tasks/{id}/result", hPentaResult)
	mux.HandleFunc("/api/v2/penta/templates", hPentaTemplates)
	mux.HandleFunc("/api/v2/penta/templates/import", hPentaTplImport)
	mux.HandleFunc("/api/v2/penta/tasks/{id}/feedback", hPentaFeedback)
	mux.HandleFunc("/api/v2/penta/audit", hPentaAuditList)
	mux.HandleFunc("DELETE /api/v2/penta/audit", hPentaAuditClear)
	return mux
}

func callPenta(t *testing.T, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	w := httptest.NewRecorder()
	pentaTestRouter().ServeHTTP(w, req)
	return w
}

// TestPentaTaskLifecycle 渗透任务全生命周期(离线, 不执行真实网络验证):
// 创建 -> 漏洞导入(幂等) -> 保存结果 -> 一键回传(漏洞条目被更新) -> 导出 -> 批量删除。
func TestPentaTaskLifecycle(t *testing.T) {
	d := installPentaTestDB(t)

	// 1) status: 安全声明 + 内置模板数
	w := callPenta(t, "GET", "/api/v2/penta/status", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "statement") ||
		!strings.Contains(w.Body.String(), `"builtinCount"`) {
		t.Fatalf("status code=%d body=%.200s", w.Code, w.Body.String())
	}

	// 2) 手动创建任务
	w = callPenta(t, "POST", "/api/v2/penta/tasks",
		`{"target":"10.0.0.5","port":6379,"protocol":"tcp","title":"Redis 未授权访问","cve":"CVE-1","templateId":"redis-unauth"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("create code=%d body=%.200s", w.Code, w.Body.String())
	}
	var created struct {
		Data struct {
			Task struct {
				ID string `json:"id"`
			} `json:"task"`
		} `json:"data"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &created)
	taskID := created.Data.Task.ID
	if taskID == "" {
		t.Fatalf("创建未返回任务 ID: %.300s", w.Body.String())
	}

	// 3) 从漏洞管理导入: 先造一条漏洞, 导入后应建任务并建议模板
	vuln := &db.Vuln{Vuln: models.Vuln{
		ID: "vuln-penta-1", AssetIP: "10.0.0.5", Port: 6379, Protocol: "tcp",
		Title: "Redis 未授权访问", Severity: "high", Status: models.VulnStatusNew,
		FoundAt: time.Now(),
	}}
	if err := d.Vulns().Create(vuln); err != nil {
		t.Fatalf("vuln create: %v", err)
	}
	w = callPenta(t, "POST", "/api/v2/penta/tasks/import", `{"vulnIds":["vuln-penta-1"]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"created":1`) {
		t.Fatalf("import code=%d body=%.200s", w.Code, w.Body.String())
	}
	// 重复导入 = 幂等(跳过, 不产生重复任务)
	w = callPenta(t, "POST", "/api/v2/penta/tasks/import", `{"vulnIds":["vuln-penta-1"]}`)
	if !strings.Contains(w.Body.String(), `"created":0`) || !strings.Contains(w.Body.String(), `"skipped":1`) {
		t.Fatalf("重复导入应幂等: %.200s", w.Body.String())
	}
	// 不存在的漏洞 = missing
	w = callPenta(t, "POST", "/api/v2/penta/tasks/import", `{"vulnIds":["no-such"]}`)
	if !strings.Contains(w.Body.String(), `"missing":1`) {
		t.Fatalf("不存在漏洞应计入 missing: %.200s", w.Body.String())
	}

	// 4) 保存验证结果(结论 + 风险定级修正)
	importedID := ""
	{
		w2 := callPenta(t, "GET", "/api/v2/penta/tasks", "")
		var list struct {
			Data struct {
				List []struct {
					ID     string `json:"id"`
					VulnID string `json:"vulnId"`
				} `json:"list"`
			} `json:"data"`
		}
		_ = json.Unmarshal(w2.Body.Bytes(), &list)
		for _, it := range list.Data.List {
			if it.VulnID == "vuln-penta-1" {
				importedID = it.ID
			}
		}
	}
	if importedID == "" {
		t.Fatal("导入的任务未出现在列表")
	}
	w = callPenta(t, "PUT", "/api/v2/penta/tasks/"+importedID,
		`{"exploitability":"exploitable","riskLevel":"critical","summary":"验证命中"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("save result code=%d body=%.200s", w.Code, w.Body.String())
	}
	// 非法结论值必须拒绝
	w = callPenta(t, "PUT", "/api/v2/penta/tasks/"+importedID, `{"exploitability":"destroyed"}`)
	if w.Code != 400 {
		t.Fatalf("非法结论应 400, 实际 %d", w.Code)
	}

	// 5) 一键回传: 漏洞条目必须被更新(验证结论 + 定级修正覆盖 Severity)
	w = callPenta(t, "POST", "/api/v2/penta/tasks/"+importedID+"/feedback", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("feedback code=%d body=%.200s", w.Code, w.Body.String())
	}
	v, err := d.Vulns().Get("vuln-penta-1")
	if err != nil {
		t.Fatalf("vuln get: %v", err)
	}
	if v.PentaResult != "exploitable" || v.Severity != "critical" ||
		v.PentaTaskID != importedID || v.PentaVerifiedAt == nil {
		t.Fatalf("回传后漏洞条目未更新: %+v", v)
	}
	// 手动任务无关联漏洞 = 400
	w = callPenta(t, "POST", "/api/v2/penta/tasks/"+taskID+"/feedback", "")
	if w.Code != 400 {
		t.Fatalf("无关联漏洞的回传应 400, 实际 %d", w.Code)
	}

	// 6) 导出: JSON 下载头
	w = callPenta(t, "POST", "/api/v2/penta/tasks/export", `{"ids":["`+importedID+`"]}`)
	if w.Code != 200 || !strings.Contains(w.Header().Get("Content-Disposition"), "attachment") {
		t.Fatalf("export code=%d header=%q", w.Code, w.Header().Get("Content-Disposition"))
	}
	if !strings.Contains(w.Body.String(), "vuln-penta-1") {
		t.Fatal("导出内容应含任务(含关联漏洞 ID)")
	}

	// 7) 执行未确认授权 = 400(合规硬门槛, 离线即可守)
	w = callPenta(t, "POST", "/api/v2/penta/tasks/"+importedID+"/run", `{"ack":false}`)
	if w.Code != 400 || !strings.Contains(w.Body.String(), "授权确认") {
		t.Fatalf("未 ack 应 400: code=%d body=%.200s", w.Code, w.Body.String())
	}

	// 8) 批量删除
	w = callPenta(t, "POST", "/api/v2/penta/tasks/batch",
		`{"ids":["`+importedID+`","`+taskID+`"]}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted":2`) {
		t.Fatalf("batch delete code=%d body=%.200s", w.Code, w.Body.String())
	}
}

// TestPentaTemplates API: 内置列表 + 自定义导入(含路径穿越拒绝)。
func TestPentaTemplates(t *testing.T) {
	installPentaTestDB(t)

	// 内置列表含 redis-unauth, tag 筛选生效
	w := callPenta(t, "GET", "/api/v2/penta/templates", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "redis-unauth") {
		t.Fatalf("templates code=%d", w.Code)
	}
	w = callPenta(t, "GET", "/api/v2/penta/templates?tag=redis", "")
	if !strings.Contains(w.Body.String(), "redis-unauth") {
		t.Fatal("tag=redis 应命中 redis-unauth")
	}

	// 自定义导入(合法)
	custom := "id: penta-smoke\nname: 冒烟模板\ntags: [test]\nsteps:\n  - name: s\n    type: tcp\n    expect: '.'\n"
	w = callPenta(t, "POST", "/api/v2/penta/templates/import", `{"content":`+pentaJSONStr(t, custom)+`}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"ok":true`) {
		t.Fatalf("tpl import code=%d body=%.200s", w.Code, w.Body.String())
	}
	// 与内置同 ID 拒绝
	w = callPenta(t, "POST", "/api/v2/penta/templates/import",
		`{"content":"id: redis-unauth\nname: x\nsteps:\n  - {name: s, type: tcp}\n"}`)
	if w.Code != 400 {
		t.Fatalf("内置 ID 冲突应 400, 实际 %d", w.Code)
	}
	// 路径穿越 ID 拒绝
	w = callPenta(t, "POST", "/api/v2/penta/templates/import",
		`{"content":"id: ../evil\nname: x\nsteps:\n  - {name: s, type: tcp}\n"}`)
	if w.Code != 400 {
		t.Fatalf("路径穿越 ID 应 400, 实际 %d", w.Code)
	}
}

// TestPentaAuditSeparate 渗透审计落独立表, 不混入通用审计(分类边界契约)。
//
// 守的是: 用户操作(此处=创建任务)产生的 penta.* 审计必须出现在独立表,
// 且通用审计表查不到 penta.* —— 若回归成混存, "清空日志"会威胁到合规留痕。
func TestPentaAuditSeparate(t *testing.T) {
	d := installPentaTestDB(t)

	// 创建任务 -> penta.task.create 必须写独立表
	w := callPenta(t, "POST", "/api/v2/penta/tasks",
		`{"target":"10.0.0.9","port":22,"protocol":"tcp","title":"SSH 弱口令验证"}`)
	if w.Code != 200 {
		t.Fatalf("create code=%d body=%.200s", w.Code, w.Body.String())
	}

	la, _, lerr := d.PentaAudits().Query(db.AuditFilter{})
	if lerr != nil || len(la) != 1 || la[0].Action != "penta.task.create" {
		t.Fatalf("独立表应有 1 条 penta.task.create: len=%d err=%v", len(la), lerr)
	}

	// 通用审计表不得出现 penta.*
	ga, _, gerr := d.Audits().Query(db.AuditFilter{})
	if gerr != nil {
		t.Fatalf("通用审计查询: %v", gerr)
	}
	for _, g := range ga {
		if strings.HasPrefix(g.Action, "penta.") {
			t.Fatalf("通用审计表混入了 penta.*: %s", g.Action)
		}
	}

	// 独立表接口可读(筛选口径与通用审计一致)
	w = callPenta(t, "GET", "/api/v2/penta/audit", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "penta.task.create") {
		t.Fatalf("audit list code=%d body=%.200s", w.Code, w.Body.String())
	}
}

// TestPentaAuditClear 管理员清空入口的契约(分发/数据交接场景):
// 清空后原记录全部消失, 且必须剩一条 penta.audit.clear 痕迹(含被清条数)
// —— 记录可清, 但"被清过"永远可审计, 不是无痕擦除。
func TestPentaAuditClear(t *testing.T) {
	d := installPentaTestDB(t)

	// 造 2 条审计: 创建任务(自动写 penta.task.create) + 再建一条
	w := callPenta(t, "POST", "/api/v2/penta/tasks",
		`{"target":"10.0.0.9","port":6379,"protocol":"tcp","title":"Redis 未授权访问","templateId":"redis-unauth"}`)
	if w.Code != 200 {
		t.Fatalf("create code=%d body=%.200s", w.Code, w.Body.String())
	}
	w = callPenta(t, "POST", "/api/v2/penta/tasks",
		`{"target":"10.0.0.10","port":22,"protocol":"tcp","title":"SSH 弱口令验证"}`)
	if w.Code != 200 {
		t.Fatalf("create2 code=%d body=%.200s", w.Code, w.Body.String())
	}
	if n, _ := d.PentaAudits().Count(); n != 2 {
		t.Fatalf("清空前应有 2 条审计, 实际 %d", n)
	}

	// 清空
	w = callPenta(t, "DELETE", "/api/v2/penta/audit", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted":2`) {
		t.Fatalf("clear code=%d body=%.200s", w.Code, w.Body.String())
	}

	// 清空后: 表里只剩 penta.audit.clear 痕迹, 且痕迹含被清条数
	la, _, err := d.PentaAudits().Query(db.AuditFilter{})
	if err != nil {
		t.Fatalf("query: %v", err)
	}
	if len(la) != 1 || la[0].Action != "penta.audit.clear" {
		t.Fatalf("清空后应只剩 1 条 penta.audit.clear: len=%d", len(la))
	}
	if !strings.Contains(la[0].Detail, "2") {
		t.Fatalf("痕迹应含被清条数: %s", la[0].Detail)
	}

	// 列表接口口径同步(前端清完刷新列表看到的就是这条痕迹)
	w = callPenta(t, "GET", "/api/v2/penta/audit", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "penta.audit.clear") ||
		!strings.Contains(w.Body.String(), `"total":1`) {
		t.Fatalf("audit list code=%d body=%.200s", w.Code, w.Body.String())
	}
}

func pentaJSONStr(t *testing.T, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatalf("json: %v", err)
	}
	return string(b)
}
