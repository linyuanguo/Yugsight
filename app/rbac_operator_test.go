package main

// RBAC 三角色契约测试(2026-09-22 新增"操作员"角色)。
//
// 守住的契约(改坏 = 权限边界静默失效, 不报错, 只会越权或功能凭空消失):
//  1. operator 能调业务写接口(adminOrOperator), 但碰不到账号体系(adminOnly)——
//     账号体系是提权红线: operator 若能建 admin, 就等于自我提权。
//  2. auditor 仍一律 403(只读): 放开放弃 adminOnly 时不能把只读角色一起放进来。
//  3. DELETE /api/v2/vulns 真清空漏洞表且不动资产表, 并留下 vuln.clear 审计记录。
//  4. DELETE /api/v2/audit 清空后必须剩一条 audit.clear 留痕 —— "日志被清空"
//     这件事本身要可查, 否则等于审计被无声抹掉。
//
// 环境注意: newV2TestEnv 默认免登录(authDisabled=true), 此时中间件全部直通、
// 角色判定被架空 —— 本文件显式打开登录并用 injectSession 注入指定角色的会话。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yugsight/internal/db"
)

// doReqAs 带会话 cookie 请求(doReq 不带 cookie, 登录模式下会被 401 掉)。
func doReqAs(t *testing.T, h http.Handler, method, path, body, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	if tok != "" {
		req.AddCookie(&http.Cookie{Name: "yugsight_session", Value: tok})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// setupRoleSessions 打开登录模式并注入三种角色的会话(各自独立临时库)。
func setupRoleSessions(t *testing.T, d *db.Database) {
	t.Helper()
	authDisabled = false
	t.Cleanup(func() { authDisabled = true })
	resetAccountMgr(t, d)
	injectSession(t, "tok-admin", "u-admin", db.RoleAdmin)
	injectSession(t, "tok-operator", "u-op", db.RoleOperator)
	injectSession(t, "tok-auditor", "u-aud", db.RoleAuditor)
}

// TestOperatorRoleBoundary: operator = 业务写操作可用 + 账号体系/审计清理不可用。
func TestOperatorRoleBoundary(t *testing.T) {
	h, d := newV2TestEnv(t)
	setupRoleSessions(t, d)

	// operator 能写业务数据(资产 upsert 走 adminOrOperator)
	if w := doReqAs(t, h, http.MethodPost, "/api/v2/assets", `{"ip":"10.9.9.1"}`, "tok-operator"); w.Code != 200 {
		t.Fatalf("operator 写资产 status=%d body=%s, 期望 200", w.Code, w.Body.String())
	}
	// auditor 仍然只读(放开 adminOnly 时不能把只读角色一起放进来)
	if w := doReqAs(t, h, http.MethodPost, "/api/v2/assets", `{"ip":"10.9.9.2"}`, "tok-auditor"); w.Code != 403 {
		t.Fatalf("auditor 写资产 status=%d, 期望 403", w.Code)
	}
	// operator 碰不到账号体系: 能建 admin 就等于自我提权
	if w := usersReq(t, http.MethodGet, "/api/v2/users", "", "tok-operator"); w.Code != 403 {
		t.Fatalf("operator 调用户列表 status=%d, 期望 403", w.Code)
	}
	if w := usersReq(t, http.MethodPost, "/api/v2/users",
		`{"username":"evil","password":"123456","role":"admin"}`, "tok-operator"); w.Code != 403 {
		t.Fatalf("operator 尝试自建 admin status=%d, 期望 403", w.Code)
	}
	// 审计清理同样是 admin 专属
	if w := doReqAs(t, h, http.MethodDelete, "/api/v2/audit", "", "tok-operator"); w.Code != 403 {
		t.Fatalf("operator 清空审计 status=%d, 期望 403", w.Code)
	}
	if w := doReqAs(t, h, http.MethodDelete, "/api/v2/audit", "", "tok-admin"); w.Code != 200 {
		t.Fatalf("admin 清空审计 status=%d body=%s, 期望 200", w.Code, w.Body.String())
	}
}

// TestVulnClearAllKeepsAssets: 清空全部漏洞 = 只清漏洞表 + 留审计痕迹。
func TestVulnClearAllKeepsAssets(t *testing.T) {
	h, d := newV2TestEnv(t)
	setupRoleSessions(t, d)

	for _, ip := range []string{"10.8.0.1", "10.8.0.2"} {
		if _, err := d.Vulns().Upsert(db.NewVuln(ip, "测试漏洞 "+ip, "high")); err != nil {
			t.Fatalf("seed vuln %s: %v", ip, err)
		}
	}
	if w := doReqAs(t, h, http.MethodPost, "/api/v2/assets", `{"ip":"10.8.0.1"}`, "tok-operator"); w.Code != 200 {
		t.Fatalf("seed asset status=%d", w.Code)
	}

	// auditor 不能清库(新增的集合级 DELETE 不能误开放)
	if w := doReqAs(t, h, http.MethodDelete, "/api/v2/vulns", "", "tok-auditor"); w.Code != 403 {
		t.Fatalf("auditor 清空漏洞 status=%d, 期望 403", w.Code)
	}

	w := doReqAs(t, h, http.MethodDelete, "/api/v2/vulns", "", "tok-operator")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted":2`) {
		t.Fatalf("清空 status=%d body=%s, 期望 deleted=2", w.Code, w.Body.String())
	}
	if n, _ := d.Vulns().Count(); n != 0 {
		t.Fatalf("清空后漏洞表 count=%d, 期望 0", n)
	}
	// 资产台账不受影响(用户只想清漏洞数据)
	if n, _ := d.Assets().Count(); n != 1 {
		t.Fatalf("清空漏洞后资产 count=%d, 期望 1", n)
	}
	// 破坏性操作必须留痕
	if recs, _, err := d.Audits().Query(db.AuditFilter{Action: "vuln.clear"}); err != nil || len(recs) != 1 {
		t.Fatalf("缺少 vuln.clear 审计记录: len=%d err=%v", len(recs), err)
	}
}

// TestScanClearAllKeepsAssets: 首页"清空历史记录"走集合级 DELETE /api/v2/scans。
// 守三条契约: 只读角色清不动、只清任务表(资产/漏洞不动)、破坏性动作留审计。
func TestScanClearAllKeepsAssets(t *testing.T) {
	h, d := newV2TestEnv(t)
	setupRoleSessions(t, d)

	for _, ip := range []string{"10.9.0.1", "10.9.0.2", "10.9.0.3"} {
		if err := d.ScanTasks().Create(&db.ScanTask{Type: "port", Target: ip, CreatedBy: "admin"}); err != nil {
			t.Fatalf("seed scan task %s: %v", ip, err)
		}
	}
	if w := doReqAs(t, h, http.MethodPost, "/api/v2/assets", `{"ip":"10.9.0.1"}`, "tok-operator"); w.Code != 200 {
		t.Fatalf("seed asset status=%d", w.Code)
	}

	// 只读角色不能清(与漏洞清空同一红线)
	if w := doReqAs(t, h, http.MethodDelete, "/api/v2/scans", "", "tok-auditor"); w.Code != 403 {
		t.Fatalf("auditor 清空任务 status=%d, 期望 403", w.Code)
	}

	w := doReqAs(t, h, http.MethodDelete, "/api/v2/scans", "", "tok-operator")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"deleted":3`) {
		t.Fatalf("清空 status=%d body=%s, 期望 deleted=3", w.Code, w.Body.String())
	}
	if n, _ := d.ScanTasks().Count(); n != 0 {
		t.Fatalf("清空后任务表 count=%d, 期望 0", n)
	}
	// 只清任务: 资产台账不受影响
	if n, _ := d.Assets().Count(); n != 1 {
		t.Fatalf("清空任务后资产 count=%d, 期望 1", n)
	}
	// 破坏性操作必须留痕
	if recs, _, err := d.Audits().Query(db.AuditFilter{Action: "scan.clear"}); err != nil || len(recs) != 1 {
		t.Fatalf("缺少 scan.clear 审计记录: len=%d err=%v", len(recs), err)
	}
}

// TestAuditClearLeavesTrace: 单条删除 + 清空都要留痕, 清空后只剩留痕那条。
func TestAuditClearLeavesTrace(t *testing.T) {
	h, d := newV2TestEnv(t)
	setupRoleSessions(t, d)

	for i := 0; i < 3; i++ {
		if err := d.Audits().Append(db.AuditLog{UserID: "u-admin", Action: "test.noise", Target: "n"}); err != nil {
			t.Fatalf("append audit: %v", err)
		}
	}

	// 单条删除: 删掉 1 条 noise, 同时补 1 条 audit.delete 留痕 -> 总数不变
	list, _, err := d.Audits().Query(db.AuditFilter{Action: "test.noise"})
	if err != nil || len(list) != 3 {
		t.Fatalf("seed 审计: len=%d err=%v", len(list), err)
	}
	if w := doReqAs(t, h, http.MethodDelete, "/api/v2/audit/"+list[0].ID, "", "tok-admin"); w.Code != 200 {
		t.Fatalf("删单条 status=%d body=%s", w.Code, w.Body.String())
	}
	if n, _ := d.Audits().Count(); n != 3 {
		t.Fatalf("单条删除后 count=%d, 期望 3(2 noise + 1 条留痕)", n)
	}
	if w := doReqAs(t, h, http.MethodDelete, "/api/v2/audit/al-not-exist", "", "tok-admin"); w.Code != 404 {
		t.Fatalf("删不存在的记录 status=%d, 期望 404", w.Code)
	}

	// 清空全部: 清完只应剩"清空"这一条留痕
	if w := doReqAs(t, h, http.MethodDelete, "/api/v2/audit", "", "tok-admin"); w.Code != 200 {
		t.Fatalf("清空 status=%d body=%s", w.Code, w.Body.String())
	}
	left, total, qerr := d.Audits().Query(db.AuditFilter{})
	if qerr != nil {
		t.Fatalf("query: %v", qerr)
	}
	if total != 1 || len(left) != 1 || left[0].Action != "audit.clear" {
		t.Fatalf("清空后应只剩 1 条 audit.clear 留痕, total=%d list=%+v", total, left)
	}
}
