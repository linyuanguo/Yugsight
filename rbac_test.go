package main

// RBAC 权限契约测试(任务: 多用户 + 角色权限)。
//
// 守两个"被改坏会静默失效"的契约:
//
//  1. 免登录模式(test_mode.txt/-no-auth)下 adminOnly 直通 —— 若被移除,
//     测试模式下所有写接口 403、整个前端不可用, 而每个接口只单独报
//     "需要管理员权限", 用户会先怀疑没登录(规则 6 契约)。
//  2. 需登录时 auditor 只读角色: 读接口 200、写接口 403。403 是后端兜底 ——
//     前端隐藏入口只是 UI 提示, 直接调 API 也不能越权提权。
//
// 鉴权状态用 newV2TestEnv(authDisabled=true)+ 注入会话 隔离, 不碰真实
// 登录流程(限流/2FA), 只验证"角色判定"本身。

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"yugsight/db"
)

// newRBACTestEnv v2 测试环境 + 指定免登录开关状态。
// newV2TestEnv 本身置 authDisabled=true; 需"登录开启"时在其后覆盖。
func newRBACTestEnv(t *testing.T, authOff bool) (http.Handler, *db.Database) {
	t.Helper()
	h, d := newV2TestEnv(t)
	if !authOff {
		authDisabled = false
		t.Cleanup(func() { authDisabled = true })
	}
	return h, d
}

// rbacReq 带(或无)会话 cookie 请求一次, 返回响应记录。
func rbacReq(t *testing.T, h http.Handler, method, target, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, target, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, target, nil)
	}
	if token != "" {
		req.AddCookie(&http.Cookie{Name: "yugsight_session", Value: token})
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w
}

// TestRBACTestModePassthrough 契约 1: 免登录模式(无会话)写接口不得被
// adminOnly 拦成 403 —— 参数校验可以 400, 但绝不能 403。
func TestRBACTestModePassthrough(t *testing.T) {
	h, _ := newRBACTestEnv(t, true)

	w := rbacReq(t, h, http.MethodGet, "/api/v2/vulns", "", "")
	if w.Code != http.StatusOK {
		t.Fatalf("免登录模式读接口应 200, 实际 %d: %s", w.Code, w.Body.String())
	}
	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/api/v2/vulns"},
		{http.MethodPut, "/api/v2/assets/whatever"},
		{http.MethodPost, "/api/v2/whitelist"},
		{http.MethodPost, "/api/v2/scans"},
		{http.MethodDelete, "/api/v2/sessions/whatever"},
	} {
		w = rbacReq(t, h, tc.method, tc.target, `{}`, "")
		if w.Code == http.StatusForbidden {
			t.Fatalf("免登录模式 %s %s 被 adminOnly 拦成 403(规则 6: 测试模式跳过所有鉴权): %s",
				tc.method, tc.target, w.Body.String())
		}
	}
}

// TestRBACAuditorDeniedAdminAllowed 契约 2: 登录开启时,
// auditor 读 200 / 写 403; admin 写接口不被 RBAC 拦截(可以参数 400, 不能 403);
// 无会话 401。
func TestRBACAuditorDeniedAdminAllowed(t *testing.T) {
	h, _ := newRBACTestEnv(t, false)
	injectSession(t, "tok-rbac-auditor", "aud1", db.RoleAuditor)
	injectSession(t, "tok-rbac-admin", "adm1", db.RoleAdmin)

	// 无会话: 401(requireAuth 先于 adminOnly)
	if w := rbacReq(t, h, http.MethodGet, "/api/v2/vulns", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("无会话应 401, 实际 %d", w.Code)
	}

	// auditor: 读接口放行
	if w := rbacReq(t, h, http.MethodGet, "/api/v2/vulns", "", "tok-rbac-auditor"); w.Code != http.StatusOK {
		t.Fatalf("auditor 读接口应 200, 实际 %d: %s", w.Code, w.Body.String())
	}
	// auditor: 写接口一律 403(后端兜底, 与前端是否隐藏入口无关)
	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/api/v2/vulns"},
		{http.MethodPut, "/api/v2/vulns/whatever"},
		{http.MethodDelete, "/api/v2/vulns/whatever"},
		{http.MethodPost, "/api/v2/assets"},
		{http.MethodPut, "/api/v2/assets/whatever"},
		{http.MethodPost, "/api/v2/whitelist"},
		{http.MethodPost, "/api/v2/scans"},
		{http.MethodDelete, "/api/v2/scans/whatever"},
		{http.MethodDelete, "/api/v2/sessions/whatever"},
	} {
		w := rbacReq(t, h, tc.method, tc.target, `{}`, "tok-rbac-auditor")
		if w.Code != http.StatusForbidden {
			t.Fatalf("auditor %s %s 应 403, 实际 %d: %s", tc.method, tc.target, w.Code, w.Body.String())
		}
	}

	// admin: 写接口不被 RBAC 拦截(空体可能 400 参数校验, 但不能 403)
	for _, tc := range []struct{ method, target string }{
		{http.MethodPost, "/api/v2/vulns"},
		{http.MethodPut, "/api/v2/assets/whatever"},
		{http.MethodPost, "/api/v2/scans"},
	} {
		w := rbacReq(t, h, tc.method, tc.target, `{}`, "tok-rbac-admin")
		if w.Code == http.StatusForbidden {
			t.Fatalf("admin %s %s 被 adminOnly 误拦: %s", tc.method, tc.target, w.Body.String())
		}
	}
}
