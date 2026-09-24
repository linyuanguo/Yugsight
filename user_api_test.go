package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"yugsight/account"
	"yugsight/db"
)

// RBAC 契约测试(任务: 多用户 + 角色权限)。
//
// 守住的契约(被改坏=安全红线失效, 不是功能退化):
//  1. auditor 调写接口必须 403 —— 只读角色不能自我提权/删资产/触发扫描
//  2. admin 调同一接口必须 200
//  3. 唯一的启用中管理员不可降权/停用/删除(否则系统锁死, 无人能管理)
//  4. 改密码/停用必须双轨同步(db 用户表 + authStore)—— 只改一侧会出现
//     "停用账号还能登录"或"新密码登录被拒"的漏洞
//
// 测试环境(newV2TestEnv)authDisabled=true, requireAuth 直通, adminOnly 是唯一
// 有效的角色检查 —— 恰好隔离验证"角色判定"本身, 不受登录流程(限流/2FA)干扰。

// resetAccountMgr 把 accountMgr 单例指向测试库(每个用例独立库, 必须重置,
// 否则 once 消费掉后后续用例还指着上一个已关闭的库 —— 与 schedAPITestMode 同手法)。
func resetAccountMgr(t *testing.T, d *db.Database) {
	t.Helper()
	accountMgrOnce = sync.Once{}
	accountMgrInst = account.NewManager(d.Users(), d.Sessions(), 12*time.Hour, func(string) {})
	t.Cleanup(func() {
		accountMgrOnce = sync.Once{}
		accountMgrInst = nil
	})
}

// injectSession 注入指定角色的会话并注册清理。
//
// 清理里取锁的隐患: 若测试体在"已持 authMu"状态下 panic/Fatal, Goexit 会先
// 跑清理 —— 清理再 Lock 同一把锁就是自死锁(实测踩过)。因此测试体所有持锁段
// 一律 defer Unlock(panic 也能释放), 清理只在"锁必已释放"的测试收尾阶段跑。
func injectSession(t *testing.T, tok, user, role string) {
	t.Helper()
	authMu.Lock()
	sessions[tok] = sessionRec{exp: time.Now().Add(time.Hour), user: user, role: role}
	authMu.Unlock()
	t.Cleanup(func() {
		authMu.Lock()
		delete(sessions, tok)
		authMu.Unlock()
	})
}

// setupAuthStore 测试环境初始化 authStore(生产里由 loadAuth 在 main 里做)。
// 双轨同步用例依赖它: authStore 为 nil 时 syncAuthStore 是 no-op, "双轨同步"
// 无从谈起。持久化替换为 no-op —— 用例绝不能写开发机真实 settings.json。
func setupAuthStore(t *testing.T) {
	t.Helper()
	prevStore, prevSave := loadAuthState()
	authMu.Lock()
	authStore = &userStore{Salt: randHex(16), Users: map[string]userRec{}}
	authMu.Unlock()
	authSaveFunc = func() {}
	t.Cleanup(func() {
		authMu.Lock()
		authStore = prevStore
		authMu.Unlock()
		authSaveFunc = prevSave
	})
}

// loadAuthState 快照当前 authStore 与持久化函数(供 setupAuthStore 还原)。
func loadAuthState() (*userStore, func()) {
	authMu.Lock()
	s := authStore
	authMu.Unlock()
	return s, authSaveFunc
}

// newUsersMux 复刻 main 的 users 路由注册。
//
// 必须经真实 ServeMux 调用(不能直调 handler): handler 用 r.PathValue("name")
// 取路径参数, 只有 ServeMux 按模式匹配后才会填充 —— 直调时 PathValue 恒为空,
// update/delete 会静默变成"操作空用户名"(假成功/假 4xx, 测试全错位)。
func newUsersMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v2/users", requireAuth(adminOnly(handleUsersCollection)))
	mux.HandleFunc("/api/v2/users/me", requireAuth(handleUsersMe))
	mux.HandleFunc("/api/v2/users/{name}", requireAuth(adminOnly(handleUsersManage)))
	return mux
}

// usersReq 以指定会话经真实 mux 调用 users 路由。
func usersReq(t *testing.T, method, path, body, tok string) *httptest.ResponseRecorder {
	t.Helper()
	var req *http.Request
	if body != "" {
		req = httptest.NewRequest(method, path, strings.NewReader(body))
	} else {
		req = httptest.NewRequest(method, path, nil)
	}
	req.AddCookie(&http.Cookie{Name: "yugsight_session", Value: tok})
	w := httptest.NewRecorder()
	newUsersMux().ServeHTTP(w, req)
	return w
}

func createUserViaAPI(t *testing.T, username, pass, role, tok string) *httptest.ResponseRecorder {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"username": username, "password": pass, "role": role})
	w := usersReq(t, http.MethodPost, "/api/v2/users", string(payload), tok)
	if w.Code != 200 {
		t.Fatalf("创建用户 %s 失败 status=%d body=%s", username, w.Code, w.Body.String())
	}
	return w
}

// TestUsersRBAC: auditor 403 / admin 200 / /me 人人可查自己
func TestUsersRBAC(t *testing.T) {
	h, d := newV2TestEnv(t)
	_ = h
	// newV2TestEnv 默认免登录(authDisabled=true), 而 adminOnly 在免登录模式
	// 下直通(规则 6) —— 角色判定会被架空。显式打开登录, 让 adminOnly 成为
	// 唯一有效的角色检查(与 rbac_test.go 同手法)。
	authDisabled = false
	t.Cleanup(func() { authDisabled = true })
	resetAccountMgr(t, d)
	injectSession(t, "tok-auditor", "u-auditor", db.RoleAuditor)
	injectSession(t, "tok-admin", "u-admin", db.RoleAdmin)

	if w := usersReq(t, http.MethodGet, "/api/v2/users", "", "tok-auditor"); w.Code != 403 {
		t.Fatalf("auditor 调用户列表 status=%d, 期望 403", w.Code)
	}
	if w := usersReq(t, http.MethodPost, "/api/v2/users", `{"username":"x","password":"123456","role":"admin"}`, "tok-auditor"); w.Code != 403 {
		t.Fatalf("auditor 创建 admin 账号(自我提权) status=%d, 期望 403", w.Code)
	}
	if w := usersReq(t, http.MethodGet, "/api/v2/users", "", "tok-admin"); w.Code != 200 {
		t.Fatalf("admin 调用户列表 status=%d, 期望 200", w.Code)
	}
	if w := usersReq(t, http.MethodGet, "/api/v2/users/me", "", "tok-auditor"); w.Code != 200 {
		t.Fatalf("auditor 查自己 status=%d, 期望 200", w.Code)
	} else if !strings.Contains(w.Body.String(), db.RoleAuditor) {
		t.Fatalf("/me 应回 auditor 角色, body=%s", w.Body.String())
	}
}

// TestLastAdminProtected: 唯一启用中的 admin 不可降权/停用/删除
func TestLastAdminProtected(t *testing.T) {
	_, d := newV2TestEnv(t)
	resetAccountMgr(t, d)
	injectSession(t, "tok-admin", "solo-admin", db.RoleAdmin)
	createUserViaAPI(t, "solo-admin", "pass1234", db.RoleAdmin, "tok-admin")

	if w := usersReq(t, http.MethodPut, "/api/v2/users/solo-admin", `{"role":"auditor"}`, "tok-admin"); w.Code < 400 {
		t.Fatalf("降权唯一 admin status=%d, 期望 4xx", w.Code)
	}
	if w := usersReq(t, http.MethodPut, "/api/v2/users/solo-admin", `{"enabled":false}`, "tok-admin"); w.Code < 400 {
		t.Fatalf("停用唯一 admin status=%d, 期望 4xx", w.Code)
	}
	if w := usersReq(t, http.MethodDelete, "/api/v2/users/solo-admin", "", "tok-admin"); w.Code < 400 {
		t.Fatalf("删除唯一 admin status=%d, 期望 4xx", w.Code)
	}
	// 账号仍在且仍是 admin(前面三次操作都必须未生效)
	m := accountMgr()
	u, err := m.Users.Get("solo-admin")
	if err != nil || u.Role != db.RoleAdmin || !u.Enabled {
		t.Fatalf("唯一 admin 状态被破坏: %+v err=%v", u, err)
	}
}

// TestPasswordChangeDualSync: 改密码必须 db 表(bcrypt) 与 authStore(sha256) 两侧一致
func TestPasswordChangeDualSync(t *testing.T) {
	_, d := newV2TestEnv(t)
	resetAccountMgr(t, d)
	setupAuthStore(t)
	injectSession(t, "tok-admin", "u-admin", db.RoleAdmin)
	createUserViaAPI(t, "dual1", "pass1234", db.RoleAdmin, "tok-admin")

	if w := usersReq(t, http.MethodPut, "/api/v2/users/dual1", `{"password":"newpass56"}`, "tok-admin"); w.Code != 200 {
		t.Fatalf("改密码 status=%d body=%s", w.Code, w.Body.String())
	}
	// authStore 侧(登录校验走这里): 必须是新密码哈希。
	// 持锁段用 defer 释放: 段内任何 panic 都不会把锁留到清理阶段(自死锁)。
	var rec userRec
	var ok bool
	var salt string
	authMu.Lock()
	defer authMu.Unlock()
	rec, ok = authStore.Users["dual1"]
	salt = authStore.Salt
	if !ok {
		t.Fatal("authStore 未同步 dual1")
	}
	if rec.PassHash != hashPass(salt, "newpass56") {
		t.Fatal("authStore 侧密码哈希未同步(新密码登录会被拒)")
	}
	// db 表侧(bcrypt): 新密码可过, 旧密码不可过
	m := accountMgr()
	if _, err := m.Verify("dual1", "newpass56"); err != nil {
		t.Fatalf("db 表侧新密码校验失败: %v", err)
	}
	if _, err := m.Verify("dual1", "pass1234"); err == nil {
		t.Fatal("db 表侧旧密码仍能过(未更新)")
	}
}

// TestDisableUserDualSync: 停用账号 → authStore 移除(不能再登录) + 会话全踢
func TestDisableUserDualSync(t *testing.T) {
	_, d := newV2TestEnv(t)
	resetAccountMgr(t, d)
	setupAuthStore(t)
	injectSession(t, "tok-admin", "u-admin", db.RoleAdmin)
	// 会话用户必须先存在于用户表(admin): 否则后建的 off1 会因"首个账号自动
	// 提升 admin"而变成唯一 admin, 停用被 ErrLastAdmin 挡住(与生产语义一致:
	// 登录者必然是表内用户)。
	createUserViaAPI(t, "u-admin", "pass1234", db.RoleAdmin, "tok-admin")
	createUserViaAPI(t, "off1", "pass1234", db.RoleAuditor, "tok-admin")
	injectSession(t, "tok-off1", "off1", db.RoleAuditor)

	if w := usersReq(t, http.MethodPut, "/api/v2/users/off1", `{"enabled":false}`, "tok-admin"); w.Code != 200 {
		t.Fatalf("停用 status=%d body=%s", w.Code, w.Body.String())
	}
	var inStore, sessAlive bool
	authMu.Lock()
	defer authMu.Unlock()
	_, inStore = authStore.Users["off1"]
	_, sessAlive = sessions["tok-off1"]
	if inStore {
		t.Fatal("停用后 authStore 仍有该账号(还能登录)")
	}
	if sessAlive {
		t.Fatal("停用后会话未踢出")
	}
}

// TestUnregisterableEmpty: 空库创建首个用户自动提升 admin(manager 既有语义回归)
func TestFirstUserAutoAdmin(t *testing.T) {
	_, d := newV2TestEnv(t)
	resetAccountMgr(t, d)
	injectSession(t, "tok-x", "u-x", db.RoleAdmin)
	createUserViaAPI(t, "first1", "pass1234", db.RoleAuditor, "tok-x")
	m := accountMgr()
	u, err := m.Users.Get("first1")
	if err != nil || u.Role != db.RoleAdmin {
		t.Fatalf("首个用户应自动提升 admin: %+v err=%v", u, err)
	}
}
