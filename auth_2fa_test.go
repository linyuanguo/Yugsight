// auth_2fa_test.go 2FA 登录链路集成测试: 种子生成/启停/登录两步/信任令牌。
//
// 数据库经 v2DBProvider 注入临时目录(勿指向 v2DB 自身, 否则无限自递归,
// 见 probe_normalize_test.go); 结束后恢复原 provider, 不污染真实 data/。
//
// 2026-09-21 收尾: 旧设置页 3 条死接口 /api/auth/2fa/status|seed|toggle 已删
// (前端零调用), 启停统一走登录前接口 /enable|/disable, 码值走 /code;
// 种子校验改为直读 db 用户表(旧的明文回显端点不在测试面内)。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"yugsight/account"
	"yugsight/db"
)

// inject2FADB 注入临时库并注册恢复。
func inject2FADB(t *testing.T) *db.Database {
	t.Helper()
	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("打开临时库失败: %v", err)
	}
	prev := v2DBProvider
	v2DBProviderMu.Lock()
	v2DBProvider = func() *db.Database { return d }
	v2DBProviderMu.Unlock()
	t.Cleanup(func() {
		v2DBProviderMu.Lock()
		v2DBProvider = prev
		v2DBProviderMu.Unlock()
	})
	return d
}

// doLoginReq 直发登录请求(可带 cookie); 返回响应(调用方关 Body)。
func doLoginReq(t *testing.T, body string, cookies []*http.Cookie) *http.Response {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	handleLogin(rec, req)
	return rec.Result()
}

// get2FA 直发 GET 到指定 handler。
func get2FA(t *testing.T, h http.HandlerFunc) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	return rec
}

// loginCode 按"当前时刻"算出应有效的动态码(±1 窗口天然覆盖跨分钟抖动)。
func loginCode(t *testing.T, seed string) string {
	t.Helper()
	code := hotpCode(seed, hotpCounterAt(time.Now()))
	if code == "" {
		t.Fatal("算码失败")
	}
	return code
}

// dbSeedOf 直读 db 用户表取当前 2FA 种子(替代已删除的 /seed 明文回显端点)。
func dbSeedOf(t *testing.T, d *db.Database, user string) string {
	t.Helper()
	u, err := d.Users().Get(user)
	if err != nil || u == nil {
		t.Fatalf("读取用户行失败: %v", err)
	}
	return u.TwoFASeed
}

// Test2FALoginFlow 全链路: 初始未配置 → 启用(自动生成种子) → 登录两步 →
// 信任令牌免码 → 停用恢复。
func Test2FALoginFlow(t *testing.T) {
	d := inject2FADB(t)
	resetAuth(t)
	resetTrustTokens()
	t.Cleanup(resetTrustTokens)
	rec := postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)
	if rec.Code != 200 {
		t.Fatalf("注册失败: %s", rec.Body.String())
	}

	// 初始未配置: 无种子、未启用(直读库; 旧 /status 死接口已删)
	u, err := d.Users().Get("alice")
	if err != nil || u.TwoFAEnabled || u.TwoFASeed != "" {
		t.Fatalf("初始状态应未配置: %+v %v", u, err)
	}

	// 启用(登录前接口: 自动生成种子并启用, 旧"无种子不可开启"路径已随开关移除)
	rec = postJSON(t, handle2FAEnable, "")
	var on struct {
		Enabled bool   `json:"enabled"`
		Error   string `json:"error"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &on)
	if !on.Enabled || on.Error != "" {
		t.Fatalf("启用失败: %s", rec.Body.String())
	}
	seed := dbSeedOf(t, d, "alice")
	if len(seed) != 32 {
		t.Fatalf("启用后库内种子应为 32 字符: %q", seed)
	}

	// 第一步: 口令对但无码 → 401 + need2fa 标记(前端据此切第二步)
	r := doLoginReq(t, `{"user":"alice","pass":"secret123"}`, nil)
	var lr struct {
		Error   string `json:"error"`
		Need2FA bool   `json:"need2fa"`
	}
	_ = json.NewDecoder(r.Body).Decode(&lr)
	r.Body.Close()
	if r.StatusCode != 401 || !lr.Need2FA {
		t.Fatalf("应 401+need2fa, got %d %+v", r.StatusCode, lr)
	}

	// 错误码 → 401
	r = doLoginReq(t, `{"user":"alice","pass":"secret123","code":"000000"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("错误码应 401, got %d", r.StatusCode)
	}

	// 正确码 → 200
	r = doLoginReq(t, `{"user":"alice","pass":"secret123","code":"`+loginCode(t, seed)+`"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("正确码应 200, got %d", r.StatusCode)
	}

	// 正确码 + trust → 200 且下发信任 cookie
	r = doLoginReq(t, `{"user":"alice","pass":"secret123","code":"`+loginCode(t, seed)+`","trust":true}`, nil)
	if r.StatusCode != 200 {
		t.Fatalf("trust 登录应 200, got %d", r.StatusCode)
	}
	var trust *http.Cookie
	for _, c := range r.Cookies() {
		if c.Name == trustCookieName {
			trust = c
		}
	}
	_ = r.Body.Close()
	if trust == nil || trust.Value == "" {
		t.Fatal("未下发信任 cookie")
	}

	// 携带信任 cookie → 免码 200; 不带 → 仍需码
	r = doLoginReq(t, `{"user":"alice","pass":"secret123"}`, []*http.Cookie{trust})
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("信任令牌应免码, got %d", r.StatusCode)
	}
	r = doLoginReq(t, `{"user":"alice","pass":"secret123"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("无信任令牌仍应要码, got %d", r.StatusCode)
	}

	// 停用 → 免码恢复
	postJSON(t, handle2FADisable, "")
	r = doLoginReq(t, `{"user":"alice","pass":"secret123"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("停用后应免码, got %d", r.StatusCode)
	}
}

// Test2FASeedResetInvalidatesCode 再次启用(重置种子)后旧码立即失效、新码有效(启用状态保持)。
func Test2FASeedResetInvalidatesCode(t *testing.T) {
	d := inject2FADB(t)
	resetAuth(t)
	resetTrustTokens()
	t.Cleanup(resetTrustTokens)
	postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)

	postJSON(t, handle2FAEnable, "")
	old := dbSeedOf(t, d, "alice")

	r := doLoginReq(t, `{"user":"alice","pass":"secret123","code":"`+loginCode(t, old)+`"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("旧码应先有效, got %d", r.StatusCode)
	}

	// 再次启用 = 重置种子(旧种子立即作废, 新种子即时生效)
	postJSON(t, handle2FAEnable, "")
	fresh := dbSeedOf(t, d, "alice")
	if fresh == "" || fresh == old {
		t.Fatal("重置应产生新种子")
	}
	r = doLoginReq(t, `{"user":"alice","pass":"secret123","code":"`+loginCode(t, old)+`"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 401 {
		t.Fatalf("旧码应失效, got %d", r.StatusCode)
	}
	r = doLoginReq(t, `{"user":"alice","pass":"secret123","code":"`+loginCode(t, fresh)+`"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("新码应有效, got %d", r.StatusCode)
	}
}

// TestTrustTokenExpiry 过期信任令牌不再免码。
func TestTrustTokenExpiry(t *testing.T) {
	tok := "expired-token"
	trustMu.Lock()
	trustTokens[tok] = time.Now().Add(-time.Second)
	trustMu.Unlock()
	req := httptest.NewRequest(http.MethodPost, "/api/login", nil)
	req.AddCookie(&http.Cookie{Name: trustCookieName, Value: tok})
	if trustOK(req) {
		t.Fatal("过期令牌应无效")
	}
}

// Test2FADisabledInTestMode 免登录测试模式: /code 回 enabled=false(不阻断登录页),
// 启用/停用拒绝(规则 6)。
func Test2FADisabledInTestMode(t *testing.T) {
	inject2FADB(t)
	resetAuth(t)
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })

	var on struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.Unmarshal(get2FA(t, handle2FACode).Body.Bytes(), &on)
	if on.Enabled {
		t.Fatal("测试模式 /code 应回 enabled=false")
	}
	if rec := postJSON(t, handle2FAEnable, ""); rec.Code != 401 {
		t.Fatalf("测试模式启用 2FA 应 401, got %d", rec.Code)
	}
	if rec := postJSON(t, handle2FADisable, ""); rec.Code != 401 {
		t.Fatalf("测试模式停用 2FA 应 401, got %d", rec.Code)
	}
}

// Test2FACodePreAuth 登录页(登录前)码值契约: 登录页无开关、动态码常驻, 未配置时
// /code 免鉴权自动启用并返回当前 6 位码, 且该码能完成登录。
//
// 守住"登录页未登录即可看到码值、且看到的码值登录时确实可用"—— 若被误改成
// requireAuth(登录页拿不到码)、或 /code 算码口径与登录校验漂移, 用户会卡在
// 登录页"看到的码登录不上", 且前端无从排查。
func Test2FACodePreAuth(t *testing.T) {
	inject2FADB(t)
	resetAuth(t)
	resetTrustTokens()
	t.Cleanup(resetTrustTokens)
	postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)

	// 登录页无开关, 动态码常驻: 未配置时拉码值应自动启用并返回 6 位码
	var on struct {
		Enabled bool   `json:"enabled"`
		Code    string `json:"code"`
		Remain  int    `json:"remain"`
	}
	_ = json.Unmarshal(get2FA(t, handle2FACode).Body.Bytes(), &on)
	if !on.Enabled || len(on.Code) != 6 {
		t.Fatalf("未配置时应自动启用并返回 6 位码: %+v", on)
	}
	if on.Remain < 1 || on.Remain > 90 {
		t.Fatalf("remain 应在 1..90, got %d", on.Remain)
	}

	// 关键契约: 登录页展示的码值必须能完成登录(口径与登录校验一致)
	r := doLoginReq(t, `{"user":"alice","pass":"secret123","code":"`+on.Code+`"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("登录页展示的码值应能登录, got %d", r.StatusCode)
	}
}

// Test2FACodeNoGhostUsers 幽灵用户回归(2026-09-23): 登录页"输入用户名即拉码"
// 的交互, 叠加旧版"任意 2-20 位合法字符都懒创建 2FA 行"的行为, 用户逐字敲
// "admin" 时会在用户表留下 ad/adm/admi 三个幽灵账号(用户管理里可见但永远
// 登录不了, 用户以为是账号被人动过)。
//
// 守住: 未知用户(不在账号库)拉码值只回 enabled=false、不落任何行; 已知用户
// 保持"自动启用 + 返回 6 位码"的原契约。
func Test2FACodeNoGhostUsers(t *testing.T) {
	d := inject2FADB(t)
	resetAuth(t)
	resetTrustTokens()
	t.Cleanup(resetTrustTokens)
	postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)

	// 1) 未知用户(逐字输入的中间态): 无码值, 且不落行
	rec := httptest.NewRecorder()
	handle2FACode(rec, httptest.NewRequest(http.MethodGet, "/api/auth/2fa/code?user=admi", nil))
	var out struct {
		Enabled bool `json:"enabled"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Enabled {
		t.Fatalf("未知用户应回 enabled=false: %s", rec.Body.String())
	}
	if u, _ := d.Users().Get("admi"); u != nil {
		t.Fatalf("未知用户不应在用户表落行, 实际存在: %+v", u)
	}

	// 2) 已知用户: 自动启用 + 6 位码值(原契约不变)
	rec2 := httptest.NewRecorder()
	handle2FACode(rec2, httptest.NewRequest(http.MethodGet, "/api/auth/2fa/code?user=alice", nil))
	var out2 struct {
		Enabled bool   `json:"enabled"`
		Code    string `json:"code"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &out2)
	if !out2.Enabled || len(out2.Code) != 6 {
		t.Fatalf("已知用户应自动启用并返回 6 位码值: %s", rec2.Body.String())
	}
}

// TestPassHashBackfillOnLogin v2 用户表 passHash 空值口径: 2FA 链路懒创建的空哈希
// 行, 首次登录成功即回填 bcrypt 哈希, 回填后可被 account.Verify 口径校验。
//
// 守住: 回填被误删/条件漂移时"空 passHash"变永久状态 —— 同一空值在 account
// 包 Verify 口径里是"必然失败", 在登录链路(authStore)里是"照常登录", 口径
// 分裂且用户管理侧无从得知该账号其实有密码。
func TestPassHashBackfillOnLogin(t *testing.T) {
	d := inject2FADB(t)
	resetAccountMgr(t, d)
	resetAuth(t)
	const salt = "bfill0"
	authMu.Lock()
	authStore = &userStore{Salt: salt, Users: map[string]userRec{
		"bob": {PassHash: hashPass(salt, "bobpass123")},
	}}
	authMu.Unlock()
	// 模拟 2FA 链路懒创建的空哈希行(未启用 2FA, 不挡登录)
	if _, err := d.Users().Upsert(db.NewUser("bob", "")); err != nil {
		t.Fatalf("建空哈希行失败: %v", err)
	}

	r := doLoginReq(t, `{"user":"bob","pass":"bobpass123"}`, nil)
	_ = r.Body.Close()
	if r.StatusCode != 200 {
		t.Fatalf("登录应成功, got %d", r.StatusCode)
	}
	u, err := d.Users().Get("bob")
	if err != nil || u == nil || u.PassHash == "" {
		t.Fatalf("登录成功后 passHash 应已回填: %+v %v", u, err)
	}
	if err := account.CompareHashAndPassword(u.PassHash, "bobpass123"); err != nil {
		t.Fatalf("回填哈希应可通过原密码校验: %v", err)
	}
}
