// auth_init_test.go 初始账号自动创建与 auth.enabled 开关的用例。
//
// 守护的契约(改坏即静默失效型):
//  1. 全新安装必须自动建号并把明文账密回写 settings.json —— 这是"初始账密
//     放在 settings.json"需求的本体, 若 loadAuth 解析丢字段或 saveAuth 落盘
//     丢字段, 用户打开配置文件会看不到账密, 只能靠手工点检发现;
//  2. enabled=false 必须走 authDisabled 通道 —— 这是所有接口免登录的唯一开关,
//     断了就是"写了配置却还要登录"的困惑工单。
package main

import (
	"encoding/json"
	"os"
	"testing"
)

// withAuthGlobals 保存并恢复 auth 全局态(authStore/authDisabled)。
// authStore 是包级单例且 loadAuth/initDefaultAccount 直接改写它, 不还原会污染
// 同包其它用例(如 auth_test.go 的注册/登录用例) —— 表现为"单跑过、全量挂"。
func withAuthGlobals(t *testing.T) {
	t.Helper()
	authMu.Lock()
	oldStore, oldDisabled := authStore, authDisabled
	authMu.Unlock()
	t.Cleanup(func() {
		authMu.Lock()
		authStore, authDisabled = oldStore, oldDisabled
		authMu.Unlock()
	})
}

// TestInitDefaultAccountFresh 全新安装(无任何配置)自动建默认号 admin/admin123,
// 且明文账密必须回写 settings.json 的 auth 节。
func TestInitDefaultAccountFresh(t *testing.T) {
	withTempExeDir(t)
	withAuthGlobals(t)
	writeTestSettings(t, `{}`)
	authDisabled = false
	authStore = &userStore{Salt: "salt0", Users: map[string]userRec{}}

	initDefaultAccount()

	rec, ok := authStore.Users["admin"]
	if !ok {
		t.Fatal("全新安装应自动创建初始账号 admin")
	}
	if rec.PassHash != hashPass("salt0", "admin123") {
		t.Fatalf("初始密码应为默认 admin123, 哈希不匹配: %s", rec.PassHash)
	}

	// 明文账密落盘: 用户打开 settings.json 必须能看到初始账密(需求本体)
	data, err := os.ReadFile(settingsFilePath())
	if err != nil {
		t.Fatalf("读 settings.json: %v", err)
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("settings.json 应为合法 JSON: %v", err)
	}
	var st userStore
	if err := json.Unmarshal(doc["auth"], &st); err != nil {
		t.Fatalf("auth 节应可解析: %v", err)
	}
	if st.User != "admin" || st.Pass != "admin123" {
		t.Fatalf("明文初始账密应回写 auth 节, 实际 user=%q pass=%q", st.User, st.Pass)
	}
	// 账号库本体不能丢(同一次合并写里同时落盘)
	if st.Users == nil || len(st.Users) != 1 {
		t.Fatalf("auth 节应同时包含 users 账号库, 实际: %s", doc["auth"])
	}
}

// TestInitDefaultAccountFromConfig 配置了 user/pass 时按配置建号。
//
// 走真实 loadAuth() 读盘链路而非手工构造 authStore —— 守住"解析 auth 节必须
// 带出 user/pass 字段"这一契约: 若有人改坏字段 tag 或解析路径, 全新安装会
// 静默退回默认 admin 账号, 用户配的初始账密被忽略。
func TestInitDefaultAccountFromConfig(t *testing.T) {
	withTempExeDir(t)
	withAuthGlobals(t)
	writeTestSettings(t, `{"auth":{"user":"ops","pass":"secret1"}}`)
	authDisabled = false

	loadAuth()
	initDefaultAccount()

	rec, ok := authStore.Users["ops"]
	if !ok {
		t.Fatalf("应按 settings.json 的初始账密创建账号 ops, 实际账号: %v", authStore.Users)
	}
	if rec.PassHash != hashPass(authStore.Salt, "secret1") {
		t.Fatal("ops 的密码哈希应来自配置的 secret1")
	}
	if _, exists := authStore.Users["admin"]; exists {
		t.Fatal("配置了初始账号时不应再创建默认 admin")
	}
}

// TestInitDefaultAccountSkipsExisting 已有账号时不动 —— 建号只发生一次,
// 否则每次启动都会把用户的账号库重置回配置文件。
func TestInitDefaultAccountSkipsExisting(t *testing.T) {
	withTempExeDir(t)
	withAuthGlobals(t)
	writeTestSettings(t, `{}`)
	authDisabled = false
	authStore = &userStore{Salt: "salt0", Users: map[string]userRec{
		"real": {PassHash: hashPass("salt0", "realpass")},
	}}

	initDefaultAccount()

	if len(authStore.Users) != 1 {
		t.Fatalf("已有账号时不应新增账号, 实际: %v", authStore.Users)
	}
	if _, ok := authStore.Users["admin"]; ok {
		t.Fatal("不应覆盖既有账号库")
	}
}

// TestAuthSwitchDisabled enabled=false 走 authDisabled 通道且不建号。
func TestAuthSwitchDisabled(t *testing.T) {
	withTempExeDir(t)
	withAuthGlobals(t)
	writeTestSettings(t, `{"auth":{"enabled":false}}`)
	authDisabled = false

	loadAuth()
	applyAuthSwitch()
	initDefaultAccount()

	if !authDisabled {
		t.Fatal("auth.enabled=false 时应置 authDisabled")
	}
	if len(authStore.Users) != 0 {
		t.Fatalf("免登录模式下不应创建账号, 实际: %v", authStore.Users)
	}
}

// TestAuthSwitchDefaultOn 未配置 enabled(或显式 true)时保持默认鉴权开启。
func TestAuthSwitchDefaultOn(t *testing.T) {
	withTempExeDir(t)
	withAuthGlobals(t)
	writeTestSettings(t, `{"auth":{"user":"u1","pass":"passwd1"}}`)
	authDisabled = false

	loadAuth()
	applyAuthSwitch()

	if authDisabled {
		t.Fatal("未配置 enabled 时鉴权应默认开启")
	}

	// 显式 true 同样保持开启
	writeTestSettings(t, `{"auth":{"enabled":true}}`)
	loadAuth()
	applyAuthSwitch()
	if authDisabled {
		t.Fatal("auth.enabled=true 时鉴权应开启")
	}
}
