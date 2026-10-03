package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestLoginSingleSession 单会话限制: 同一账号第二次登录成功即挤掉第一次的会话 ——
// 旧 token 调 whoami 立即 401(前端据此回登录页), 新 token 正常 200。
// 守契约: "一个账号只允许一个在线会话", 多设备同时在线是明确不允许的。
func TestLoginSingleSession(t *testing.T) {
	resetAuth(t)
	postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)

	login := func() string {
		rec := postJSON(t, handleLogin, `{"user":"alice","pass":"secret123"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("login = %d, body=%s", rec.Code, rec.Body.String())
		}
		c := rec.Result().Cookies()[0]
		if c == nil || c.Name != "yugsight_session" {
			t.Fatal("登录响应缺少 yugsight_session Cookie")
		}
		return c.Value
	}
	whoami := func(tok string) int {
		req := httptest.NewRequest("GET", "/api/whoami", nil)
		req.AddCookie(&http.Cookie{Name: "yugsight_session", Value: tok})
		rec := httptest.NewRecorder()
		handleWhoami(rec, req)
		return rec.Code
	}

	tok1 := login()
	if code := whoami(tok1); code != http.StatusOK {
		t.Fatalf("首次登录 whoami = %d, want 200", code)
	}

	tok2 := login()
	if tok2 == tok1 {
		t.Fatal("每次登录应签发新 token")
	}
	if code := whoami(tok1); code != http.StatusUnauthorized {
		t.Errorf("旧会话应被挤下线, whoami = %d, want 401", code)
	}
	if code := whoami(tok2); code != http.StatusOK {
		t.Errorf("新会话应有效, whoami = %d, want 200", code)
	}
}

// TestLoginSingleSessionDifferentUser 单会话限制按用户隔离: 两个不同账号各自
// 保持会话互不影响(不能"任意新登录清空全部会话")。
func TestLoginSingleSessionDifferentUser(t *testing.T) {
	resetAuth(t)
	postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)
	// 注册接口限"账号库为空"且只允许一个注册者, 第二个账号走 v2 用户表不可行 ——
	// 直接注入一个合法用户行使双账号场景(与 authStore 同口径的哈希)。
	authMu.Lock()
	authStore.Users["bob"] = userRec{PassHash: hashPass(authStore.Salt, "secret456")}
	authMu.Unlock()

	login := func(u, p string) string {
		rec := postJSON(t, handleLogin, `{"user":"`+u+`","pass":"`+p+`"}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("login(%s) = %d, body=%s", u, rec.Code, rec.Body.String())
		}
		return rec.Result().Cookies()[0].Value
	}
	whoami := func(tok string) int {
		req := httptest.NewRequest("GET", "/api/whoami", nil)
		req.AddCookie(&http.Cookie{Name: "yugsight_session", Value: tok})
		rec := httptest.NewRecorder()
		handleWhoami(rec, req)
		return rec.Code
	}

	tokA := login("alice", "secret123")
	tokB := login("bob", "secret456")
	if code := whoami(tokA); code != http.StatusOK {
		t.Errorf("bob 登录后 alice 的会话仍应有效, whoami = %d, want 200", code)
	}
	if code := whoami(tokB); code != http.StatusOK {
		t.Errorf("bob 自己的会话应有效, whoami = %d, want 200", code)
	}
}
