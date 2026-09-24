package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// resetAuth 重置为全新注册模式(测试进程在临时目录, users.json 隔离; 注册表键显式清空)
func resetAuth(t *testing.T) {
	t.Helper()
	loadAuth()
	authMu.Lock()
	authStore = &userStore{Salt: randHex(16), Users: map[string]userRec{}}
	for k := range sessions {
		delete(sessions, k)
	}
	authMu.Unlock()
}

func postJSON(t *testing.T, h http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest("POST", "/", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h(rec, req)
	return rec
}

// TestRegisterAndLogin 注册 -> 登录 -> whoami 全流程
func TestRegisterAndLogin(t *testing.T) {
	resetAuth(t)

	rec := postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("register = %d, body=%s", rec.Code, rec.Body.String())
	}
	var regOut struct{ User string }
	_ = json.Unmarshal(rec.Body.Bytes(), &regOut)
	if regOut.User == "" {
		t.Fatal("注册响应缺少用户名")
	}

	// 重复注册应被拒
	rec2 := postJSON(t, handleRegister, `{"user":"bob","pass":"secret123","pass2":"secret123"}`)
	if rec2.Code != http.StatusUnauthorized {
		t.Fatalf("重复注册 = %d, want 401", rec2.Code)
	}

	// 错误密码
	rec3 := postJSON(t, handleLogin, `{"user":"alice","pass":"wrong"}`)
	if rec3.Code != http.StatusUnauthorized {
		t.Fatalf("错误密码登录 = %d, want 401", rec3.Code)
	}

	// 正确登录
	rec4 := postJSON(t, handleLogin, `{"user":"alice","pass":"secret123"}`)
	if rec4.Code != http.StatusOK {
		t.Fatalf("login = %d, body=%s", rec4.Code, rec4.Body.String())
	}
	cookie := rec4.Result().Cookies()[0]
	if cookie == nil || cookie.Name != "yugsight_session" {
		t.Fatal("登录响应缺少 yugsight_session Cookie")
	}

	// whoami: 必须回显真实用户名(前端顶栏"用户: xxx"依赖它)。
	// 曾误写死 "ok", 刷新页面后顶栏永远显示不了登录账号。
	reqWho := httptest.NewRequest("GET", "/api/whoami", nil)
	reqWho.AddCookie(cookie)
	rec5 := httptest.NewRecorder()
	handleWhoami(rec5, reqWho)
	if rec5.Code != http.StatusOK {
		t.Fatalf("whoami = %d, want 200", rec5.Code)
	}
	var who struct{ User, Role string }
	if err := json.Unmarshal(rec5.Body.Bytes(), &who); err != nil {
		t.Fatalf("whoami 响应非 JSON: %v (body=%s)", err, rec5.Body.String())
	}
	if who.User != "alice" {
		t.Errorf("whoami user = %q, want alice(真实登录名)", who.User)
	}
	if who.Role != "admin" {
		t.Errorf("whoami role = %q, want admin", who.Role)
	}
}



// TestAuthStatus 状态接口返回注册/绑定状态
func TestAuthStatus(t *testing.T) {
	resetAuth(t)
	rec := httptest.NewRecorder()
	handleAuthStatus(rec, httptest.NewRequest("GET", "/api/auth/status", nil))
	var st struct{ Registered bool }
	_ = json.Unmarshal(rec.Body.Bytes(), &st)
	if st.Registered {
		t.Fatalf("全新状态应为未注册: %+v", st)
	}
	postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`)
	rec2 := httptest.NewRecorder()
	handleAuthStatus(rec2, httptest.NewRequest("GET", "/api/auth/status", nil))
	_ = json.Unmarshal(rec2.Body.Bytes(), &st)
	if !st.Registered {
		t.Fatalf("注册后状态错误: %+v", st)
	}
}
