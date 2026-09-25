// auth_ratelimit_test.go 登录限流与锁定。
//
// 判定逻辑(limitRecord/limitCheck)是纯函数、时间可注入, 故窗口计数/锁定/过期
// 全部用可控时钟直接断言, 不 sleep。集成用例只补"两个接口确实挂上了限流"这一层。
//
// 【IP 约定】限流键含 IP, 而 httptest 默认 RemoteAddr 是 192.0.2.1(所有用例共用)。
// 本文件一律用 TEST-NET-2 的 198.51.100.x 并显式改写 RemoteAddr, 避免把锁定状态
// 留到后续用例(曾几何时一个用例锁住共享 IP 会让毫不相关的登录用例变 429)。
package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// clock 可控时钟(单测注入用)
type clock struct{ t time.Time }

func (c *clock) now() time.Time      { return c.t }
func (c *clock) add(d time.Duration) { c.t = c.t.Add(d) }

// loginReqFrom 构造指定来源 IP 的登录请求
func loginReqFrom(ip, body string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = ip + ":54321"
	return req
}

// doLogin 直发登录请求并返回响应码(调用方关 Body)
func doLogin(ip, body string) int {
	rec := httptest.NewRecorder()
	handleLogin(rec, loginReqFrom(ip, body))
	res := rec.Result()
	defer res.Body.Close()
	return res.StatusCode
}

// TestLimitRecordWindowCountAndLock 纯函数: 窗口内累计到阈值即锁定, 且锁定后清零计数。
//
// 守住"阈值判定是 >= 而不是 >"与"锁定即清零"两条: 前者错会让实际允许次数变成 6,
// 后者错会让解锁瞬间因残留计数立刻二次锁定(用户观感是"永远登不上")。
func TestLimitRecordWindowCountAndLock(t *testing.T) {
	cfg := defaultLimitConfig()
	now := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	var st attemptState
	for i := 1; i < cfg.MaxFails; i++ {
		var locked bool
		st, locked = limitRecord(st, now, cfg)
		if locked {
			t.Fatalf("第 %d 次失败不应锁定", i)
		}
		if st.Fails != i {
			t.Fatalf("第 %d 次失败后计数 = %d", i, st.Fails)
		}
	}
	st, locked := limitRecord(st, now, cfg)
	if !locked {
		t.Fatal("达到阈值应锁定")
	}
	if st.Fails != 0 {
		t.Fatalf("锁定后计数应清零, got %d", st.Fails)
	}
	if got := st.LockedUntil.Sub(now); got != cfg.Lock {
		t.Fatalf("锁定时长 = %v, want %v", got, cfg.Lock)
	}
	// 锁定期间继续记录不再改变状态(全函数性质)
	same, still := limitRecord(st, now.Add(time.Minute), cfg)
	if !still || same != st {
		t.Fatalf("锁定期间记录应保持状态不变: %+v", same)
	}
}

// TestLimitWindowExpiryResetsCount 窗口过期后重新计数(未达阈值的失败不累积)。
//
// 守住"窗口是滑动重置而非永久累计": 用户一天里手误 5 次却被锁 15 分钟, 是典型的
// 限流误伤, 也是本用例存在的理由。
func TestLimitWindowExpiryResetsCount(t *testing.T) {
	cfg := defaultLimitConfig()
	c := &clock{t: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)}
	var st attemptState
	for i := 0; i < cfg.MaxFails-1; i++ {
		st, _ = limitRecord(st, c.now(), cfg)
	}
	if st.Fails != cfg.MaxFails-1 {
		t.Fatalf("前置失败数 = %d", st.Fails)
	}
	// 跨过窗口后再失败一次: 应重新开窗, 而不是凑满阈值触发锁定
	c.add(cfg.Window + time.Second)
	st, locked := limitRecord(st, c.now(), cfg)
	if locked {
		t.Fatal("窗口过期后不应锁定")
	}
	if st.Fails != 1 {
		t.Fatalf("窗口过期后计数应重置为 1, got %d", st.Fails)
	}
}

// TestLimitLockExpiry 锁定期满后恢复, 且恢复后从 0 重新开始。
func TestLimitLockExpiry(t *testing.T) {
	cfg := defaultLimitConfig()
	c := &clock{t: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)}
	var st attemptState
	for i := 0; i < cfg.MaxFails; i++ {
		st, _ = limitRecord(st, c.now(), cfg)
	}
	if _, remain := limitCheck(st, c.now()); !limitCheckLocked(st, c.now()) || remain != cfg.Lock {
		t.Fatalf("触发锁定后应立即处于锁定中, remain=%v", remain)
	}
	// 差 1 秒到期仍在锁定中
	c.add(cfg.Lock - time.Second)
	if !limitCheckLocked(st, c.now()) {
		t.Fatal("锁定期满前不应解锁")
	}
	// 到期即解锁, 且下一个失败只算第 1 次
	c.add(time.Second)
	if limitCheckLocked(st, c.now()) {
		t.Fatal("锁定期满应解锁")
	}
	st, locked := limitRecord(st, c.now(), cfg)
	if locked || st.Fails != 1 {
		t.Fatalf("解锁后应从 1 重新计数, got locked=%v fails=%d", locked, st.Fails)
	}
}

func limitCheckLocked(st attemptState, now time.Time) bool {
	locked, _ := limitCheck(st, now)
	return locked
}

// TestLoginLimiterSweepExpired 过期条目被清理(否则键里含 IP 的 map 会无上界增长)。
func TestLoginLimiterSweepExpired(t *testing.T) {
	c := &clock{t: time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)}
	l := newLoginLimiter(defaultLimitConfig(), c.now)
	l.Failure("1.1.1.1") // 1 次失败: 窗口到期即过期
	for i := 0; i < loginFailMax; i++ {
		l.Failure("2.2.2.2") // 触发锁定: 15 分钟后才过期
	}
	if len(l.entries) != 2 {
		t.Fatalf("清理前应有 2 条, got %d", len(l.entries))
	}
	c.add(loginFailWindow + time.Second)
	l.Locked("3.3.3.3") // 任意访问触发清理
	if _, ok := l.entries["1.1.1.1"]; ok {
		t.Fatal("已过期的窗口条目应被清理")
	}
	if _, ok := l.entries["2.2.2.2"]; !ok {
		t.Fatal("仍在锁定中的条目不应被清理")
	}
	c.add(loginLockDur)
	l.Locked("3.3.3.3")
	if len(l.entries) != 0 {
		t.Fatalf("全部过期后应清空, got %d", len(l.entries))
	}
}

// TestLoginRateLimitLocksIP /api/login 按 IP 限流: 连续失败到阈值后返回 429(而非 401)。
//
// 守住"接口真的挂上了限流"这一层接线 —— 纯函数再正确, 没人调用就等于没做。
func TestLoginRateLimitLocksIP(t *testing.T) {
	resetAuth(t)
	loginLimit.reset()
	codeLimit.reset()
	t.Cleanup(func() { loginLimit.reset(); codeLimit.reset() })
	if rec := postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`); rec.Code != 200 {
		t.Fatalf("注册失败: %s", rec.Body.String())
	}
	const ip = "198.51.100.7"
	for i := 0; i < loginFailMax; i++ {
		if code := doLogin(ip, `{"user":"alice","pass":"wrong"}`); code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次失败应 401, got %d", i+1, code)
		}
	}
	if code := doLogin(ip, `{"user":"alice","pass":"secret123"}`); code != http.StatusTooManyRequests {
		t.Fatalf("达到阈值后应 429, got %d", code)
	}
	// 换一个来源 IP 不受影响(键是 IP, 不是全局开关)
	if code := doLogin("198.51.100.8", `{"user":"alice","pass":"secret123"}`); code != http.StatusOK {
		t.Fatalf("其它来源 IP 应正常登录, got %d", code)
	}
	// 登录成功清除计数: 手误几次不该把正常用户锁在外面
	if code := doLogin(ip, `{"user":"alice","pass":"wrong"}`); code != http.StatusTooManyRequests {
		t.Fatalf("清除前仍应锁定, got %d", code)
	}
	loginLimit.Success(ip)
	if code := doLogin(ip, `{"user":"alice","pass":"secret123"}`); code != http.StatusOK {
		t.Fatalf("清除计数后应能登录, got %d", code)
	}
}

// TestLoginRateLimitSkippedInTestMode 免登录/测试模式(test_mode.txt)跳过限流(规则 6)。
//
// 守住"测试模式不被自己的安全机制挡住": 该模式下所有鉴权都已跳过, 若限流还生效,
// 自动化冒烟会在第 6 次失败请求上莫名 429。
func TestLoginRateLimitSkippedInTestMode(t *testing.T) {
	resetAuth(t)
	loginLimit.reset()
	codeLimit.reset()
	t.Cleanup(func() { loginLimit.reset(); codeLimit.reset() })
	if rec := postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`); rec.Code != 200 {
		t.Fatalf("注册失败: %s", rec.Body.String())
	}
	prev := authDisabled
	authDisabled = true
	t.Cleanup(func() { authDisabled = prev })

	const ip = "198.51.100.9"
	for i := 0; i < loginFailMax*2; i++ {
		if code := doLogin(ip, `{"user":"alice","pass":"wrong"}`); code != http.StatusUnauthorized {
			t.Fatalf("测试模式第 %d 次失败应仍 401(不限流), got %d", i+1, code)
		}
	}
	if len(loginLimit.entries) != 0 {
		t.Fatalf("测试模式不应写入限流状态, got %d 条", len(loginLimit.entries))
	}
}

// Test2FACodeLimitSharesLoginFailures /api/auth/2fa/code 与登录同口径: 动态码连续
// 校验失败后, 按 user+IP 锁定码值接口。
//
// 守住"两个限流器是一条绳上的": 只锁 /api/login 的话, 攻击者仍能从码值接口无限
// 拉取当前时间片码值(离线工具码值登录前可见), 爆破窗口并未真正收窄。
func Test2FACodeLimitSharesLoginFailures(t *testing.T) {
	inject2FADB(t)
	resetAuth(t)
	resetTrustTokens()
	loginLimit.reset()
	codeLimit.reset()
	t.Cleanup(func() {
		resetTrustTokens()
		loginLimit.reset()
		codeLimit.reset()
	})
	if rec := postJSON(t, handleRegister, `{"user":"alice","pass":"secret123","pass2":"secret123"}`); rec.Code != 200 {
		t.Fatalf("注册失败: %s", rec.Body.String())
	}
	postJSON(t, handle2FAEnable, "") // 登录前接口: 生成种子并启用(旧 /seed+/toggle 死接口已删)

	const ip = "198.51.100.11"
	for i := 0; i < loginFailMax; i++ {
		if code := doLogin(ip, `{"user":"alice","pass":"secret123","code":"000000"}`); code != http.StatusUnauthorized {
			t.Fatalf("第 %d 次错误动态码应 401, got %d", i+1, code)
		}
	}
	// 码值接口按 user+IP 同口径锁定
	req := httptest.NewRequest(http.MethodGet, "/api/auth/2fa/code?user=alice", nil)
	req.RemoteAddr = ip + ":54321"
	rec := httptest.NewRecorder()
	handle2FACode(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("码值接口应 429, got %d", rec.Code)
	}
	// 同一 IP 的其它用户不受影响(键是 user+IP, 不是纯 IP)
	req2 := httptest.NewRequest(http.MethodGet, "/api/auth/2fa/code?user=bob", nil)
	req2.RemoteAddr = ip + ":54321"
	rec2 := httptest.NewRecorder()
	handle2FACode(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("其它用户不应被连坐, got %d", rec2.Code)
	}
}

// TestLimitIPIgnoresForwardedFor 限流键刻意忽略 X-Forwarded-For(该头客户端可控)。
//
// 守住"限流按真实连接地址": 若复用 clientIP, 攻击者每次换一个 XFF 就能换一轮额度,
// 限流等于没做 —— 这类旁路不会有任何报错, 只在真实爆破时暴露。
func TestLimitIPIgnoresForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.12:54321"
	req.Header.Set("X-Forwarded-For", "9.9.9.9")
	if got := limitIP(req); got != "198.51.100.12" {
		t.Fatalf("限流键应取真实远端地址, got %q", got)
	}
}
