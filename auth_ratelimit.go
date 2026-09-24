// auth_ratelimit.go 登录失败限流与临时锁定。
//
// ===== 为什么要有 =====
//
// 登录接口此前对"同一来源反复试口令/试动态码"毫无约束, 单管理员内网工具一旦
// 暴露到局域网(程序默认就绑局域网 IP), 在线爆破完全可行: 6 位动态码只有 10^6
// 空间, 不设上限等于把 2FA 降成装饰。
//
// ===== 口径 =====
//
//   - /api/login        按客户端 IP 计数(登录前无从得知用户名是否真实, IP 是唯一可靠维度)
//   - /api/auth/2fa/code 按 user + IP 组合计数(动态码按用户签发, 只按 IP 会误伤同一出口 IP)
//
// 两者共用同一套参数(5 分钟窗口内失败 5 次 → 锁定 15 分钟)。code 接口的计数
// **只由"登录时动态码校验失败"喂入**, 不把"拉取码值"本身算失败 —— 登录页每 90
// 秒轮询一次该接口, 把正常拉取计作失败会在 8 分钟内把正常用户锁死。
//
// ===== 判定为什么抽成纯函数 =====
//
// 时间窗口/过期这类逻辑一旦直接读写 time.Now() 就只能靠 sleep 测, 用例既慢又不稳。
// 这里把"状态 + 注入的时间 → 新状态"做成纯函数(limitRecord/limitCheck), 管壁
// 与调度(loginLimiter)只负责加锁与存取。
package main

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// 限流参数(需求口径: 5 分钟窗口内失败 5 次锁定 15 分钟)
const (
	loginFailWindow = 5 * time.Minute
	loginFailMax    = 5
	loginLockDur    = 15 * time.Minute
)

// limitConfig 限流参数(结构体而非散常量, 便于单测注入不同口径)
type limitConfig struct {
	Window   time.Duration // 失败计数窗口
	MaxFails int           // 窗口内允许的失败次数(达到即锁定)
	Lock     time.Duration // 锁定时长
}

// defaultLimitConfig 生产口径
func defaultLimitConfig() limitConfig {
	return limitConfig{Window: loginFailWindow, MaxFails: loginFailMax, Lock: loginLockDur}
}

// attemptState 单个限流键的状态(纯数据, 无锁, 便于单测与断言)
type attemptState struct {
	Fails       int       // 当前窗口内已失败次数(锁定后清零)
	WindowUntil time.Time // 当前计数窗口的到期时刻(零值 = 尚未开窗)
	LockedUntil time.Time // 锁定到期时刻(零值 = 未锁定)
}

// limitCheck 纯判定: 给定时刻该键是否处于锁定中, 并返回剩余锁定时长。
func limitCheck(st attemptState, now time.Time) (locked bool, remain time.Duration) {
	if st.LockedUntil.IsZero() || !now.Before(st.LockedUntil) {
		return false, 0
	}
	return true, st.LockedUntil.Sub(now)
}

// limitExpired 该状态是否已完全过期(既没在锁定中, 计数窗口也已关掉)。
// 用于内存清理: 过期条目留着只是占内存, 没有任何判定价值。
func limitExpired(st attemptState, now time.Time) bool {
	if locked, _ := limitCheck(st, now); locked {
		return false
	}
	// 窗口未开(零值)也判过期: 触发锁定那一刻会清空窗口只留锁定时刻, 若要求
	// "窗口必须存在过", 这类条目将在解锁后永远滞留在 map 里(键含 IP, 会涨)。
	return st.WindowUntil.IsZero() || !now.Before(st.WindowUntil)
}

// limitRecord 纯判定: 记录一次失败, 返回更新后的状态与本次是否被锁定。
//
// 口径要点:
//   - 锁定期间不再累计(调用方本就应先查锁定, 这里兜底保证函数是全函数);
//   - 计数窗口过期即重新开窗(连上次未触发锁定的失败一并作废);
//   - 触发锁定后清空窗口与计数: 解锁后从 0 重新开始, 不会因历史失败立刻二次锁定。
func limitRecord(st attemptState, now time.Time, cfg limitConfig) (attemptState, bool) {
	if locked, _ := limitCheck(st, now); locked {
		return st, true
	}
	if st.WindowUntil.IsZero() || !now.Before(st.WindowUntil) {
		st = attemptState{WindowUntil: now.Add(cfg.Window)}
	}
	st.Fails++
	if cfg.MaxFails > 0 && st.Fails >= cfg.MaxFails {
		st.LockedUntil = now.Add(cfg.Lock)
		st.Fails, st.WindowUntil = 0, time.Time{}
		return st, true
	}
	return st, false
}

// ===== 调度层 =====

// loginLimiter 内存态限流器(进程重启即清零)。
//
// 【为什么不落库】限流是"瞬时抗压"机制, 写入 JSONL 文件库既慢又会在高频失败时
// 放大磁盘写入; 而重启清零的代价只是"攻击者换到新的一轮机会", 口令本身仍是
// salt+sha256, 5 次/5 分钟的窗口已足以挡住在线爆破。
type loginLimiter struct {
	mu      sync.Mutex
	cfg     limitConfig
	now     func() time.Time // 时间注入点(生产为 time.Now, 单测为可控时钟)
	entries map[string]attemptState
}

func newLoginLimiter(cfg limitConfig, now func() time.Time) *loginLimiter {
	return &loginLimiter{cfg: cfg, now: now, entries: map[string]attemptState{}}
}

// Locked 该键当前是否被锁定(不计数, 纯查询)。
func (l *loginLimiter) Locked(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	return limitCheck(l.entries[key], now)
}

// Failure 记录一次失败: 返回更新后是否锁定 + 剩余锁定时长。
func (l *loginLimiter) Failure(key string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.sweep(now)
	st, locked := limitRecord(l.entries[key], now, l.cfg)
	l.entries[key] = st
	if locked {
		return true, st.LockedUntil.Sub(now)
	}
	return false, 0
}

// Success 该键成功一次(登录通过) → 清除其失败记录。
func (l *loginLimiter) Success(key string) {
	l.mu.Lock()
	delete(l.entries, key)
	l.mu.Unlock()
}

// sweep 清理已过期条目(调用方必须已持锁)。
//
// 必须在每次访问时做: 键里含 IP, 攻击者换源地址能让 map 无上界增长, 而过期条目
// 已不影响任何判定 —— 留着只会让内存随时间单调上涨。
func (l *loginLimiter) sweep(now time.Time) {
	for k, st := range l.entries {
		if limitExpired(st, now) {
			delete(l.entries, k)
		}
	}
}

// reset 清空全部状态(测试用)。
func (l *loginLimiter) reset() {
	l.mu.Lock()
	l.entries = map[string]attemptState{}
	l.mu.Unlock()
}

// 两个限流器: 登录按 IP, 动态码按 user+IP(同参数, 见文件头说明)。
var (
	loginLimit = newLoginLimiter(defaultLimitConfig(), time.Now)
	codeLimit  = newLoginLimiter(defaultLimitConfig(), time.Now)
)

// loginLimitOn 限流是否生效。免登录模式(-no-auth / settings 的 auth.enabled=false)
// 与测试模式(test_mode.txt)一律跳过(项目规则 6)。
func loginLimitOn() bool {
	return !authDisabled && !testModeEnabled()
}

// limitIP 取限流用的客户端 IP。
//
// 【刻意不用 clientIP】clientIP 优先读 X-Forwarded-For, 而该头由客户端可控 ——
// 用它做限流等于给攻击者一个"每次换头就换一轮额度"的旁路。限流必须按真实连接地址。
func limitIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}

// loginLimitKey /api/login 的限流键: 客户端 IP
func loginLimitKey(r *http.Request) string { return limitIP(r) }

// codeLimitKey /api/auth/2fa/code 的限流键: user + IP 组合
func codeLimitKey(r *http.Request, user string) string { return user + "|" + limitIP(r) }

// http429Locked 锁定期间的统一响应: 429 + 剩余秒数。
// 用 429 而非 401 —— 401 会被前端当作"口令错"提示用户重试, 恰好与限流意图相反。
func http429Locked(w http.ResponseWriter, remain time.Duration) {
	sec := int((remain + time.Second - 1) / time.Second)
	if sec < 1 {
		sec = 1
	}
	wait := strconv.Itoa(sec) + " 秒"
	if sec >= 60 {
		wait = strconv.Itoa((sec+59)/60) + " 分钟"
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusTooManyRequests)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":    "登录失败次数过多, 请在 " + wait + "后重试",
		"locked":   true,
		"retrySec": sec,
	})
}

// loginFail 统一处理一次登录失败: 限流计数 + 审计日志 + 401。
// 审计失败绝不影响登录响应(logAudit 内部降级记日志)。
func loginFail(w http.ResponseWriter, r *http.Request, ip, user, msg string) {
	if loginLimitOn() {
		loginLimit.Failure(ip)
	}
	logAudit(v2DB(), r, "login_failed", user, msg+" (IP "+ip+")")
	http401(w, msg)
}

// loginOK 登录成功: 清除该来源的失败计数(否则一次手误 + 5 次正确登录也会被锁)。
func loginOK(r *http.Request, ip, user string) {
	if !loginLimitOn() {
		return
	}
	loginLimit.Success(ip)
	codeLimit.Success(codeLimitKey(r, user))
}
