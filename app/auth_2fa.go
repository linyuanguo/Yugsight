// auth_2fa.go 两步验证(2FA/HOTP)装配层: 种子存取(db 用户表) + 设置页接口 +
// 登录"记住设备"信任令牌。
//
// ===== 存储位置 =====
//
// 种子与启用标记存 db 用户表(db.User 新增字段, 见 db/user.go), 不进
// settings.json —— 账号口令在配置文件的 auth 节是既有约定(合并写保注释),
// 而种子属高敏数据, 与口令分库存放也便于"数据库损坏后凭明文备份恢复"。
// 经典账号体系是单管理员模型(注册后不可再注册), 因此 2FA 状态按唯一
// 账号用户名对齐 db.User 行(行不存在时懒创建, PassHash 留空 —— 空值口径见
// auth.go backfillPassHash: 首次成功登录/注册即回填 bcrypt 哈希, 空态仅存在于
// 用户首次成功登录之前)。
//
// ===== 信任令牌("记住登录 1 天") =====
//
// 完整登录(口令+动态码)通过后, 若勾选"记住登录", 下发 yugsight_trust
// cookie(24h); 之后登录仍必须校验口令, 但可跳过动态码 —— 等价于业界
// "记住此浏览器"的 2FA 降频策略。令牌只存内存: 重启后失效属预期(fail-
// closed), 用户重新输一次口令+动态码即可, 不为此新建持久化表。
package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"time"

	"yugsight/internal/db"
)

const (
	trustCookieName = "yugsight_trust"
	trustTTL        = 24 * time.Hour // "记住登录"有效期: 1 天
)

// 信任令牌: token -> 过期时间(内存态, 重启即失效, 刻意不持久化)。
var (
	trustMu     sync.Mutex
	trustTokens = map[string]time.Time{}
)

// currentAdminName 当前唯一管理员用户名(经典账号体系最多一个账户)。
func currentAdminName() string {
	authMu.Lock()
	defer authMu.Unlock()
	for name := range authStore.Users {
		return name
	}
	return ""
}

// authStoreUsers 判断用户是否存在于账号库(即"能登录"的唯一事实来源,
// handleLogin 只认账号库里的用户)。
func authStoreUsers(name string) (userRec, bool) {
	authMu.Lock()
	defer authMu.Unlock()
	if authStore == nil || authStore.Users == nil {
		return userRec{}, false
	}
	u, ok := authStore.Users[name]
	return u, ok
}

// twoFAInfo 读指定用户的 2FA 状态(启用标记 + 种子)。
// 库不可用/行不存在一律按"未启用"降级: 登录链路只认"有种子且启用"才要码,
// 绝不因读库失败阻断登录(降级不崩溃; 行不存在本就等价未配置)。
func twoFAInfo(user string) (enabled bool, seed string) {
	d := v2DB()
	if d == nil || d.Users() == nil {
		return false, ""
	}
	u, err := d.Users().Get(user)
	if err != nil {
		return false, ""
	}
	return u.TwoFAEnabled && u.TwoFASeed != "", u.TwoFASeed
}

// twoFAUpsertSeed 生成/重置种子并落库(懒创建用户行, 保留既有字段)。
// 重置不清除启用标记: 旧种子立即作废, 新种子即时生效, 与"重置密钥"语义一致。
func twoFAUpsertSeed(user string) (seed string, err error) {
	seed = hotpSeedGenerate()
	if seed == "" {
		return "", errSeedRandom
	}
	d := v2DB()
	if d == nil || d.Users() == nil {
		return "", errSeedDBUnavailable
	}
	dao := d.Users()
	u, gerr := dao.Get(user)
	if gerr != nil {
		// 懒创建对齐行: 经典账号在 settings.json, db 用户表只承载 2FA 状态,
		// PassHash 留空(空态是暂时的: 该用户首次成功登录/注册时回填, 见
		// auth.go backfillPassHash)。
		// 角色显式给 admin: 能走到这里的用户必在 authStore(旧账号库)里 —— 旧
		// 单用户体系下就是全权限, 注册路径(handleRegister)同口径对齐 admin
		// ("原来什么权限, 升级后什么权限")。db.NewUser 默认 auditor, 不显式
		// 覆盖会把旧管理员锁进只读角色(写接口 403 + 授权管理菜单消失,
		// 2026-09-24 真机踩坑)。
		u = db.NewUser(user, "")
		u.Role = db.RoleAdmin
	}
	u.TwoFASeed = seed
	if _, uerr := dao.Upsert(u); uerr != nil {
		return "", uerr
	}
	return seed, nil
}

// twoFASetEnabled 仅切换启用标记(开启前提: 已有种子)。
func twoFASetEnabled(user string, on bool) error {
	d := v2DB()
	if d == nil || d.Users() == nil {
		return errSeedDBUnavailable
	}
	dao := d.Users()
	u, gerr := dao.Get(user)
	if gerr != nil {
		if on {
			return errNoSeed
		}
		// 关闭一个不存在的行 = 幂等成功
		return nil
	}
	if on && u.TwoFASeed == "" {
		return errNoSeed
	}
	u.TwoFAEnabled = on
	_, err := dao.Upsert(u)
	return err
}

// ===== 信任令牌 =====

// issueTrustToken 签发信任令牌并写 cookie(24h)。
func issueTrustToken(w http.ResponseWriter) {
	tok := randHex(24)
	trustMu.Lock()
	// 顺手清理过期项, 防长期运行内存缓涨(频率极低, 无需专门协程)
	now := time.Now()
	for k, exp := range trustTokens {
		if now.After(exp) {
			delete(trustTokens, k)
		}
	}
	trustTokens[tok] = now.Add(trustTTL)
	trustMu.Unlock()
	http.SetCookie(w, &http.Cookie{
		Name: trustCookieName, Value: tok, Path: "/",
		HttpOnly: true, MaxAge: int(trustTTL.Seconds()),
	})
}

// trustOK 校验请求是否携带有效信任令牌(未启用 2FA 时不需调用本函数)。
func trustOK(r *http.Request) bool {
	c, err := r.Cookie(trustCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	trustMu.Lock()
	defer trustMu.Unlock()
	exp, ok := trustTokens[c.Value]
	if !ok || !time.Now().Before(exp) {
		delete(trustTokens, c.Value)
		return false
	}
	return true
}

// resetTrustTokens 清空信任令牌(测试用)。
func resetTrustTokens() {
	trustMu.Lock()
	trustTokens = map[string]time.Time{}
	trustMu.Unlock()
}

// ===== 错误与响应 =====

var (
	errSeedRandom        = errString("随机数生成失败, 请重试")
	errSeedDBUnavailable = errString("数据库不可用, 无法保存种子")
	errNoSeed            = errString("尚未生成种子密钥, 请先生成")
)

type errString string

func (e errString) Error() string { return string(e) }

// http401Need2FA 登录第一步通过但需要动态码: 401 + need2fa 标记,
// 前端据此切换到验证码输入步骤(而非当作口令错误提示)。
func http401Need2FA(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{"error": "请输入动态验证码", "need2fa": true})
}

// 【已删除的死接口】旧设置页(授权管理 2FA 卡片)的 3 条 requireAuth 路由
// /api/auth/2fa/status|seed|toggle 在"码值内联登录页"重做后前端零调用,
// 2026-09-21 收尾清理时整体移除(验收口径: 不留死接口)。启用/停用统一走
// 登录前接口 /api/auth/2fa/enable|disable, 码值走 /api/auth/2fa/code。

// trimCode 规整输入码(去空白; 前端已限 6 位数字, 这里兜底)。
func trimCode(s string) string { return strings.TrimSpace(s) }

// ===== 登录页动态码(登录前, 无会话) =====
//
// 单管理员离线内网工具, 动态码本就展示在登录页(用户"看得到才输得进"), 因此
// 码值读取与启用/停用不走 requireAuth —— 与 /api/login、/api/auth/status 同口径。
// 旧版两步登录把码值放在"授权管理"页(需登录后才能进), 登录页提示"码值见授权
// 管理页"实为死循环; 本次改为码值内联登录页, 启用/停用也随之落到登录页。

// handle2FACode GET /api/auth/2fa/code?user=<name> → {enabled, code, remain}
// 登录页拉取当前时间片码值展示。user 可选(留空取唯一管理员)。登录页无开关、
// 动态码常驻: 未配置(无种子/未启用)时自动生成种子并启用; 仅读库失败时回
// enabled=false(不阻断登录页)。
func handle2FACode(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if authDisabled {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
		return
	}
	user := r.URL.Query().Get("user")
	if user == "" || !validUser(user) {
		user = currentAdminName()
	}
	// 限流(与 /api/login 同口径, 键为 user+IP): 计数只由"登录时动态码校验失败"
	// 喂入(见 auth.go handleLogin) —— 本接口是登录页每 90 秒一次的只读轮询,
	// 把正常拉取也算失败会在 8 分钟内把正常用户锁死。
	if loginLimitOn() {
		if locked, remain := codeLimit.Locked(codeLimitKey(r, user)); locked {
			http429Locked(w, remain)
			return
		}
	}
	// 只为"能登录的用户"(在账号库里)自动建 2FA 种子行。
	// 【为什么必须有这道守卫】登录页是"输入用户名即拉码"的交互, 旧实现下任何
	// 2-20 位合法字符都会调 twoFAUpsertSeed 在 db 用户表落一行 —— 用户逐字敲
	// "admin" 时会在用户管理里留下 ad/adm/admi 三个幽灵账号(永远登录不了,
	// 却让用户以为账号被人动过)。未知用户直接按未启用返回: 反正登录不了,
	// 给他码没有意义。
	if _, ok := authStoreUsers(user); !ok {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
		return
	}
	// 登录页无开关, 动态码常驻: 未配置(无种子/未启用)时自动生成种子并启用,
	// 保证"看得到才输得进"始终成立(旧版靠登录页"开启/关闭"开关, 现已移除)。
	if user != "" {
		if enabled, seed := twoFAInfo(user); !enabled || seed == "" {
			if s, err := twoFAUpsertSeed(user); err == nil && s != "" {
				_ = twoFASetEnabled(user, true)
			}
		}
	}
	out := map[string]any{"enabled": false}
	if user != "" {
		if enabled, seed := twoFAInfo(user); enabled && seed != "" {
			now := time.Now()
			out = map[string]any{"enabled": true, "code": hotpCode(seed, hotpCounterAt(now)), "remain": hotpRemainSecAt(now)}
		}
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(out)
}

// handle2FAEnable POST /api/auth/2fa/enable → {enabled:true}: 生成种子并启用(重置信任令牌)。
func handle2FAEnable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if authDisabled {
		http401(w, "免登录测试模式下不提供 2FA 配置")
		return
	}
	user := currentAdminName()
	if user == "" {
		http401(w, "尚无账户, 请先注册")
		return
	}
	if _, err := twoFAUpsertSeed(user); err != nil {
		http401(w, err.Error())
		return
	}
	if err := twoFASetEnabled(user, true); err != nil {
		http401(w, err.Error())
		return
	}
	resetTrustTokens()
	logLine("2FA(动态验证码)已启用, 登录需输入 6 位动态码")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"enabled": true})
}

// handle2FADisable POST /api/auth/2fa/disable → {enabled:false}: 停用(保留种子, 重新启用即恢复)。
func handle2FADisable(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if authDisabled {
		http401(w, "免登录测试模式下不提供 2FA 配置")
		return
	}
	user := currentAdminName()
	if user == "" {
		http401(w, "尚无账户, 请先注册")
		return
	}
	if err := twoFASetEnabled(user, false); err != nil {
		http401(w, err.Error())
		return
	}
	logLine("2FA(动态验证码)已关闭")
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{"enabled": false})
}
