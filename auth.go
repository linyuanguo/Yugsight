package main

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"yugsight/account"
	"yugsight/db"
)

const minPassLen = 6

type userRec struct {
	PassHash string `json:"passHash"`
}

type userStore struct {
	Salt  string             `json:"salt"`
	Users map[string]userRec `json:"users"`
	// Enabled: 登录鉴权总开关(缺省/nil=开启)。显式 false 时所有接口免登录,
	// 与 -no-auth / test_mode.txt 同走 authDisabled 通道, 前端零改动直进主界面。
	Enabled *bool `json:"enabled,omitempty"`
	// User/Pass: 初始账号明文。仅当账号库为空(全新安装)时用于自动建号, 之后
	// 修改不影响已建账号(校验始终走 salt+sha256 哈希, 不存在改明文绕哈希的旁门)。
	// 明文留存于此供用户直接查看/修改 —— 这正是"初始账密放在 settings.json"的需求。
	User string `json:"user,omitempty"`
	Pass string `json:"pass,omitempty"`
}

// sessionRec 会话记录: 过期时间 + 登录用户名 + 角色(RBAC)。
// 角色在登录时从 db 用户表解析后固化进会话 —— 中途改角色不会让已登录会话
// 越权/降权到不一致状态(旧会话保留登录时权限, 重新登录生效), 语义明确。
type sessionRec struct {
	exp  time.Time
	user string
	role string // db.RoleAdmin / db.RoleAuditor
}

var (
	authMu       sync.Mutex
	authStore    *userStore
	sessions     = map[string]sessionRec{} // token -> 会话记录
	authDisabled bool                      // -no-auth 测试模式: 跳过注册/登录
)

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func usersPath() string {
	exe, _ := os.Executable()
	return filepath.Join(filepath.Dir(exe), "users.json")
}

// saveAuth 持久化账号库。
//
// 【必须走 writeSection 合并写, 不能直接写文件】账号库现在存在 settings.json 的
// auth 节里(那也是一个可供用户手写注释的配置文件)。若这里整文件覆盖写, 会把
// 用户写在 capture/engine 等其它节里的注释与格式全部抹掉 —— 而账号保存属于
// "用户点一下注册/登录就发生"的高频动作, 破坏面很大。
// writeSection 读盘 → 只替换 auth 节 → 原子写回, 其它节字节原样保留。
func saveAuth() {
	if err := writeSection(secAuth, authStore); err != nil {
		logLine("账号库保存失败: " + err.Error())
	}
}

// loadAuth 加载用户库; 无账号则进入注册模式; 有账号则校验设备绑定
func loadAuth() {
	// settings.json 的 auth 节优先, 回退旧 users.json(结构与节内容一致, 共用解析)
	data, ok := section(secAuth, "users.json")
	var parsed userStore
	haveParsed := false
	if ok && len(data) > 0 {
		if json.Unmarshal(data, &parsed) == nil && parsed.Users != nil {
			authStore = &parsed
			return
		}
		// 解析成功但无账号库(只写了 enabled/user/pass 的全新配置): 下面走
		// 全新安装分支, 但开关与初始账密字段必须带过去, 否则用户写的
		// auth.enabled=false / 初始账号会被静默丢弃 —— 表现为"配了不生效"。
		haveParsed = true
	}
	// 全新安装: 无账号, 注册模式(不写盘, 等待注册)
	authStore = &userStore{Salt: randHex(16), Users: map[string]userRec{}}
	if haveParsed {
		authStore.Enabled, authStore.User, authStore.Pass = parsed.Enabled, parsed.User, parsed.Pass
	}
}

func hashPass(salt, pass string) string {
	h := sha256.Sum256([]byte(salt + pass))
	return hex.EncodeToString(h[:])
}

func validUser(u string) bool {
	if len(u) < 2 || len(u) > 20 {
		return false
	}
	for _, c := range u {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func authBlocked() bool {
	return false
}

func http401(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func validSession(r *http.Request) bool {
	c, err := r.Cookie("yugsight_session")
	if err != nil {
		return false
	}
	authMu.Lock()
	rec, ok := sessions[c.Value]
	if ok {
		if time.Now().Before(rec.exp) {
			authMu.Unlock()
			return true
		}
		delete(sessions, c.Value)
	}
	authMu.Unlock()
	return false
}

// sessionRole 当前会话的角色; 无效会话返回空串。
func sessionRole(token string) string {
	authMu.Lock()
	defer authMu.Unlock()
	return sessions[token].role
}

// sessionUser 当前会话的登录用户名; 无效会话返回空串。
// whoami 用它回显真实账号 —— 前端顶栏"用户: xxx"与登录后的展示都依赖它,
// 之前误写死 "ok", 刷新页面后顶栏永远显示不了真实用户名。
func sessionUser(token string) string {
	authMu.Lock()
	defer authMu.Unlock()
	return sessions[token].user
}

// http403Role 权限不足统一 403 响应(前端据 whoami 的 role 隐藏入口, 这里是后端兜底)。
func http403Role(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// adminOnly RBAC 中间件: 只允许 admin(需包在 requireAuth 内使用)。
//
// 使用范围 = "授权管理"页与提权红线: 用户账号体系(/api/v2/users 写)、会话吊销、
// 审计配置与清理。这些能力若对操作员开放, 操作员可自建 admin 账号自我提权,
// 与"操作员只是执行者"的定位冲突 —— 所以这里刻意比 adminOrOperator 更严。
// auditor 等只读角色调写接口一律 403(直接调 API 也不能越权)。
//
// 免登录模式(-no-auth/test_mode.txt)直通: 该模式下没有登录会话, 角色无从解析,
// 与 handleWhoami 的 "local/admin" 同口径 —— 否则规则 6 的"跳过所有鉴权"会被
// 这里架空, 测试模式下全部写接口 403, 整个前端不可用。
func adminOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authDisabled {
			next(w, r)
			return
		}
		c, err := r.Cookie("yugsight_session")
		if err != nil || sessionRole(c.Value) != db.RoleAdmin {
			http403Role(w, "需要管理员权限")
			return
		}
		next(w, r)
	}
}

// adminOrOperator RBAC 中间件: admin 与 operator 均可(需包在 requireAuth 内使用)。
//
// 操作员定位: "除授权管理页外全部功能都能用" —— 扫描/抓包/落库数据/探针/引擎/报告
// 这些写操作都走本中间件; 授权管理页相关(用户/会话/审计配置与清理)保持 adminOnly。
// auditor 仍然只读: 一律 403(与 adminOnly 同口径)。
func adminOrOperator(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authDisabled {
			next(w, r)
			return
		}
		c, err := r.Cookie("yugsight_session")
		if err != nil {
			http403Role(w, "需要管理员或操作员权限")
			return
		}
		switch sessionRole(c.Value) {
		case db.RoleAdmin, db.RoleOperator:
			next(w, r)
		default:
			http403Role(w, "需要管理员或操作员权限")
		}
	}
}

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if authDisabled {
			next(w, r)
			return
		}
		if authBlocked() {
			http401(w, "设备已变更, 注册已失效, 请先迁移绑定")
			return
		}
		if !validSession(r) {
			http401(w, "未登录")
			return
		}
		next(w, r)
	}
}

// handleRegister 首次注册: 创建账号 + 绑定设备 + 生成迁移密钥
func handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		User, Pass, Pass2 string
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http401(w, "请求格式错误")
		return
	}
	user := strings.TrimSpace(req.User)
	if !validUser(user) {
		http401(w, "用户名需 2-20 位字母/数字/_/-")
		return
	}
	if len(req.Pass) < minPassLen {
		http401(w, "密码至少 "+strconv.Itoa(minPassLen)+" 位")
		return
	}
	if req.Pass != req.Pass2 {
		http401(w, "两次输入的密码不一致")
		return
	}
	authMu.Lock()
	defer authMu.Unlock()
	if len(authStore.Users) > 0 {
		http401(w, "已存在账户, 请直接登录")
		return
	}
	if _, exists := authStore.Users[user]; exists {
		http401(w, "用户名已存在")
		return
	}
	authStore.Users[user] = userRec{PassHash: hashPass(authStore.Salt, req.Pass)}
	saveAuth()
	logLine("已注册账户: " + user)
	// 注册成功直接建立会话(首个注册者 = admin, 与 db 用户表"首个账号自动提升"同口径)
	token := randHex(24)
	sessions[token] = sessionRec{exp: time.Now().Add(12 * time.Hour), user: user, role: db.RoleAdmin}
	// 同步写入 db 用户表(RBAC 载体): 行不存在则建号; 行已存在(如 2FA 链路
	// 懒创建的空哈希行)则对齐角色, 且空哈希时回填注册密码 —— 两轨 passHash
	// 口径保持一致(见 backfillPassHash 注释)
	if m := accountMgr(); m != nil {
		if u, err := m.Users.Get(user); err != nil {
			if _, cerr := m.CreateUser(user, req.Pass, db.RoleAdmin); cerr != nil {
				logLine("注册用户同步到账号库失败: " + cerr.Error())
			}
		} else {
			opts := &account.UpdateOpts{}
			if u.Role != db.RoleAdmin {
				opts.Role = ptrRole(db.RoleAdmin)
			}
			if u.PassHash == "" {
				pw := req.Pass
				opts.Password = &pw
			}
			if opts.Role != nil || opts.Password != nil {
				if _, uerr := m.UpdateUser(user, opts); uerr != nil {
					logLine("注册用户双轨对齐失败: " + uerr.Error())
				}
			}
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "yugsight_session", Value: token, Path: "/", HttpOnly: true, MaxAge: 12 * 3600})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"user": user})
}

// handleLogin 用户名 + 密码 登录(启用 2FA 时第二步需提交动态验证码)。
//
// 两步合并在同一接口: 第二步由前端携带同一次输入的 user/pass+code 重放提交,
// 无服务端"半登录"中间态 —— 少一套 pending token 生命周期要管, 失败语义
// 与既有 401 完全一致。
// "记住登录"(trust): 完整登录通过后签发 24h 信任 cookie; 之后口令仍必校验,
// 动态码可免(见 auth_2fa.go)。
func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		User  string `json:"user"`
		Pass  string `json:"pass"`
		Code  string `json:"code"`  // 6 位动态验证码(2FA 启用且无信任令牌时必填)
		Trust bool   `json:"trust"` // 登录成功后签发 24h "记住登录"信任令牌
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		http401(w, "请求格式错误")
		return
	}
	// 登录限流: 5 分钟窗口内失败 5 次锁定 15 分钟(免登录/测试模式跳过, 规则 6)。
	// 判定放在校验之前: 锁定期间连正确口令也拒, 否则爆破只是被限速而非被拦住。
	ip := loginLimitKey(r)
	if loginLimitOn() {
		if locked, remain := loginLimit.Locked(ip); locked {
			http429Locked(w, remain)
			return
		}
	}
	authMu.Lock()
	u, ok := authStore.Users[req.User]
	store := authStore
	authMu.Unlock()
	if !ok || u.PassHash != hashPass(store.Salt, req.Pass) {
		loginFail(w, r, ip, req.User, "用户名或密码错误")
		return
	}
	// ===== 2FA 第二步: 口令通过后校验动态码 =====
	// 免登录测试模式(-no-auth/test_mode.txt)跳过; 有效信任令牌免码。
	// 读库失败按未配置降级(twoFAInfo 语义), 不阻断登录。
	if !authDisabled {
		if enabled, seed := twoFAInfo(req.User); enabled && seed != "" && !trustOK(r) {
			if trimCode(req.Code) == "" {
				http401Need2FA(w)
				return
			}
			if !hotpVerify(seed, req.Code, time.Now()) {
				// 动态码错误同时喂两个限流器: 按 IP 拦爆破者, 按 user+IP 让
				// /api/auth/2fa/code 同口径锁定(见 auth_ratelimit.go 文件头)
				if loginLimitOn() {
					loginLimit.Failure(ip)
					codeLimit.Failure(codeLimitKey(r, req.User))
				}
				logAudit(v2DB(), r, "login_failed", req.User, "动态验证码错误 (IP "+ip+")")
				http401(w, "动态验证码错误或已过期")
				return
			}
		}
	}
	// v2 用户表 passHash 空值口径对齐: 2FA 链路懒创建的行 PassHash 为空(见
	// auth_2fa.go 头注), 登录成功即回填 bcrypt 哈希 —— 空态仅存在于用户首次
	// 成功登录之前, 此后 account 包的 Verify(bcrypt 校验)口径对所有真实用户成立。
	backfillPassHash(req.User, req.Pass)
	loginOK(r, ip, req.User)
	// 登录成功入审计(失败路径已有 login_failed): 审计日志是"谁在什么时候进了系统"
	// 的第一证据, 用户明确要求登录/操作/启动全量入审计。
	logAudit(v2DB(), r, "login.success", req.User, "IP "+ip)
	// RBAC: 角色以 db 用户表为准(三态 admin/operator/auditor); 表内无该用户
	// (旧单用户安装)按 admin 兼容 —— 保持"原来什么权限, 升级后什么权限",
	// 不锁死既有用户。未知角色值由 account.NormalizeRole 兜底降为只读,
	// 与用户管理侧的写入口径同源(两处各写 if-else 迟早分叉)。
	role := db.RoleAdmin
	if m := accountMgr(); m != nil {
		if u, err := m.Users.Get(req.User); err == nil {
			role = account.NormalizeRole(u.Role)
		}
	}
	token := randHex(24)
	authMu.Lock()
	sessions[token] = sessionRec{exp: time.Now().Add(12 * time.Hour), user: req.User, role: role}
	authMu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: "yugsight_session", Value: token, Path: "/", HttpOnly: true, MaxAge: 12 * 3600})
	if req.Trust {
		// 只有完整登录(含动态码校验)才可能走到这里, 签发时机安全
		issueTrustToken(w)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"user": req.User, "role": role})
}

// backfillPassHash v2 用户表 passHash 空值口径对齐: 行存在但 PassHash 为空时,
// 用明文密码回填 bcrypt 哈希。明文已知的入口只有两个 —— 注册(handleRegister)
// 与登录成功(本函数), 两处都走这里, 保证口径唯一。
//
// 【为什么需要】2FA 链路(登录页拉码值)会懒创建用户行且 PassHash 留空; 空值在
// account 包 Verify 的口径里是"必然校验失败", 在登录链路(authStore 哈希)里是
// "照常登录" —— 同一空值两种解读, 就是"口径不对齐"。回填后空态只剩"用户从未
// 成功登录过"这一种含义。失败一律静默降级(登录/注册主链路不因 db 异常中断)。
func backfillPassHash(user, pass string) {
	m := accountMgr()
	if m == nil {
		return
	}
	u, err := m.Users.Get(user)
	if err != nil || u == nil || u.PassHash != "" {
		return
	}
	h, err := account.HashPassword(pass, account.DefaultCost)
	if err != nil {
		return
	}
	u.PassHash = h
	if err := m.Users.Update(u); err != nil {
		logLine("账号库回填密码哈希失败(用户 " + user + "): " + err.Error())
	}
}

// handleAuthStatus 返回注册状态(免登录)
func handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	authMu.Lock()
	registered := authStore != nil && len(authStore.Users) > 0
	disabled := authDisabled
	authMu.Unlock()
	if disabled {
		registered = true
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]bool{"registered": registered, "disabled": disabled})
}

func handleWhoami(w http.ResponseWriter, r *http.Request) {
	if authDisabled {
		// 免登录模式视为最高权限(前端全功能可用)
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Write([]byte(`{"user":"local","role":"admin"}`))
		return
	}
	c, err := r.Cookie("yugsight_session")
	if err != nil || !validSession(r) {
		http401(w, "未登录")
		return
	}
	// role 供前端决定只读态: auditor 隐藏用户管理/写操作入口;
	// 后端 adminOnly 中间件是真正的权限边界, 这里只是 UI 提示。
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]string{"user": sessionUser(c.Value), "role": sessionRole(c.Value)})
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie("yugsight_session"); err == nil {
		authMu.Lock()
		rec, ok := sessions[c.Value]
		delete(sessions, c.Value)
		authMu.Unlock()
		if ok {
			// 登出入审计(与 login.success 配对): 审计要求"操作全量入日志"
			logAudit(v2DB(), r, "logout", rec.user, "IP "+clientIP(r))
		}
	}
	http.SetCookie(w, &http.Cookie{Name: "yugsight_session", Value: "", Path: "/", MaxAge: -1})
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Write([]byte(`{"ok":true}`))
}
