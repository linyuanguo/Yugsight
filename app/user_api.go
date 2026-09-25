package main

// 用户管理 REST API(RBAC 载体, 任务: 多用户 + 角色权限)。
//
// 双轨账号体系并存(见 db/user.go 头注):
//   - authStore(settings.json auth 节): 本地桌面单用户, sha256+salt, 设备绑定
//   - db 用户表(data/users.jsonl): 中心管理端多用户, bcrypt, 角色 admin/auditor
//
// 登录鉴权仍走 authStore(既有行为零改动, 登录限流/2FA 全部照旧), 角色从 db
// 表解析后固化进会话; 本文件的管理操作对两轨同步写, 保证"改密码/停用"在
// 登录校验与角色判定两侧同时生效 —— 只改一侧会出现"停用账号还能登录"的漏洞。
//
// 路由(除 /me 外全部 adminOnly):
//
//	GET    /api/v2/users          用户列表(不含密码哈希)
//	POST   /api/v2/users          创建 {username,password,role?}
//	PUT    /api/v2/users/{name}   更新 {password?,role?,enabled?}
//	DELETE /api/v2/users/{name}   删除(同步踢出会话)
//	GET    /api/v2/users/me       当前用户 {user,role}(requireAuth 即可)

import (
	"encoding/json"
	"errors"
	"net/http"
	"sync"

	"yugsight/internal/account"
	"yugsight/internal/db"
	"yugsight/internal/server"
)

var (
	accountMgrOnce sync.Once
	accountMgrInst *account.Manager
)

// accountMgr 账号管理器单例(懒加载)。
// v2 库不可用时返回 nil —— 调用方按"无多用户体系"降级: 登录角色全部按 admin
// 兼容(旧单用户语义), 用户管理接口返回 503, 不 panic 不崩。
func accountMgr() *account.Manager {
	accountMgrOnce.Do(func() {
		d := v2DB()
		if d == nil || d.Users() == nil || d.Sessions() == nil {
			return
		}
		accountMgrInst = account.NewManager(d.Users(), d.Sessions(), 12*3600*1e9, logLine)
	})
	return accountMgrInst
}

func ptrRole(s string) *string { return &s }

func userOuts(m *account.Manager) ([]account.UserOut, error) {
	return m.ListUsers()
}

// authSaveFunc 持久化接缝: 默认 saveAuth(写 settings.json auth 节)。
// 测试替换为 no-op —— 用例必须不能污染开发机真实配置(调度器测试踩过同类坑)。
var authSaveFunc = saveAuth

// syncAuthStore 把 db 用户表变更同步到 authStore(登录校验侧)。
// 与 handleRegister/handleLogin 的写路径共用 authMu, 保持 users.json 读写一致性。
//
// 锁内只做内存改, 持久化(authSaveFunc)放锁外: 持锁期间做磁盘 I/O 会拉长
// 锁窗口, 其他等锁路径(会话检查/测试清理)与它叠加时曾实测死锁。
func syncAuthStore(username, plainPass string, enabled bool) {
	// 停用: 必须从 authStore 移除(登录直接失败), 与本次是否改密码无关 ——
	// 曾把"密码为空就跳过"放在最前面, 导致"只停用不改密"时账号残留、还能登录。
	if !enabled {
		authMu.Lock()
		if authStore != nil && authStore.Users != nil {
			delete(authStore.Users, username)
		}
		authMu.Unlock()
		authSaveFunc()
		return
	}
	if plainPass == "" {
		return
	}
	authMu.Lock()
	if authStore == nil || authStore.Users == nil {
		authMu.Unlock()
		return
	}
	// 改密码: 同步更新 authStore 哈希, 否则新密码登录被旧哈希拒掉
	authStore.Users[username] = userRec{PassHash: hashPass(authStore.Salt, plainPass)}
	authMu.Unlock()
	authSaveFunc()
}

// kickUserSessions 吊销某用户的全部内存会话(authStore 侧; db 侧由 KickUser 负责)。
func kickUserSessions(username string) {
	authMu.Lock()
	defer authMu.Unlock()
	for tok, rec := range sessions {
		if rec.user == username {
			delete(sessions, tok)
		}
	}
}

// handleUsersCollection 同路径 GET(列表) / POST(创建) 按方法分发。
//
// 为什么必须分发: Go 1.22 ServeMux 同路径只能注册一个 handler, 若只挂 list,
// POST 创建会静默返回用户列表(200)—— 前端以为建成功了, 实际什么都没建,
// 这类"假成功"比报错难查得多(本次测试就是被它坑出来的)。
func handleUsersCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		handleUsersCreate(w, r)
	default:
		handleUsersList(w, r)
	}
}

func handleUsersList(w http.ResponseWriter, r *http.Request) {
	m := accountMgr()
	if m == nil {
		failJSON(w, "账号库不可用(数据目录未初始化)")
		return
	}
	out, err := m.ListUsers()
	if err != nil {
		failJSON(w, err.Error())
		return
	}
	server.OK(w, out)
}

func handleUsersCreate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		failJSON(w, "method not allowed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		failJSON(w, "请求格式错误")
		return
	}
	m := accountMgr()
	if m == nil {
		failJSON(w, "账号库不可用(数据目录未初始化)")
		return
	}
	if req.Role == "" {
		req.Role = db.RoleAuditor // 默认只读, 显式提权才能给 admin
	}
	if _, err := m.CreateUser(req.Username, req.Password, req.Role); err != nil {
		if errors.Is(err, account.ErrUserExists) {
			failJSON(w, "用户名已存在")
			return
		}
		failJSON(w, err.Error())
		return
	}
	syncAuthStore(req.Username, req.Password, true)
	logAudit(v2DB(), r, "user_create", req.Username, "角色 "+req.Role)
	server.OK(w, map[string]string{"username": req.Username, "role": req.Role})
}

// handleUsersManage 同路径 PUT(更新) / DELETE(删除) 按方法分发。
func handleUsersManage(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPut:
		handleUsersUpdate(w, r)
	case http.MethodDelete:
		handleUsersDelete(w, r)
	default:
		failJSON(w, "method not allowed")
	}
}

func handleUsersUpdate(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	var req struct {
		Password string `json:"password"`
		Role     string `json:"role"`
		Enabled  *bool  `json:"enabled"`
	}
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		failJSON(w, "请求格式错误")
		return
	}
	m := accountMgr()
	if m == nil {
		failJSON(w, "账号库不可用(数据目录未初始化)")
		return
	}
	opts := &account.UpdateOpts{Password: strPtrIf(req.Password), Role: strPtrIf(req.Role), Enabled: req.Enabled}
	if opts.Password == nil && opts.Role == nil && opts.Enabled == nil {
		failJSON(w, "无更新字段")
		return
	}
	if _, err := m.UpdateUser(name, opts); err != nil {
		if errors.Is(err, account.ErrLastAdmin) {
			failJSON(w, "不能操作唯一的启用中管理员")
			return
		}
		if errors.Is(err, account.ErrUserNotFnd) {
			failJSON(w, "用户不存在")
			return
		}
		failJSON(w, err.Error())
		return
	}
	// 同步 authStore: 改密码/停用必须两侧一致, 否则出现"停用后仍可登录"
	u, _ := m.Users.Get(name)
	if u != nil {
		if req.Enabled != nil && !*req.Enabled {
			kickUserSessions(name)
		}
		syncAuthStore(name, req.Password, u.Enabled)
	}
	logAudit(v2DB(), r, "user_update", name, "")
	server.OK(w, m.ToOut(u))
}

func handleUsersDelete(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	m := accountMgr()
	if m == nil {
		failJSON(w, "账号库不可用(数据目录未初始化)")
		return
	}
	if err := m.DeleteUser(name); err != nil {
		if errors.Is(err, account.ErrLastAdmin) {
			failJSON(w, "不能删除唯一的启用中管理员")
			return
		}
		if errors.Is(err, account.ErrUserNotFnd) {
			failJSON(w, "用户不存在")
			return
		}
		failJSON(w, err.Error())
		return
	}
	syncAuthStore(name, "", false)
	kickUserSessions(name)
	logAudit(v2DB(), r, "user_delete", name, "")
	server.OK(w, map[string]bool{"ok": true})
}

func handleUsersMe(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("yugsight_session")
	if err != nil {
		failJSON(w, "未登录")
		return
	}
	authMu.Lock()
	rec, ok := sessions[c.Value]
	authMu.Unlock()
	if !ok {
		failJSON(w, "未登录")
		return
	}
	server.OK(w, map[string]string{"user": rec.user, "role": rec.role})
}

// strPtrIf 空串返回 nil(UpdateOpts 语义: nil=不修改), 避免"空密码清空哈希"。
func strPtrIf(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
