package account

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"yugsight/db"
)

// 密码最低长度(与经典账号体系 minPassLen 一致)。
const minPassLen = 6

var (
	ErrUserExists  = errors.New("用户名已存在")
	ErrUserNotFnd  = errors.New("用户不存在")
	ErrBadCred     = errors.New("用户名或密码错误")
	ErrUserLocked  = errors.New("账号已停用")
	ErrLastAdmin   = errors.New("不能操作唯一的启用中管理员")
	ErrSessionDead = errors.New("会话已失效, 请重新登录")
)

// Manager 账号会话管理器: 全部持久化经 db 统一 DAO 接口(users/sessions 表),
// 业务层不直接操作存储。
type Manager struct {
	Users    *db.UserDAO
	Sessions *db.SessionDAO
	TTL      time.Duration // 会话有效期
	log      func(string)
}

// NewManager 构建账号管理器。ttl<=0 时默认 12 小时。
func NewManager(users *db.UserDAO, sessions *db.SessionDAO, ttl time.Duration, log func(string)) *Manager {
	if ttl <= 0 {
		ttl = 12 * time.Hour
	}
	if log == nil {
		log = func(string) {}
	}
	return &Manager{Users: users, Sessions: sessions, TTL: ttl, log: log}
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// UserOut 账号视图(不泄露密码哈希)。
type UserOut struct {
	Username  string    `json:"username"`
	Role      string    `json:"role"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`
}

// ToOut 转视图。
func (m *Manager) ToOut(u *db.User) UserOut {
	return UserOut{Username: u.Username, Role: u.Role, Enabled: u.Enabled, CreatedAt: u.CreatedAt}
}

// NormalizeRole 角色归一: admin/operator 保持; 其余(未知值/历史空值)一律 auditor。
//
// 导出原因: 登录时(main 包 auth.go)也要按同一口径把 db 行里的角色固化进会话,
// 两处各写一份 if-else 迟早分叉 —— 只读兜底必须是唯一实现。
func NormalizeRole(role string) string {
	switch role {
	case db.RoleAdmin:
		return db.RoleAdmin
	case db.RoleOperator:
		return db.RoleOperator
	default:
		return db.RoleAuditor
	}
}

// CreateUser 创建账号(bcrypt 哈希; 系统首个账号自动提升为 admin, 保证可管理)。
func (m *Manager) CreateUser(username, pass, role string) (*db.User, error) {
	if len(pass) < minPassLen {
		return nil, fmt.Errorf("密码至少 %d 位", minPassLen)
	}
	role = NormalizeRole(role)
	if n, err := m.Users.Count(); err == nil && n == 0 && role != db.RoleAdmin {
		role = db.RoleAdmin
	}
	hash, err := HashPassword(pass, DefaultCost)
	if err != nil {
		return nil, err
	}
	u := db.NewUser(username, hash)
	u.Role = role
	if err := u.Validate(); err != nil {
		return nil, err
	}
	if err := m.Users.Create(u); err != nil {
		if errors.Is(err, db.ErrExists) {
			return nil, ErrUserExists
		}
		return nil, err
	}
	m.log("账号已创建: " + u.Username + " (角色 " + role + ")")
	return u, nil
}

// UpdateOpts 账号更新选项(空值 = 不修改)。
type UpdateOpts struct {
	Password *string
	Role     *string
	Enabled  *bool
}

// UpdateUser 更新账号; 唯一的启用中管理员不可降权/停用。
func (m *Manager) UpdateUser(username string, opts *UpdateOpts) (*db.User, error) {
	u, err := m.Users.Get(username)
	if err != nil {
		return nil, ErrUserNotFnd
	}
	if opts == nil {
		return u, nil
	}
	lastAdmin, _ := m.isOnlyEnabledAdmin(u)
	if lastAdmin {
		if opts.Enabled != nil && !*opts.Enabled {
			return nil, ErrLastAdmin
		}
		if opts.Role != nil && NormalizeRole(*opts.Role) != db.RoleAdmin {
			return nil, ErrLastAdmin
		}
	}
	if opts.Password != nil && *opts.Password != "" {
		if len(*opts.Password) < minPassLen {
			return nil, fmt.Errorf("密码至少 %d 位", minPassLen)
		}
		hash, herr := HashPassword(*opts.Password, DefaultCost)
		if herr != nil {
			return nil, herr
		}
		u.PassHash = hash
	}
	if opts.Role != nil {
		u.Role = NormalizeRole(*opts.Role)
	}
	if opts.Enabled != nil {
		u.Enabled = *opts.Enabled
	}
	if err := m.Users.Update(u); err != nil {
		return nil, err
	}
	m.log("账号已更新: " + u.Username)
	return u, nil
}

// DeleteUser 删除账号(唯一的启用中管理员不可删); 同步吊销其全部会话。
func (m *Manager) DeleteUser(username string) error {
	u, err := m.Users.Get(username)
	if err != nil {
		return ErrUserNotFnd
	}
	if last, _ := m.isOnlyEnabledAdmin(u); last {
		return ErrLastAdmin
	}
	if _, err := m.KickUser(username); err != nil {
		m.log("删除账号时吊销会话失败: " + err.Error())
	}
	if ok, err := m.Users.Delete(u.ID); err != nil || !ok {
		return err
	}
	m.log("账号已删除: " + username)
	return nil
}

// Verify 校验凭证(bcrypt); 统一返回 ErrBadCred(不区分用户不存在/密码错误)。
func (m *Manager) Verify(username, pass string) (*db.User, error) {
	u, err := m.Users.Get(username)
	if err != nil {
		return nil, ErrBadCred
	}
	if !u.Enabled {
		return nil, ErrUserLocked
	}
	if err := CompareHashAndPassword(u.PassHash, pass); err != nil {
		return nil, ErrBadCred
	}
	return u, nil
}

// ListUsers 全部账号(不泄露密码)。
func (m *Manager) ListUsers() ([]UserOut, error) {
	list, err := m.Users.List()
	if err != nil {
		return nil, err
	}
	out := make([]UserOut, 0, len(list))
	for _, u := range list {
		out = append(out, m.ToOut(u))
	}
	return out, nil
}

// CreateSession 创建会话(token + 有效期), 返回 token 与过期时间。
func (m *Manager) CreateSession(username, clientIP string) (string, time.Time, error) {
	tok := randToken(24)
	exp := time.Now().Add(m.TTL)
	s := &db.Session{ID: tok, UserID: username, ClientIP: clientIP, ExpiresAt: exp}
	if err := s.Validate(); err != nil {
		return "", time.Time{}, err
	}
	if err := m.Sessions.Create(s); err != nil {
		return "", time.Time{}, err
	}
	return tok, exp, nil
}

// Lookup 按 token 查找会话与所属用户; 已吊销/已过期/用户停用均视为失效。
func (m *Manager) Lookup(token string) (*db.User, *db.Session, error) {
	if strings.TrimSpace(token) == "" {
		return nil, nil, ErrSessionDead
	}
	s, err := m.Sessions.Get(token)
	if err != nil {
		return nil, nil, ErrSessionDead
	}
	if s.Revoked() || s.Expired() {
		return nil, nil, ErrSessionDead
	}
	u, err := m.Users.Get(s.UserID)
	if err != nil {
		return nil, nil, ErrSessionDead
	}
	if !u.Enabled {
		return nil, nil, ErrUserLocked
	}
	return u, s, nil
}

// RevokeSession 按完整 token 或前缀吊销会话, 返回吊销数量。
func (m *Manager) RevokeSession(tokenPrefix string) (int, error) {
	if strings.TrimSpace(tokenPrefix) == "" {
		return 0, errors.New("会话 token 不能为空")
	}
	n := 0
	list, err := m.Sessions.List()
	if err != nil {
		return 0, err
	}
	for _, s := range list {
		if !s.Revoked() && (s.ID == tokenPrefix || strings.HasPrefix(s.ID, tokenPrefix)) {
			if err := m.Sessions.Revoke(s.ID); err == nil {
				n++
			}
		}
	}
	return n, nil
}

// KickUser 强制踢出: 吊销该用户全部未吊销会话, 返回数量。
func (m *Manager) KickUser(username string) (int, error) {
	n := 0
	list, err := m.Sessions.List()
	if err != nil {
		return 0, err
	}
	for _, s := range list {
		if s.UserID == username && !s.Revoked() {
			if err := m.Sessions.Revoke(s.ID); err == nil {
				n++
			}
		}
	}
	return n, nil
}

// SessionsOf 该用户的有效(未吊销未过期)会话。
func (m *Manager) SessionsOf(username string) ([]*db.Session, error) {
	list, err := m.Sessions.List()
	if err != nil {
		return nil, err
	}
	var out []*db.Session
	for _, s := range list {
		if s.UserID == username && !s.Revoked() && !s.Expired() {
			out = append(out, s)
		}
	}
	return out, nil
}

// CleanupExpired 清理已过期/已吊销会话, 返回清理数量。
func (m *Manager) CleanupExpired() int {
	return m.Sessions.ExpireNow()
}

// isOnlyEnabledAdmin 判断是否为唯一的启用中管理员。
func (m *Manager) isOnlyEnabledAdmin(u *db.User) (bool, error) {
	if u.Role != db.RoleAdmin || !u.Enabled {
		return false, nil
	}
	list, err := m.Users.List()
	if err != nil {
		return false, err
	}
	for _, x := range list {
		if x.ID != u.ID && x.Role == db.RoleAdmin && x.Enabled {
			return false, nil
		}
	}
	return true, nil
}
