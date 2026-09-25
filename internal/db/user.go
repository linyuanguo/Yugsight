package db

import (
	"errors"
	"strings"
	"time"
)

// 用户角色常量(RBAC 三角色, 任务 5 + 2026-09-22 增加操作员):
// admin    = 管理员(全权限, 含授权管理页: 用户 / 会话 / 审计清理);
// operator = 操作员(除授权管理页外全部功能: 能扫描/改资产漏洞/管探针与引擎, 但碰不到账号体系);
// auditor  = 审计员(只读: 仅查看)。
// 【注意】"operator" 曾是旧口径里的"只读"值(见 account.NormalizeRole 历史注释),
// 现复用为真正的操作员角色 —— 老库里若残留 role=operator 的行, 升级后会获得写权限,
// 上线后建议在用户管理页复核一次既有账号角色。
const (
	RoleAdmin    = "admin"
	RoleOperator = "operator"
	RoleAuditor  = "auditor"
)

// User 用户账号表实体(中心管理端多用户场景)。
// 本地桌面端的单用户账号仍走 users.json(防盗用/设备绑定), 本表服务
// 中心管理端; 两套账号体系互不干扰。
type User struct {
	ID        string    `json:"id"` // = 用户名
	Username  string    `json:"username"`
	PassHash  string    `json:"passHash"`
	Role      string    `json:"role"` // admin|operator|auditor
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"createdAt"`

	// ===== 2FA(动态验证码)状态 —— 本次新增的仅有的两个字段 =====
	// 本地桌面端登录(auth.go)按用户名对齐本表读写这两个字段; PassHash/
	// Role 等既有字段不参与桌面端登录, 语义不变。
	// TwoFAEnabled 2FA 启用标记: true 时登录需提交 6 位动态验证码。
	TwoFAEnabled bool `json:"twoFAEnabled"`
	// TwoFASeed HOTP 种子密钥(base32 无填充, 32 字符, 160 位熵)。
	// 由管理员登录后在设置页手动生成; 明文回显供备份恢复, 绝不写入
	// settings.json 等配置文件。为空表示尚未配置(此时开关不可开启)。
	TwoFASeed string `json:"twoFASeed,omitempty"`
}

// EntityID 用户 ID(= 用户名)。
func (u *User) EntityID() string {
	if u.ID == "" {
		u.ID = u.Username
	}
	return u.ID
}

// Validate 自检: 用户名规则(2-20 位字母/数字/_/-), 角色默认 auditor。
func (u *User) Validate() error {
	if u.Username == "" {
		return errors.New("用户名不能为空")
	}
	if !validUsername(u.Username) {
		return errors.New("用户名需 2-20 位字母/数字/_/-")
	}
	if u.Role == "" {
		u.Role = RoleAuditor
	}
	if u.ID == "" {
		u.ID = u.Username
	}
	if u.CreatedAt.IsZero() {
		u.CreatedAt = time.Now()
	}
	return nil
}

// NewUser 构造用户(默认启用, 角色 auditor)。
func NewUser(username, passHash string) *User {
	return &User{Username: username, PassHash: passHash, Role: RoleAuditor, Enabled: true}
}

func validUsername(u string) bool {
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

// Session 用户会话表实体。
type Session struct {
	ID        string     `json:"id"` // 会话 token
	UserID    string     `json:"userId"`
	ClientIP  string     `json:"clientIp,omitempty"`
	CreatedAt time.Time  `json:"createdAt"`
	ExpiresAt time.Time  `json:"expiresAt"`
	RevokedAt *time.Time `json:"revokedAt,omitempty"`
}

// EntityID 会话 ID。
func (s *Session) EntityID() string {
	if s.ID == "" {
		s.ID = newID("sn")
	}
	return s.ID
}

// Validate 自检: token / 用户 / 过期时间必填。
func (s *Session) Validate() error {
	if strings.TrimSpace(s.ID) == "" {
		return errors.New("会话 token 不能为空")
	}
	if s.UserID == "" {
		return errors.New("会话所属用户不能为空")
	}
	if s.ExpiresAt.IsZero() {
		return errors.New("会话过期时间不能为空")
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	return nil
}

// Revoked 是否已吊销。
func (s *Session) Revoked() bool { return s.RevokedAt != nil }

// Expired 是否已过期。
func (s *Session) Expired() bool { return time.Now().After(s.ExpiresAt) }

// UserDAO 用户账号 DAO。
type UserDAO struct {
	*Table[*User]
}

// newUserTable 打开用户表。
func newUserTable(path string) (*UserDAO, error) {
	t, err := NewTable[*User]("users", path, func() *User { return &User{} })
	if err != nil {
		return nil, err
	}
	return &UserDAO{Table: t}, nil
}

// EnabledOnly 启用中的用户。
func (d *UserDAO) EnabledOnly() ([]*User, error) {
	return d.Query(func(u *User) bool { return u.Enabled })
}

// SessionDAO 用户会话 DAO。
type SessionDAO struct {
	*Table[*Session]
}

// newSessionTable 打开会话表。
func newSessionTable(path string) (*SessionDAO, error) {
	t, err := NewTable[*Session]("sessions", path, func() *Session { return &Session{} })
	if err != nil {
		return nil, err
	}
	return &SessionDAO{Table: t}, nil
}

// Revoke 吊销会话(幂等)。
func (d *SessionDAO) Revoke(id string) error {
	s, err := d.Get(id)
	if err != nil {
		return err
	}
	if s.RevokedAt == nil {
		now := time.Now()
		s.RevokedAt = &now
		return d.Update(s)
	}
	return nil
}

// Active 有效会话(未吊销且未过期)。
func (d *SessionDAO) Active() ([]*Session, error) {
	return d.Query(func(s *Session) bool { return !s.Revoked() && !s.Expired() })
}

// ExpireNow 清理已过期/已吊销会话, 返回清理数量。
func (d *SessionDAO) ExpireNow() int {
	list, _ := d.List()
	n := 0
	for _, s := range list {
		if s.Revoked() || s.Expired() {
			if _, err := d.Delete(s.ID); err == nil {
				n++
			}
		}
	}
	return n
}
