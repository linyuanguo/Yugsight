package account

import (
	"errors"
	"testing"
	"time"

	"yugsight/db"
)

// newTestManager 临时库 + 快速 cost(通过短 TTL 验证会话过期)。
func newTestManager(t *testing.T, ttl time.Duration) (*Manager, *db.Database) {
	t.Helper()
	d, err := db.Open(db.Config{Type: db.TypeSQLite, Dir: t.TempDir()})
	if err != nil {
		t.Fatalf("db.Open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	m := NewManager(d.Users(), d.Sessions(), ttl, func(string) {})
	return m, d
}

// TestNormalizeRoleThreeRoles 角色归一必须保留 operator。
//
// 被改坏的症状是"静默降级": 操作员在登录/建号/改角色时被归一成只读,
// 界面上角色写着操作员却什么都干不了(403), 不报错所以极难定位。
func TestNormalizeRoleThreeRoles(t *testing.T) {
	cases := map[string]string{
		db.RoleAdmin:    db.RoleAdmin,
		db.RoleOperator: db.RoleOperator,
		db.RoleAuditor:  db.RoleAuditor,
		"":              db.RoleAuditor, // 历史空值 -> 最小权限兜底
		"root":          db.RoleAuditor, // 未知值 -> 最小权限兜底
	}
	for in, want := range cases {
		if got := NormalizeRole(in); got != want {
			t.Errorf("NormalizeRole(%q)=%q, 期望 %q", in, got, want)
		}
	}
}

// TestUserCRUD 账号增删改查 + 首账号自动 admin + 唯一管理员保护。
func TestUserCRUD(t *testing.T) {
	m, d := newTestManager(t, time.Hour)
	// 首个账号自动 admin
	u1, err := m.CreateUser("admin1", "pass123", db.RoleAuditor)
	if err != nil {
		t.Fatal(err)
	}
	if u1.Role != db.RoleAdmin {
		t.Fatalf("首账号应自动 admin, 实际 %s", u1.Role)
	}
	// 重复用户名
	if _, err := m.CreateUser("admin1", "xxx123", db.RoleAuditor); !errors.Is(err, ErrUserExists) {
		t.Fatalf("重复用户名 err=%v", err)
	}
	// 弱密码
	if _, err := m.CreateUser("weak", "123", db.RoleAuditor); err == nil {
		t.Fatal("弱密码应拒绝")
	}
	// 创建审计员
	u2, err := m.CreateUser("auditor1", "pass456", db.RoleAuditor)
	if err != nil {
		t.Fatal(err)
	}
	if u2.Role != db.RoleAuditor {
		t.Fatalf("角色=%s", u2.Role)
	}
	// 列表(不泄露哈希)
	list, err := m.ListUsers()
	if err != nil || len(list) != 2 {
		t.Fatalf("list=%d,%v", len(list), err)
	}
	for _, x := range list {
		if x.Username == "" || x.Role == "" {
			t.Fatalf("视图不完整: %+v", x)
		}
	}
	// 唯一启用中 admin 保护(停用/降权/删除均应拒绝)
	if _, err := m.UpdateUser("admin1", &UpdateOpts{Enabled: ptr(false)}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("唯一 admin 停用 err=%v", err)
	}
	if _, err := m.UpdateUser("admin1", &UpdateOpts{Role: ptr(db.RoleAuditor)}); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("唯一 admin 降权 err=%v", err)
	}
	if err := m.DeleteUser("admin1"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("唯一 admin 删除 err=%v", err)
	}
	// 提升 auditor1 为 admin 后, admin1 即可停用
	if _, err := m.UpdateUser("auditor1", &UpdateOpts{Role: ptr(db.RoleAdmin)}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.UpdateUser("auditor1", &UpdateOpts{Password: ptr("newpass789")}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify("auditor1", "newpass789"); err != nil {
		t.Fatalf("改密后应能登录: %v", err)
	}
	if _, err := m.UpdateUser("admin1", &UpdateOpts{Enabled: ptr(false)}); err != nil {
		t.Fatalf("有第二 admin 后应可停用: %v", err)
	}
	if _, err := m.Verify("admin1", "pass123"); !errors.Is(err, ErrUserLocked) {
		t.Fatalf("停用账号登录 err=%v", err)
	}
	// 停用中的 admin 可删(启用中 admin 仍有 auditor1)
	if err := m.DeleteUser("admin1"); err != nil {
		t.Fatal(err)
	}
	// 最后一位启用中 admin 不可删
	if err := m.DeleteUser("auditor1"); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("最后一个启用中 admin 删除 err=%v", err)
	}
	if n, _ := d.Users().Count(); n != 1 {
		t.Fatalf("count=%d", n)
	}
}

// TestVerify 凭证校验(统一错误信息, 不泄露用户存在性)。
func TestVerify(t *testing.T) {
	m, _ := newTestManager(t, time.Hour)
	if _, err := m.CreateUser("u1", "pass123", db.RoleAdmin); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify("u1", "pass123"); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Verify("u1", "badpass"); !errors.Is(err, ErrBadCred) {
		t.Fatalf("err=%v", err)
	}
	if _, err := m.Verify("ghost", "whatever"); !errors.Is(err, ErrBadCred) {
		t.Fatalf("不存在的用户应同错: %v", err)
	}
}

// TestSessions 会话: 创建/查找/过期/吊销/踢出/清理。
func TestSessions(t *testing.T) {
	m, _ := newTestManager(t, 50*time.Millisecond)
	m.CreateUser("u1", "pass123", db.RoleAdmin)
	m.CreateUser("u2", "pass456", db.RoleAuditor)

	tok1, exp, err := m.CreateSession("u1", "1.1.1.1")
	if err != nil {
		t.Fatal(err)
	}
	if exp.Sub(time.Now()) > time.Hour || exp.Sub(time.Now()) < 40*time.Millisecond {
		t.Fatalf("过期时间异常: %v", exp)
	}
	tok2, _, _ := m.CreateSession("u2", "2.2.2.2")
	if _, _, err := m.Lookup(tok1); err != nil {
		t.Fatalf("有效会话应可用: %v", err)
	}
	// 过期
	time.Sleep(80 * time.Millisecond)
	if _, _, err := m.Lookup(tok1); !errors.Is(err, ErrSessionDead) {
		t.Fatalf("过期会话 err=%v", err)
	}
	// 新会话 + 前缀吊销
	tok3, _, _ := m.CreateSession("u1", "3.3.3.3")
	if n, err := m.RevokeSession(tok3[:8]); err != nil || n != 1 {
		t.Fatalf("前缀吊销 n=%d err=%v", n, err)
	}
	// 踢出 u2(其会话 tok2 仍有效)
	if n, err := m.KickUser("u2"); err != nil || n != 1 {
		t.Fatalf("踢出 n=%d err=%v", n, err)
	}
	if _, _, err := m.Lookup(tok2); !errors.Is(err, ErrSessionDead) {
		t.Fatal("被踢会话应失效")
	}
	// 清理
	m.Sessions.ExpireNow()
	active, _ := m.Sessions.Active()
	if len(active) != 0 {
		t.Fatalf("清理后仍有 %d 个有效会话", len(active))
	}
}

func ptr[T any](v T) *T { return &v }
