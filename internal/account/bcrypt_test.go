package account

import (
	"strings"
	"testing"
)

// bcryptjs 参考向量(开发期用 node bcryptjs@2.4.3 生成, 固定盐, 见 tmp-verify/gen.js 记录):
//
//	salt10 = $2b$10$WM7BOyrZbq8SMw9ckIanW.
//	hash("password", salt10) = $2b$10$WM7BOyrZbq8SMw9ckIanW.CAdJeS61GCeg4wPt7ScLNXnTqXQ9j1G
//	salt5  = $2b$05$w7Fn1nscsI/4ScBdumacUe
//	hash("test", salt5)      = $2b$05$w7Fn1nscsI/4ScBdumacUeoYVy8KKC01UmdZI0whB3D/S4dj/RP8y
//	hash("",      salt5)     = $2b$05$w7Fn1nscsI/4ScBdumacUeT1eTrgyJT54SEQR1wFGEKYHxSSWbT5q
//	salt4  = $2b$04$poLgzinlfyuMrOqvISfMn.
//	hash("a",     salt4)     = $2b$04$poLgzinlfyuMrOqvISfMn.HCMgz/wuxQmTrPmdTzJ3BiN0.XZQPb2
//	hash("密码x",  salt4)     = $2b$04$poLgzinlfyuMrOqvISfMn.qU8bODkHztMtaa2h0gjRki6RV62ArSu
//	hash(72xA,    salt4) == hash(72xA+"B", salt4)  (72 字节截断)
func TestBcryptReferenceVectors(t *testing.T) {
	fixed := func(salt, pass string, want string) {
		t.Helper()
		// 用固定盐复算: 截取 salt 部分 + 直接跑核心
		if err := verifyFixed(salt, pass, want); err != nil {
			t.Fatalf("pass=%q: %v", pass, err)
		}
	}
	fixed("WM7BOyrZbq8SMw9ckIanW.", "password", "CAdJeS61GCeg4wPt7ScLNXnTqXQ9j1G")
	fixed("w7Fn1nscsI/4ScBdumacUe", "test", "oYVy8KKC01UmdZI0whB3D/S4dj/RP8y")
	fixed("w7Fn1nscsI/4ScBdumacUe", "", "T1eTrgyJT54SEQR1wFGEKYHxSSWbT5q")
	fixed("poLgzinlfyuMrOqvISfMn.", "a", "HCMgz/wuxQmTrPmdTzJ3BiN0.XZQPb2")
	fixed("poLgzinlfyuMrOqvISfMn.", "密码x", "qU8bODkHztMtaa2h0gjRki6RV62ArSu")
}

// verifyFixed 用固定盐(22 位)与 cost 复算哈希摘要并与参考值比对。
func verifyFixed(salt22, pass, wantDigest31 string) error {
	// 从参考完整哈希反推 cost(此处参考 cost 已知: 按盐前缀映射)
	cost := map[string]int{
		"WM7BOyrZbq8SMw9ckIanW.": 10,
		"w7Fn1nscsI/4ScBdumacUe": 5,
		"poLgzinlfyuMrOqvISfMn.": 4,
	}[salt22]
	salt, err := bcB64.DecodeString(salt22)
	if err != nil || len(salt) != saltLen {
		return err
	}
	key := append([]byte(pass), 0)
	d := bcryptCore(key, cost, salt)
	got := bcB64.EncodeToString(d)
	if got != wantDigest31 {
		return errDigestMismatch{got: got, want: wantDigest31}
	}
	return nil
}

type errDigestMismatch struct{ got, want string }

func (e errDigestMismatch) Error() string { return "摘要不匹配: got=" + e.got + " want=" + e.want }

// TestBcryptRoundTrip 哈希/校验往返 + 格式 + 错密码 + 截断。
func TestBcryptRoundTrip(t *testing.T) {
	h, err := HashPassword("s3cret", 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(h) != 61 || h[:4] != "$2b$" || h[6] != '$' || h[29] != '$' {
		t.Fatalf("格式异常: %s", h)
	}
	if err := CompareHashAndPassword(h, "s3cret"); err != nil {
		t.Fatalf("校验应通过: %v", err)
	}
	if err := CompareHashAndPassword(h, "wrong"); err == nil {
		t.Fatal("错误密码不应通过")
	}
	if err := CompareHashAndPassword("bad", "x"); err == nil {
		t.Fatal("非法哈希应报错")
	}
	// 72 字节截断: 73 位与 72 位同摘要
	a, _ := HashPassword(strings.Repeat("A", 72), 4)
	_ = a
	p72 := strings.Repeat("A", 72)
	h1, _ := HashPassword(p72, 4)
	if CompareHashAndPassword(h1, p72+"B") != nil {
		t.Fatal("73 位密码应等价于前 72 位")
	}
	// $2a$ 前缀兼容
	if err := CompareHashAndPassword(strings.Replace(h1, "$2b$", "$2a$", 1), p72); err != nil {
		t.Fatalf("$2a$ 应兼容: %v", err)
	}
	// cost 非法
	if _, err := HashPassword("x", 3); err == nil {
		t.Fatal("cost=3 应报错")
	}
	c, err := CostOf(h1)
	if err != nil || c != 4 {
		t.Fatalf("CostOf=%d,%v", c, err)
	}
}
