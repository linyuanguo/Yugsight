// hotp_test.go HOTP(时间片版)算法单元测试。
//
// 覆盖: 种子生成(熵/格式/可解) / 动态码计算(RFC 4226 官方向量) /
// ±1 时间片容错(含边界拒绝) / 种子归一(小写/空格/填充)。
package main

import (
	"encoding/base32"
	"strings"
	"testing"
	"time"
)

// rfc4226Seed RFC 4226 附录 D 官方测试种子(ASCII "12345678901234567890" 的 base32)。
const rfc4226Seed = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

// TestHotpCodeRFC4226Vectors 官方向量: 计数器 0..9 的 6 位码值必须逐位一致。
// 这是与"前端同算法"约定的锚点 —— 算法一旦偏离, 此处立即失败。
func TestHotpCodeRFC4226Vectors(t *testing.T) {
	want := []string{"755224", "287082", "359152", "969429", "338314",
		"254676", "287922", "162583", "399871", "520489"}
	for counter, code := range want {
		got := hotpCode(rfc4226Seed, uint64(counter))
		if got != code {
			t.Fatalf("counter=%d got=%s want=%s", counter, got, code)
		}
		if len(got) != hotpDigits {
			t.Fatalf("counter=%d 码长=%d, want %d", counter, len(got), hotpDigits)
		}
	}
}

// TestHotpCodeInvalidSeed 非法种子返回空串而非 panic(降级不崩溃)。
func TestHotpCodeInvalidSeed(t *testing.T) {
	for _, bad := range []string{"", "   ", "!!not-base32!!", "abc1"} { // '1' 非法 base32 字符
		if got := hotpCode(bad, 1); got != "" {
			t.Fatalf("非法种子 %q 应返回空串, got %q", bad, got)
		}
	}
}

// TestHotpVerifyWindow ±1 时间片容错: 当前片与前后各一片均通过,
// 更远的片与错误码拒绝。
func TestHotpVerifyWindow(t *testing.T) {
	const n = 5 // counter=5 → 254676
	seed := rfc4226Seed
	code := "254676"

	atCounter := func(c uint64) time.Time { return time.Unix(int64(c)*90, 0) }
	for _, c := range []uint64{4, 5, 6} {
		if !hotpVerify(seed, code, atCounter(c)) {
			t.Fatalf("counter=%d 时应通过 ±1 容错", c)
		}
	}
	for _, c := range []uint64{3, 7} {
		if hotpVerify(seed, code, atCounter(c)) {
			t.Fatalf("counter=%d 超出 ±1 容错, 应拒绝", c)
		}
	}
	if hotpVerify(seed, "000000", atCounter(5)) {
		t.Fatal("错误码应拒绝")
	}
	if hotpVerify("", code, atCounter(5)) {
		t.Fatal("空种子应拒绝")
	}
}

// TestHotpVerifyRealClock 真实时钟下, 按当前时刻计算的码必须立即通过
// (前后端"同一时刻同一种子同码"的核心契约)。
func TestHotpVerifyRealClock(t *testing.T) {
	seed := hotpSeedGenerate()
	if seed == "" {
		t.Fatal("种子生成失败")
	}
	code := hotpCode(seed, hotpCounterAt(time.Now()))
	if !hotpVerify(seed, code, time.Now()) {
		t.Fatalf("实时码 %s 校验失败", code)
	}
}

// TestHotpSeedGenerate 种子: 32 字符 / base32 无填充 / 归一后可解出 20 字节 /
// 两次生成不同(熵)。
func TestHotpSeedGenerate(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 32; i++ {
		s := hotpSeedGenerate()
		if len(s) != 32 {
			t.Fatalf("种子长度=%d, want 32", len(s))
		}
		if strings.ContainsAny(s, "=/+") {
			t.Fatalf("种子含非 base32 标准字符: %q", s)
		}
		if seen[s] {
			t.Fatalf("种子重复: %s", s)
		}
		seen[s] = true
		raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s)
		if err != nil || len(raw) != hotpSeedBytes {
			t.Fatalf("种子不可解: %q err=%v raw=%d", s, err, len(raw))
		}
		if hotpCode(s, 1) == "" {
			t.Fatal("合法种子算码失败")
		}
	}
}

// TestHotpNormalizeSeed 小写/空格/横线/尾部填充的种子应归一为标准形态。
func TestHotpNormalizeSeed(t *testing.T) {
	const upper = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	for in, label := range map[string]string{
		strings.ToLower(upper):          "小写",
		" " + upper + " ":               "空白",
		strings.ToLower(upper) + "====": "尾部填充",
		"GEZD GNBV-GY3T QOJQGEZDGNBVGY3TQOJQ": "混合分隔符",
	} {
		if got := hotpNormalizeSeed(in); got != upper {
			t.Fatalf("%s 归一失败: %q → %q", label, in, got)
		}
	}
}

// TestHotpCounterAndRemain 计数器与剩余秒数口径(前端 JS 需严格一致)。
func TestHotpCounterAndRemain(t *testing.T) {
	t0 := time.Unix(180, 0) // 90*2 整点
	if got := hotpCounterAt(t0); got != 2 {
		t.Fatalf("counter=%d, want 2", got)
	}
	if got := hotpRemainSecAt(t0); got != 90 {
		t.Fatalf("剩余=%d, want 90", got)
	}
	t1 := time.Unix(243, 0) // 180+63
	if got := hotpRemainSecAt(t1); got != 27 {
		t.Fatalf("剩余=%d, want 27", got)
	}
}
