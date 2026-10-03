package weakpass

import (
	"encoding/json"
	"testing"
)

// TestResultJSONKeys 守 Result 的 JSON 键名契约(前端按小写驼峰读取)。
//
// 回归背景(2026-09-25): 漏写 json tag 时 Go 按字段名原样输出 "OK"/"Password",
// Weakpass.vue 与报告中心原始报告详情读 r.ok 恒为 undefined → 命中行全部显示
// "未命中", 而摘要计数(后端算)仍正确, 形成"1 个命中但明细全未命中"的矛盾,
// 属"改坏会静默失效"的契约, 用单测钉住。
func TestResultJSONKeys(t *testing.T) {
	r := Result{
		Target:    Target{Host: "10.0.0.1", Port: 23, Service: "telnet"},
		OK:        true,
		Password:  "123456",
		EmptyPass: true,
		Attempts:  3,
		Stopped:   "found",
	}
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	want := map[string]any{
		"host": "10.0.0.1", "port": float64(23), "service": "telnet",
		"ok": true, "password": "123456", "emptyPass": true,
		"attempts": float64(3), "stopped": "found",
	}
	for k, v := range want {
		got, ok := m[k]
		if !ok {
			t.Fatalf("缺少小写驼峰键 %q(前端按该键读取): %s", k, b)
		}
		if got != v {
			t.Fatalf("键 %q 值不符: 期望 %v, 实际 %v", k, v, got)
		}
	}
	// 大写键必须消失(存在即说明 tag 又被删了)
	for _, k := range []string{"OK", "Password", "EmptyPass", "Attempts", "Stopped", "Unsupported", "Error"} {
		if _, ok := m[k]; ok {
			t.Fatalf("出现大写键 %q: %s", k, b)
		}
	}
}
