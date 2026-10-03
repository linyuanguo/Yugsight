package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDecodeBodiesTolerateDoubleEncoded 守契约: 前端历史 bug 会把已序列化的 body 再
// 序列化一次, 服务端收到的是 JSON 字符串字面量(外层多包一层引号)。decodeJSON /
// decodeAIBody 必须解开内层再解析, 否则"保存"会静默 400 —— 报告/AI 配置三处都踩过。
func TestDecodeBodiesTolerateDoubleEncoded(t *testing.T) {
	type req struct {
		Modules map[string]bool `json:"modules"`
		Name    string          `json:"name"`
	}
	once := `{"modules":{"scan":true},"name":"x"}`            // 单次序列化(正常)
	twice := `"{\"modules\":{\"scan\":true},\"name\":\"x\"}"` // 二次序列化(历史 bug)

	for name, raw := range map[string]string{"single": once, "double": twice} {
		t.Run(name, func(t *testing.T) {
			newReq := func() *http.Request {
				return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(raw))
			}
			var v req
			if !decodeJSON(httptest.NewRecorder(), newReq(), &v) {
				t.Fatalf("decodeJSON 拒绝 body %s", raw)
			}
			if v.Name != "x" || !v.Modules["scan"] {
				t.Fatalf("decodeJSON 解析错误: %+v", v)
			}

			var v2 req
			if err := decodeAIBody(newReq(), &v2); err != nil {
				t.Fatalf("decodeAIBody 拒绝 body %s: %v", raw, err)
			}
			if v2.Name != "x" || !v2.Modules["scan"] {
				t.Fatalf("decodeAIBody 解析错误: %+v", v2)
			}
		})
	}
}

// TestDecodeBodiesRejectGarbage 守契约: 真垃圾(非 JSON)仍要拒绝, 兜底不能吞掉真错误。
func TestDecodeBodiesRejectGarbage(t *testing.T) {
	newReq := func(s string) *http.Request {
		return httptest.NewRequest(http.MethodPost, "/", strings.NewReader(s))
	}
	var v struct{ A string `json:"a"` }
	if decodeJSON(httptest.NewRecorder(), newReq("not json at all"), &v) {
		t.Fatal("decodeJSON 应拒绝非法 body")
	}
	if err := decodeAIBody(newReq("not json at all"), &v); err == nil {
		t.Fatal("decodeAIBody 应拒绝非法 body")
	}
	// 字符串字面量但内层不是 JSON: 也要拒绝
	var v2 struct{ A string `json:"a"` }
	if err := decodeAIBody(newReq(`"plain string"`), &v2); err == nil {
		t.Fatal("decodeAIBody 应拒绝内层非 JSON 的字符串字面量")
	}
}
