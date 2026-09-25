package scanner

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestDefaultScopeForType 适用范围按匹配方式推导: body/header/path 均属 Web 面。
// 这条推导是"外部规则文件不补 scope 也能正常归位"的基础, 必须稳定。
func TestDefaultScopeForType(t *testing.T) {
	cases := []struct {
		typ  string
		want string
	}{
		{"body", ScopeWeb},
		{"header", ScopeWeb},
		{"path", ScopeWeb},
		// 未知 type 不是合法规则(LoadVulnLibrary 会拒绝), 推导值仅作兜底, 取 Web
		{"unknown-type", ScopeWeb},
		{"", ScopeWeb},
	}
	for _, c := range cases {
		if got := DefaultScopeForType(c.typ); got != c.want {
			t.Errorf("DefaultScopeForType(%q)=%q, want %q", c.typ, got, c.want)
		}
	}
}

// TestEffectivescope 已声明 scope 优先(含大小写/空白容错), 未声明按 type 推导。
func TestEffectiveScope(t *testing.T) {
	cases := []struct {
		name string
		rule VulnRule
		want string
	}{
		{"未声明 + body -> web", VulnRule{Type: "body"}, ScopeWeb},
		{"未声明 + path -> web", VulnRule{Type: "path"}, ScopeWeb},
		{"显式 host 覆盖推导", VulnRule{Type: "body", Scope: "host"}, ScopeHost},
		{"显式 web", VulnRule{Type: "body", Scope: "web"}, ScopeWeb},
		{"大写 HOST 容错", VulnRule{Type: "body", Scope: "HOST"}, ScopeHost},
		{"前后空白容错", VulnRule{Type: "body", Scope: "  web  "}, ScopeWeb},
		{"非法值回落推导", VulnRule{Type: "body", Scope: "wang"}, ScopeWeb},
		{"非法值 + header 仍推 web", VulnRule{Type: "header", Scope: "x"}, ScopeWeb},
	}
	for _, c := range cases {
		if got := c.rule.EffectiveScope(); got != c.want {
			t.Errorf("%s: EffectiveScope()=%q, want %q", c.name, got, c.want)
		}
	}
}

// TestLoadVulnLibraryScopeNormalized 内置规则加载后 scope 必须已归一化为非空明确值。
// 前端表格直接渲染该字段, 出现空串会显示成空单元格, 属可感知的展示缺陷。
func TestLoadVulnLibraryScopeNormalized(t *testing.T) {
	if n, errs := LoadVulnLibrary(); n == 0 {
		t.Fatalf("内置漏洞库加载 0 条, errs=%v", errs)
	}
	rules := AllRules()
	if len(rules) == 0 {
		t.Fatal("AllRules() 返回空")
	}
	for _, r := range rules {
		switch r.Scope {
		case ScopeWeb, ScopeHost:
		default:
			t.Errorf("规则 %s 的 scope 未归一化: %q", r.ID, r.Scope)
		}
	}
}

// TestBuiltinRulesHaveExplicitScope 内置 JSON 每条规则都显式带 scope。
// 内置规则随 exe 分发, 显式声明可让用户在界面/文件里直接看到可用取值,
// 而不是面对一个空字段去猜。
func TestBuiltinRulesHaveExplicitScope(t *testing.T) {
	var vf vulnFile
	if err := json.Unmarshal(builtinVulnJSON, &vf); err != nil {
		t.Fatalf("内置规则 JSON 解析失败: %v", err)
	}
	if len(vf.Rules) == 0 {
		t.Fatal("内置规则为空")
	}
	for _, r := range vf.Rules {
		if strings.TrimSpace(r.Scope) == "" {
			t.Errorf("内置规则 %s (%s) 缺少显式 scope 字段", r.ID, r.Name)
		}
	}
}
