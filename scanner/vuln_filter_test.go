package scanner

import (
	"regexp"
	"testing"
)

// testFilterRules 构造一套覆盖 body/header/path 三类的测试规则(re 直接编译, 不依赖磁盘),
// 专用于验证"按 ID 集合过滤"的逻辑。
func testFilterRules() []VulnRule {
	return []VulnRule{
		{ID: "T-BODY-1", Name: "Body A", Severity: "high", Type: "body", Pattern: "SECRET_KEY", Detail: "a", Scope: ScopeWeb, re: regexp.MustCompile(`SECRET_KEY`)},
		{ID: "T-BODY-2", Name: "Body B", Severity: "low", Type: "body", Pattern: "DEBUG_MODE", Detail: "b", Scope: ScopeWeb, re: regexp.MustCompile(`DEBUG_MODE`)},
		{ID: "T-HEADER-1", Name: "Header", Severity: "medium", Type: "header", Pattern: "X-Leak: 1", Detail: "c", Scope: ScopeWeb, re: regexp.MustCompile(`X-Leak: 1`)},
		{ID: "T-PATH-1", Name: "Path A", Severity: "high", Type: "path", Pattern: "/secret.bak", Detail: "d", Scope: ScopeWeb},
		{ID: "T-PATH-2", Name: "Path B", Severity: "medium", Type: "path", Pattern: "/.env.bak", Detail: "e", Scope: ScopeWeb},
	}
}

// withRules 临时替换全局 vulnRules(持写锁, 清理时还原), 供离线测试过滤逻辑。
// 用锁读写是为与线上 AddLock 口径一致, 即便将来有并发测试也不产生数据竞争。
func withRules(t *testing.T, rules []VulnRule) {
	t.Helper()
	vulnMu.Lock()
	old := vulnRules
	vulnRules = rules
	vulnMu.Unlock()
	t.Cleanup(func() {
		vulnMu.Lock()
		vulnRules = old
		vulnMu.Unlock()
	})
}

// TestMatchRulesFiltered 守卫"规则选择"契约: sel 只放行集合内规则, nil 放行全部,
// 空集放行 0 条。若过滤判定被改坏(如漏掉 sel 检查), 用户在 Web 扫描页禁用某规则后
// 它仍会命中 —— 属"改坏就静默失效"的契约, 必须锁定。
func TestMatchRulesFiltered(t *testing.T) {
	withRules(t, testFilterRules())
	body := "SECRET_KEY=1 and DEBUG_MODE on"
	header := "X-Leak: 1\nContent-Type: text/html\n"

	if hits := MatchRulesFiltered(body, header, nil); len(hits) != 3 {
		t.Fatalf("nil 过滤应命中全部 3 条(body 2 + header 1), 实际 %d: %+v", len(hits), hits)
	}
	if hits := MatchRulesFiltered(body, header, map[string]bool{"T-BODY-1": true}); len(hits) != 1 || hits[0].ID != "T-BODY-1" {
		t.Fatalf("仅选 T-BODY-1 应命中 1 条, 实际 %d: %+v", len(hits), hits)
	}
	hits := MatchRulesFiltered(body, header, map[string]bool{"T-BODY-2": true, "T-HEADER-1": true})
	if len(hits) != 2 {
		t.Fatalf("选 T-BODY-2 + T-HEADER-1 应命中 2 条, 实际 %d: %+v", len(hits), hits)
	}
	if hits := MatchRulesFiltered(body, header, map[string]bool{}); len(hits) != 0 {
		t.Fatalf("空集应命中 0 条, 实际 %d: %+v", len(hits), hits)
	}
}

// TestPathRulesFiltered 同理守卫 path 规则的选择过滤(nil 全量 / 子集 / 空集)。
func TestPathRulesFiltered(t *testing.T) {
	withRules(t, testFilterRules())
	if got := len(PathRulesFiltered(nil)); got != 2 {
		t.Fatalf("nil 应返回 2 条 path 规则, 实际 %d", got)
	}
	got := PathRulesFiltered(map[string]bool{"T-PATH-2": true})
	if len(got) != 1 || got[0].desc != "[T-PATH-2] Path B" {
		t.Fatalf("仅选 T-PATH-2 应返回 1 条且描述带 [ID] 名称, 实际 %+v", got)
	}
	if got := len(PathRulesFiltered(map[string]bool{})); got != 0 {
		t.Fatalf("空集应返回 0 条, 实际 %d", got)
	}
}
