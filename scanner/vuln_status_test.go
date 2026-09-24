package scanner

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPendingRuleExcludedFromScan 守卫"验证状态"契约: 待验证规则不参与 body/header 匹配
// (避免未验证规则产生误报), 已验证与空状态(老文件)规则照常参与。若 IsActive 判定被改坏
// (如漏掉 pending 检查), 未验证规则会悄悄进入扫描结果 —— 属"改坏就静默失效"的契约。
func TestPendingRuleExcludedFromScan(t *testing.T) {
	withRules(t, []VulnRule{
		{ID: "V-ACTIVE", Name: "A", Severity: "high", Type: "body", Pattern: "LEAK_A", Scope: ScopeWeb, Status: RuleStatusVerified, re: regexp.MustCompile(`LEAK_A`)},
		{ID: "V-EMPTY", Name: "E", Severity: "low", Type: "body", Pattern: "LEAK_E", Scope: ScopeWeb, re: regexp.MustCompile(`LEAK_E`)},
		{ID: "V-PENDING", Name: "P", Severity: "high", Type: "body", Pattern: "LEAK_P", Scope: ScopeWeb, Status: RuleStatusPending, re: regexp.MustCompile(`LEAK_P`)},
	})
	body := "LEAK_A x LEAK_E y LEAK_P z"

	hits := MatchRulesFiltered(body, "", nil)
	got := map[string]bool{}
	for _, h := range hits {
		got[h.ID] = true
	}
	if !got["V-ACTIVE"] || !got["V-EMPTY"] {
		t.Fatalf("已验证/空状态规则应参与匹配, 实际命中 %+v", got)
	}
	if got["V-PENDING"] {
		t.Fatalf("待验证规则不应参与扫描, 却命中了 V-PENDING: %+v", got)
	}
	if len(hits) != 2 {
		t.Fatalf("应命中 2 条, 实际 %d: %+v", len(hits), hits)
	}
}

// TestPendingPathExcluded 同理: 待验证 path 规则不进入敏感路径探测目标。
func TestPendingPathExcluded(t *testing.T) {
	withRules(t, []VulnRule{
		{ID: "P-OK", Name: "ok", Severity: "high", Type: "path", Pattern: "/ok", Scope: ScopeWeb, Status: RuleStatusVerified},
		{ID: "P-PEND", Name: "pend", Severity: "high", Type: "path", Pattern: "/pend", Scope: ScopeWeb, Status: RuleStatusPending},
	})
	if got := len(PathRulesFiltered(nil)); got != 1 {
		t.Fatalf("待验证 path 应被排除, 应剩 1 条, 实际 %d", got)
	}
}

// TestIsActiveContract 直接锁 IsActive / EffectiveStatus 的语义(空=活跃, pending=不活跃,
// verified=活跃), 避免上层过滤逻辑与状态语义漂移。
func TestIsActiveContract(t *testing.T) {
	cases := []struct {
		status string
		active bool
	}{
		{"", true},
		{RuleStatusVerified, true},
		{RuleStatusPending, false},
	}
	for _, c := range cases {
		r := VulnRule{Status: c.status}
		if r.IsActive() != c.active {
			t.Errorf("IsActive(%q) = %v, 期望 %v", c.status, r.IsActive(), c.active)
		}
	}
	if (VulnRule{Status: RuleStatusPending}).EffectiveStatus() != RuleStatusPending {
		t.Error("pending 的 EffectiveStatus 应为 pending")
	}
	if (VulnRule{Status: ""}).EffectiveStatus() != RuleStatusVerified {
		t.Error("空状态 EffectiveStatus 应为 verified(向后兼容)")
	}
}

// TestRuleSeverityStats 守卫等级统计口径: 未知值归 info, 大小写容错。
func TestRuleSeverityStats(t *testing.T) {
	withRules(t, []VulnRule{
		{Severity: "critical"},
		{Severity: "HIGH"},
		{Severity: "medium"},
		{Severity: "low"},
		{Severity: "weird"},
	})
	stats := RuleSeverityStats()
	want := map[string]int{"critical": 1, "high": 1, "medium": 1, "low": 1, "info": 1}
	for k, v := range want {
		if stats[k] != v {
			t.Fatalf("等级统计 %s = %d, 期望 %d (全部: %+v)", k, stats[k], v, stats)
		}
	}
}

// TestMarkRulesVerifiedRoundTrip 守卫"已验证集"文件契约: 幂等去重 + 读写往返一致。
// 测试二进制位于临时目录, VulnerableDir() 指向临时 vuln/, 不污染真实部署目录。
func TestMarkRulesVerifiedRoundTrip(t *testing.T) {
	added, err := MarkRulesVerified([]string{"RULE-X", "RULE-X", "RULE-Y"})
	if err != nil {
		t.Fatalf("MarkRulesVerified 出错: %v", err)
	}
	if added != 2 {
		t.Fatalf("去重后应新增 2 个, 实际 %d", added)
	}
	set := loadVerifiedSet()
	if !set["RULE-X"] || !set["RULE-Y"] {
		t.Fatalf("已验证集应含 RULE-X/RULE-Y, 实际 %+v", set)
	}
	// 重复标记不新增(幂等)
	added2, _ := MarkRulesVerified([]string{"RULE-X"})
	if added2 != 0 {
		t.Fatalf("重复标记应新增 0, 实际 %d", added2)
	}
}

// TestImportEffectiveByDefault 守卫"导入即生效"口径(2026-09-22 用户确认的行为变更):
// 导入规则未声明 status 时默认已验证, 热重载后立即参与扫描, 落盘文件显式写明
// verified; 导入内容显式声明 status=pending 时尊重显式意图, 保持待验证不参与扫描。
// 若默认值被改回 pending, 用户导入的规则会全部静默失效 —— 属"改坏就静默失效"的
// 契约, 必须锁定。
func TestImportEffectiveByDefault(t *testing.T) {
	vulnMu.Lock()
	old := vulnRules
	vulnMu.Unlock()
	// 清理导入落盘的测试文件并恢复全局规则集, 避免污染同进程后续用例
	t.Cleanup(func() {
		os.Remove(filepath.Join(VulnerableDir(), "test_imp_default.json"))
		os.Remove(filepath.Join(VulnerableDir(), "test_imp_pending.json"))
		vulnMu.Lock()
		vulnRules = old
		vulnMu.Unlock()
	})

	n, warns, err := ImportVulnRules(
		`{"rules":[{"id":"IMP-DEF-1","name":"默认生效","severity":"high","type":"body","pattern":"IMPDEF1"}]}`,
		"test_imp_default.json")
	if err != nil {
		t.Fatalf("导入(未声明状态)失败: %v (告警 %v)", err, warns)
	}
	if n != 1 {
		t.Fatalf("应导入 1 条, 实际 %d", n)
	}
	if _, warns, err := ImportVulnRules(
		`{"rules":[{"id":"IMP-PND-1","name":"显式暂存","severity":"high","type":"body","pattern":"IMPPND1","status":"pending"}]}`,
		"test_imp_pending.json"); err != nil {
		t.Fatalf("导入(显式 pending)失败: %v (告警 %v)", err, warns)
	}

	byID := map[string]VulnRule{}
	for _, r := range AllRules() {
		byID[r.ID] = r
	}
	d, ok := byID["IMP-DEF-1"]
	if !ok || !d.IsActive() {
		t.Fatalf("未声明 status 的导入规则应默认已验证并参与扫描, 实际 %+v (存在=%v)", d, ok)
	}
	p, ok := byID["IMP-PND-1"]
	if !ok || p.IsActive() {
		t.Fatalf("显式 pending 的导入规则应保持待验证(不参与扫描), 实际 %+v (存在=%v)", p, ok)
	}

	hits := MatchRulesFiltered("IMPDEF1 x IMPPND1", "", nil)
	got := map[string]bool{}
	for _, h := range hits {
		got[h.ID] = true
	}
	if !got["IMP-DEF-1"] {
		t.Fatalf("默认已验证规则应参与匹配: %+v", got)
	}
	if got["IMP-PND-1"] {
		t.Fatalf("待验证规则不应参与匹配: %+v", got)
	}

	data, rerr := os.ReadFile(filepath.Join(VulnerableDir(), "test_imp_default.json"))
	if rerr != nil {
		t.Fatalf("读取导入文件失败: %v", rerr)
	}
	if !strings.Contains(string(data), `"status": "verified"`) {
		t.Fatalf("导入文件应显式写明 status=verified(导入即生效), 实际内容: %s", data)
	}
}
