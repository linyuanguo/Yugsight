package scanner

import "testing"

func TestIntelBuiltin(t *testing.T) {
	n, m := RefreshIntel()
	if n == 0 {
		t.Fatal("内置 KEV 集为空")
	}
	if m == 0 {
		t.Fatal("内置 EPSS 集为空")
	}
	// Log4Shell: KEV + EPSS + 勒索软件标记
	e, ok := IsKEV("CVE-2021-44228")
	if !ok {
		t.Fatal("CVE-2021-44228 应在 KEV 中")
	}
	if e.Product != "Log4j2" || !e.Ransomware || e.DateAdded == "" {
		t.Errorf("KEV 条目字段不完整: %+v", e)
	}
	// CVE 号大小写不敏感
	if _, ok := IsKEV("cve-2021-44228"); !ok {
		t.Error("CVE 号匹配应大小写不敏感")
	}
	// EPSS 分值
	s, ok := EPSSScore("CVE-2021-44228")
	if !ok || s <= 0 || s > 1 {
		t.Errorf("EPSS 分值异常: %v (ok=%v)", s, ok)
	}
	// 未知 CVE 不命中
	if _, ok := IsKEV("CVE-1999-0001"); ok {
		t.Error("未知 CVE 不应命中 KEV")
	}
	if _, ok := EPSSScore("CVE-1999-0001"); ok {
		t.Error("未知 CVE 不应有 EPSS")
	}
	// 列表接口
	if len(KEVList()) != n {
		t.Errorf("KEVList 数量 %d != KEVCount %d", len(KEVList()), n)
	}
	if len(EPSSList()) != m {
		t.Errorf("EPSSList 数量 %d != RefreshIntel %d", len(EPSSList()), m)
	}
	if IntelVersion() == "" {
		t.Error("情报集版本应为空")
	}
}

func mkTestRule(id, sev string, cves ...string) Rule {
	r := Rule{ID: id}
	r.Info = &Info{Severity: sev}
	if len(cves) > 0 {
		r.Info.Cves = stringOrList(cves)
	}
	return r
}

func TestPrioritizeRulesOrder(t *testing.T) {
	RefreshIntel()
	rules := []Rule{
		mkTestRule("a", "high"),
		mkTestRule("b", "high", "CVE-2021-44228"),        // KEV + 高 EPSS
		mkTestRule("c", "medium", "CVE-2019-0708"),       // KEV + 较低 EPSS
		mkTestRule("d", "critical"),
		mkTestRule("e", "medium", "CVE-1999-0001"),       // 无情报
	}
	in := make([]Rule, len(rules))
	copy(in, rules)
	out := PrioritizeRules(rules)
	if len(out) != len(rules) {
		t.Fatalf("排序后数量 %d != %d", len(out), len(rules))
	}
	want := []string{"b", "c", "d", "a", "e"}
	for i, id := range want {
		if out[i].ID != id {
			t.Fatalf("第 %d 位应为 %s, 实际 %s (整列: %v)", i+1, id, out[i].ID, out)
		}
	}
	// 入参不被修改
	for i := range in {
		if rules[i].ID != in[i].ID {
			t.Fatal("入参列表被修改")
		}
	}
	// nil / 空 / 单元素
	if PrioritizeRules(nil) != nil {
		t.Error("nil 应返回 nil")
	}
	if len(PrioritizeRules(rules[:1])) != 1 {
		t.Error("单元素列表应原样返回")
	}
}

func TestRulePriorityInfo(t *testing.T) {
	RefreshIntel()
	r := mkTestRule("x", "high", "CVE-2021-44228", "CVE-2019-0708")
	pi := RulePriorityInfoOf(&r)
	if !pi.KEV || pi.KEVCVE != "CVE-2021-44228" {
		t.Errorf("应命中 KEV 且取高 EPSS 的 CVE: %+v", pi)
	}
	if pi.EPSS != 0.9758 {
		t.Errorf("EPSS 应取最大值 0.9758, 实际 %v", pi.EPSS)
	}
	if pi.Severity != "high" {
		t.Errorf("Severity 应为 high, 实际 %v", pi.Severity)
	}
	// 无 CVE 的模板
	r2 := mkTestRule("y", "critical")
	pi2 := RulePriorityInfoOf(&r2)
	if pi2.KEV || pi2.EPSS != 0 {
		t.Errorf("无 CVE 模板不应有 KEV/EPSS: %+v", pi2)
	}
	// nil 安全
	if (RulePriorityInfoOf(nil)).KEV {
		t.Error("nil 模板应安全返回")
	}
}
