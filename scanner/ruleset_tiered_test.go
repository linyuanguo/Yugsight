package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ===== 体积分级加载(任务 2 检查点 4) =====
//
// 策略: 内置基础包 + 高危(critical/high)常驻; 非高危且文件 > 512KB 按需。
// 默认关闭(行为与原实现一致), SetTieredLoad(true) 启用。

const (
	tierSmallHigh = "id: t-high\ninfo:\n  name: h\n  severity: critical\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n"
	tierSmallLow  = "id: t-low\ninfo:\n  name: l\n  severity: low\nrequest:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n"
)

// tierBigLow 大体量低频模板(~1.1MB, 超过默认 512KB 阈值): 用合法的长 tags 列表撑体积
var tierBigLow = buildTierBigLow()

func buildTierBigLow() string {
	var sb strings.Builder
	sb.WriteString("id: t-big\ninfo:\n  name: b\n  severity: low\n  tags:\n")
	for i := 0; i < 60000; i++ {
		fmt.Fprintf(&sb, "    - pad-%07d\n", i)
	}
	sb.WriteString("request:\n  method: GET\n  path: /\nmatchers:\n  - type: status\n    status: [200]\n")
	return sb.String()
}

func writeTieredRules(t *testing.T, rulesDir string) {
	t.Helper()
	httpDir := filepath.Join(rulesDir, "http")
	if err := os.MkdirAll(httpDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"t-high.yaml": tierSmallHigh,
		"t-big.yaml":  tierBigLow,
		"t-low.yaml":  tierSmallLow,
	} {
		if err := os.WriteFile(filepath.Join(httpDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// withTiered 保存/恢复分级加载开关(默认关闭)
func withTiered(t *testing.T) {
	t.Helper()
	oldOn := TieredLoadOn()
	t.Cleanup(func() {
		SetTieredLoad(oldOn)
		SetOnDemandThreshold(0) // 恢复默认 512KB
	})
}

// ruleIDs 收集规则集 ID 集合
func ruleIDs(t *testing.T, rules []Rule) map[string]bool {
	t.Helper()
	m := make(map[string]bool, len(rules))
	for _, r := range rules {
		m[r.ID] = true
	}
	return m
}

// TestRuleTierClassify 纯函数分级判定: 内置/高危常驻, 大体量低频按需
func TestRuleTierClassify(t *testing.T) {
	rulesDir, _ := withDirs(t)
	writeTieredRules(t, rulesDir)
	all, _ := RefreshRules()
	byID := map[string]Rule{}
	for _, r := range all {
		byID[r.ID] = r
	}
	if got := ruleTierOf(byID["t-high"]); got != TierResident {
		t.Errorf("高危模板应常驻, got %s", got)
	}
	if got := ruleTierOf(byID["t-low"]); got != TierResident {
		t.Errorf("小体积低风险模板应常驻(安全默认), got %s", got)
	}
	if got := ruleTierOf(byID["t-big"]); got != TierOnDemand {
		t.Errorf("大体量低频模板应按需, got %s", got)
	}
	// 内置基础包恒常驻
	builtin, _ := LoadBuiltinRules()
	if len(builtin) == 0 {
		t.Fatal("应有内置基础包")
	}
	if got := ruleTierOf(builtin[0]); got != TierResident {
		t.Errorf("内置基础包应常驻, got %s", got)
	}
	// 无 severity 信息的小模板: 安全默认常驻
	if got := ruleTierOf(Rule{ID: "x", Path: byID["t-low"].Path}); got != TierResident {
		t.Errorf("无 severity 模板应常驻, got %s", got)
	}
}

// TestTieredDefaultOff 默认关闭: 全量常驻, 行为与原实现一致
func TestTieredDefaultOff(t *testing.T) {
	rulesDir, _ := withDirs(t)
	writeTieredRules(t, rulesDir)
	withTiered(t)
	SetTieredLoad(false)

	rules, _ := RefreshRules()
	m := ruleIDs(t, rules)
	for _, id := range []string{"t-high", "t-big", "t-low"} {
		if !m[id] {
			t.Errorf("默认关闭时 %s 应在规则集中", id)
		}
	}
	st := TieredStats()
	if st.Enabled || st.OnDemandCount != 0 || st.LoadedCount != 0 {
		t.Errorf("默认关闭时分级统计应为空: %+v", st)
	}
	// LoadOnDemand 在关闭时应明确提示而非静默
	if n, warns := LoadOnDemand([]string{"t-big"}); n != 0 || len(warns) != 1 {
		t.Errorf("关闭时 LoadOnDemand 应返回提示: n=%d warns=%v", n, warns)
	}
}

// TestTieredSplitLoadRelease 开启: 大体量模板剔除出常驻集 -> 按需加载 -> 扫描结束释放
func TestTieredSplitLoadRelease(t *testing.T) {
	rulesDir, _ := withDirs(t)
	writeTieredRules(t, rulesDir)
	withTiered(t)
	SetTieredLoad(true)

	rules, _ := RefreshRules()
	m := ruleIDs(t, rules)
	if !m["t-high"] || !m["t-low"] {
		t.Error("高危/小风险模板应常驻")
	}
	if m["t-big"] {
		t.Error("大体量低频模板应被剔除出常驻集")
	}

	st := TieredStats()
	if !st.Enabled || st.OnDemandCount != 1 || st.OnDemandBytes <= 512<<10 {
		t.Errorf("分级统计错误: %+v", st)
	}
	if st.ResidentCount == 0 {
		t.Error("常驻集不应为空")
	}
	// 总数口径: 常驻 + 按需
	if got := RuleCount(); got != st.ResidentCount+st.OnDemandCount {
		t.Errorf("RuleCount 应含按需模板: got=%d want=%d", got, st.ResidentCount+st.OnDemandCount)
	}

	// 按需加载: 显式 API(模拟扫描开始按计划加载)
	n, warns := LoadOnDemand([]string{"t-big", "no-such-id"})
	if n != 1 || len(warns) != 1 || !strings.Contains(warns[0], "no-such-id") {
		t.Errorf("LoadOnDemand 错误: n=%d warns=%v", n, warns)
	}
	eff, _ := Rules()
	m2 := ruleIDs(t, eff)
	if !m2["t-big"] {
		t.Error("按需加载后 t-big 应出现在有效规则集")
	}
	if TieredStats().LoadedCount != 1 {
		t.Errorf("工作集应加载 1 条, got %+v", TieredStats())
	}

	// 懒加载路径: 释放后经 GetRuleByID 自动重新加载
	ReleaseOnDemand()
	if TieredStats().LoadedCount != 0 {
		t.Error("释放后工作集应为空")
	}
	if r, ok := GetRuleByID("t-big"); !ok || r.Info == nil || r.Info.Severity != "low" {
		t.Errorf("GetRuleByID 应自动懒加载按需模板: ok=%v", ok)
	}
	if TieredStats().LoadedCount != 1 {
		t.Error("懒加载后工作集应为 1")
	}

	// 扫描结束释放: 有效规则集缩回常驻集
	if n := ReleaseOnDemand(); n != 1 {
		t.Errorf("释放应返回 1, got %d", n)
	}
	eff2, _ := Rules()
	for _, r := range eff2 {
		if r.ID == "t-big" {
			t.Error("释放后 t-big 不应再在有效规则集")
		}
	}
}

// TestTieredIdleAutoRelease 闲置超时自动释放(兜底, 防调用方漏调)
func TestTieredIdleAutoRelease(t *testing.T) {
	rulesDir, _ := withDirs(t)
	writeTieredRules(t, rulesDir)
	withTiered(t)
	SetTieredLoad(true)
	RefreshRules()
	LoadOnDemand([]string{"t-big"})

	oldIdle := onDemandIdle
	onDemandIdle = time.Minute
	t.Cleanup(func() { onDemandIdle = oldIdle })

	// 未闲置: 不释放
	if checkIdleRelease(time.Now()) {
		t.Error("刚访问过的工作集不应释放")
	}
	// 模拟闲置 11 分钟
	tierMu.Lock()
	lastUsed = time.Now().Add(-11 * time.Minute)
	tierMu.Unlock()
	if !checkIdleRelease(time.Now()) {
		t.Error("闲置超时应自动释放")
	}
	if TieredStats().LoadedCount != 0 {
		t.Error("自动释放后工作集应为空")
	}
	// 空工作集: 幂等
	if checkIdleRelease(time.Now()) {
		t.Error("空工作集不应再释放")
	}
}
