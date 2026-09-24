package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ===== 测试辅助 =====

// httpTpl 生成最小可用的 http 模板 YAML
func httpTpl(id, sev, tag string) string {
	return "id: " + id +
		"\ninfo:\n  name: " + id +
		"\n  severity: " + sev +
		"\n  tags: " + tag +
		"\nrequest:\n  method: GET\n  path: /\n" +
		"matchers:\n  - type: status\n    status: [200]\n"
}

// writeRulesTree 构造测试用 rules/ 目录结构(官方 + 自定义 + 干扰文件)
//
//	rules/
//	  off1.yaml      (official, high, nginx)
//	  off2.yaml      (official, medium, apache)
//	  head.yaml      (headless, 应跳过并记录原因)
//	  js.yaml        (javascript, 应跳过并记录原因)
//	  net.yaml       (network, 应跳过并记录原因)
//	  nohttp.yaml    (无 request/requests, 应跳过并记录原因)
//	  bad.yaml       (坏 YAML, 记解析错误)
//	  custom/
//	    off1.yaml    (custom, 与官方同 ID, 应覆盖官方; critical)
//	    own.yaml     (custom, low, tomcat)
func writeRulesTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite := func(rel, content string) {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("off1.yaml", httpTpl("off-1", "high", "nginx"))
	mustWrite("off2.yaml", httpTpl("off-2", "medium", "apache"))
	mustWrite("head.yaml", "id: h1\ninfo:\n  name: h\n  severity: high\nheadless:\n  steps: []\n")
	mustWrite("js.yaml", "id: j1\ninfo:\n  name: j\n  severity: high\njavascript:\n  code: \"1\"\n")
	mustWrite("net.yaml", "id: n1\ninfo:\n  name: n\n  severity: high\nnetwork:\n  ports: [80]\n")
	mustWrite("nohttp.yaml", "id: nh1\ninfo:\n  name: nh\n  severity: info\ndsl: true\n")
	mustWrite("bad.yaml", "{{{ not valid yaml")
	mustWrite("custom/off1.yaml", httpTpl("off-1", "critical", "nginx"))
	mustWrite("custom/own.yaml", httpTpl("own-1", "low", "tomcat"))
	return dir
}

// withRulesDir 切换测试规则目录并清理缓存
func withRulesDir(t *testing.T, dir string) {
	t.Helper()
	old := rulesExternalDir
	rulesExternalDir = dir
	t.Cleanup(func() {
		rulesExternalDir = old
		rulesMu.Lock()
		extLoaded = false
		rulesMu.Unlock()
	})
}

// idOf 判断规则列表中是否含指定 ID
func idOf(rules []Rule, id string) (Rule, bool) {
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return Rule{}, false
}

// ===== 模块1 测试 =====

// TestLoadBuiltinRules 一级内置核心包: embed 编译进 exe, 与内置模板目录一致
func TestLoadBuiltinRules(t *testing.T) {
	rules, errs := LoadBuiltinRules()
	if len(rules) != 5 {
		t.Fatalf("内置核心包应有 5 条模板, got %d (errs=%v)", len(rules), errs)
	}
	for _, r := range rules {
		if r.ID == "" {
			t.Errorf("内置规则缺少 ID: %+v", r)
		}
		if !r.Builtin {
			t.Errorf("内置规则 Builtin 应为 true: %s", r.ID)
		}
		if r.SHA256 == "" {
			t.Errorf("内置规则应有 SHA256: %s", r.ID)
		}
	}
	if _, ok := idOf(rules, "yugsight-nginx-default-page"); !ok {
		t.Error("内置包应包含 yugsight-nginx-default-page")
	}
}

// TestLoadExternalRules 二级/三级加载: 类型过滤记录原因、同 ID 自定义覆盖官方
func TestLoadExternalRules(t *testing.T) {
	withRulesDir(t, writeRulesTree(t))

	rules, warns := LoadExternalRules()
	joined := strings.Join(warns, "\n")

	// 4 个应跳过的文件, 原因全部记录, 不中断加载
	for _, kw := range []string{"head.yaml", "js.yaml", "net.yaml", "nohttp.yaml"} {
		if !strings.Contains(joined, kw) {
			t.Errorf("跳过原因应记录 %s: %s", kw, joined)
		}
	}
	if !strings.Contains(joined, "bad.yaml") {
		t.Errorf("坏文件应记录解析错误: %s", joined)
	}
	if !strings.Contains(joined, "headless") || !strings.Contains(joined, "javascript") || !strings.Contains(joined, "network") {
		t.Errorf("跳过原因应注明模板类型: %s", joined)
	}

	// 官方 2 + 自定义 2, 同 ID off-1 去重(自定义胜出) => 3 条
	if len(rules) != 3 {
		t.Fatalf("外部规则应 3 条(去重后), got %d: %v", len(rules), joined)
	}
	r, ok := idOf(rules, "off-1")
	if !ok {
		t.Fatal("off-1 应存在")
	}
	if r.Info == nil || r.Info.Severity != "critical" {
		t.Errorf("off-1 应被自定义包覆盖(critical), got %+v", r.Info)
	}
	if _, ok := idOf(rules, "own-1"); !ok {
		t.Error("自定义 own-1 应存在")
	}

	// 三级合并: 内置 5 + 外部 3 = 8
	merged, _ := RefreshRules()
	if len(merged) != 8 {
		t.Errorf("合并集应 8 条, got %d", len(merged))
	}
	if RuleTier("off-1") != RuleTierCustom {
		t.Errorf("off-1 最终层级应为 custom, got %s", RuleTier("off-1"))
	}
	if RuleTier("yugsight-git-exposed") != RuleTierBuiltin {
		t.Errorf("yugsight-git-exposed 最终层级应为 builtin")
	}
	if RuleTier("off-2") != RuleTierOfficial {
		t.Errorf("off-2 最终层级应为 official")
	}
}

// TestRulesetChecksum checksum.sha256 完整性校验: 通过放行, 失败跳过并告警
func TestRulesetChecksum(t *testing.T) {
	dir := writeRulesTree(t)
	withRulesDir(t, dir)
	// 移除 custom/: 其 off1.yaml 与官方同 ID 同路径基准, 会干扰"官方 off-1 被跳过"的断言
	if err := os.RemoveAll(filepath.Join(dir, "custom")); err != nil {
		t.Fatal(err)
	}

	// 1) 正确校验和: off-1 正常加载
	good := sha256Hex([]byte(httpTpl("off-1", "high", "nginx")))
	if err := os.WriteFile(filepath.Join(dir, "checksum.sha256"), []byte(good+"  off1.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, _ := RefreshRules()
	if _, ok := idOf(rules, "off-1"); !ok {
		t.Error("校验和正确的 off-1 应加载")
	}

	// 2) 错误校验和: off-1 跳过 + 告警
	badSum := strings.Repeat("0", 64)
	if err := os.WriteFile(filepath.Join(dir, "checksum.sha256"), []byte(badSum+"  off1.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rules, warns := RefreshRules()
	if _, ok := idOf(rules, "off-1"); ok {
		t.Error("校验和失败的 off-1 应被跳过")
	}
	if !strings.Contains(strings.Join(warns, "\n"), "off1.yaml") {
		t.Errorf("校验失败应告警: %v", warns)
	}
	// 未登记校验和的文件不受影响
	if _, ok := idOf(rules, "off-2"); !ok {
		t.Error("未登记校验和的 off-2 应正常加载")
	}
}

// TestGetRuleByID 按 ID 查找(内置/自定义/未知)
func TestGetRuleByID(t *testing.T) {
	withRulesDir(t, writeRulesTree(t))

	r, ok := GetRuleByID("yugsight-spring-actuator")
	if !ok || !r.Builtin {
		t.Errorf("内置规则应可查: ok=%v r=%+v", ok, r)
	}
	r, ok = GetRuleByID("own-1")
	if !ok || r.Info == nil || r.Info.Severity != "low" {
		t.Errorf("自定义规则应可查: ok=%v r=%+v", ok, r)
	}
	if _, ok := GetRuleByID("no-such-rule"); ok {
		t.Error("未知 ID 应返回 false")
	}
}

// TestFilterRulesBySeverity 按严重级别筛选(不区分大小写 / 多值 / 空条件)
func TestFilterRulesBySeverity(t *testing.T) {
	withRulesDir(t, writeRulesTree(t))
	rules, _ := RefreshRules()

	high := FilterRulesBySeverity(rules, "high")
	if len(high) == 0 {
		t.Fatal("应存在 high 规则")
	}
	for _, r := range high {
		if r.Info == nil || !strings.EqualFold(r.Info.Severity, "high") {
			t.Errorf("筛选结果应全部为 high: %+v", r.Info)
		}
	}

	// 大小写 + 多值
	got := FilterRulesBySeverity(rules, "HIGH", "info")
	sevs := map[string]bool{}
	for _, r := range got {
		sevs[strings.ToLower(r.Info.Severity)] = true
	}
	if !sevs["high"] || !sevs["info"] || len(got) == 0 {
		t.Errorf("多值大小写筛选错误: %v", sevs)
	}

	// 空条件 = 不过滤
	if len(FilterRulesBySeverity(rules)) != len(rules) {
		t.Error("空条件应原样返回")
	}
}

// TestFilterRulesByFingerprint 按服务指纹筛选(产品标签 + 通用规则)
func TestFilterRulesByFingerprint(t *testing.T) {
	withRulesDir(t, writeRulesTree(t))
	rules, _ := RefreshRules()

	ng := FilterRulesByFingerprint(rules, "nginx", "")
	if _, ok := idOf(ng, "yugsight-nginx-default-page"); !ok {
		t.Error("nginx 指纹应保留 nginx 模板")
	}
	if _, ok := idOf(ng, "off-2"); ok {
		t.Error("nginx 指纹不应保留 apache 模板")
	}
	if _, ok := idOf(ng, "own-1"); ok {
		t.Error("nginx 指纹不应保留 tomcat 模板")
	}

	// 筛选器不内置产品归一化(调用方负责, 如 "Apache httpd" -> "apache"), 这里直接传归一化键
	ap := FilterRulesByFingerprint(rules, "apache", "")
	if _, ok := idOf(ap, "off-2"); !ok {
		t.Error("apache 指纹应保留 apache 模板")
	}

	// 通用规则(无产品标签)对任何产品都保留
	generic := FilterRulesByFingerprint(rules, "zzz-unknown", "")
	for _, r := range rules {
		if len(ProductTags(&r)) == 0 {
			if _, ok := idOf(generic, r.ID); !ok {
				t.Errorf("通用规则 %s 应保留", r.ID)
			}
		}
	}
}

// TestProductTags 产品标签提取(通用词不视为产品)
func TestProductTags(t *testing.T) {
	withRulesDir(t, writeRulesTree(t))
	r, ok := GetRuleByID("yugsight-nginx-default-page")
	if !ok {
		t.Fatal("yugsight-nginx-default-page 应存在")
	}
	tags := ProductTags(r)
	if !containsStr(tags, "nginx") {
		t.Errorf("应含 nginx 标签, got %v", tags)
	}
	if containsStr(tags, "misconfig") {
		t.Errorf("通用词 misconfig 不应视为产品标签, got %v", tags)
	}
	if ProductTags(nil) != nil {
		t.Error("nil 规则应返回 nil")
	}
}

// TestRulesStat 统计: 三级计数 + vuln_builtin.json 并行体系
func TestRulesStat(t *testing.T) {
	withRulesDir(t, writeRulesTree(t))
	LoadVulnLibrary() // 并行体系(正则规则)需先加载

	st := RulesStat()
	if st.Total != st.Builtin+st.Official+st.Custom {
		t.Errorf("总数应等于三级之和: %+v", st)
	}
	if st.Builtin != 5 {
		t.Errorf("内置胜出计数应为 5, got %+v", st)
	}
	if st.Official != 1 || st.Custom != 2 {
		t.Errorf("official=1, custom=2, got %+v", st)
	}
	if st.VulnRules == 0 {
		t.Error("vuln_builtin.json 内置正则规则应计入(两套体系并行)")
	}
}

// TestRulesDirMissing 规则目录不存在: 降级为仅内置规则, 不报错
func TestRulesDirMissing(t *testing.T) {
	withRulesDir(t, filepath.Join(t.TempDir(), "not-exist"))
	rules, _ := RefreshRules()
	if len(rules) != 5 {
		t.Errorf("目录缺失时应仅剩内置 5 条, got %d", len(rules))
	}
}
