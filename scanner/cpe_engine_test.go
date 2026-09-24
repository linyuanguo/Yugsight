package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ===== 模块2 测试(CPE 主机漏洞引擎) =====

// TestParseCPEConstraint 版本约束解析: < <= > >= == (== 为 cpe.go 之上的扩展)
func TestParseCPEConstraint(t *testing.T) {
	// == 精确匹配
	c, err := ParseCPEConstraint("== 1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Match("1.2.3") || c.Match("1.2.4") || c.Match("1.2") {
		t.Error("== 1.2.3 判定错误")
	}

	// == 与其他运算符组合(AND)
	c, err = ParseCPEConstraint(">= 1.0, == 1.2.3")
	if err != nil {
		t.Fatal(err)
	}
	if !c.Match("1.2.3") || c.Match("1.0") || c.Match("1.2.4") {
		t.Error(">= 1.0, == 1.2.3 判定错误")
	}

	// 兼容四种不等式运算符
	cases := []struct {
		cs   string
		v    string
		want bool
	}{
		{"< 2.0", "1.9", true}, {"< 2.0", "2.0", false},
		{"<= 2.0", "2.0", true}, {"<= 2.0", "2.0.1", false},
		{"> 1.0", "1.0.1", true}, {"> 1.0", "1.0", false},
		{">= 1.0", "1.0", true}, {">= 1.0", "0.9", false},
	}
	for _, cs := range cases {
		c, err := ParseCPEConstraint(cs.cs)
		if err != nil {
			t.Fatalf("解析 %q 失败: %v", cs.cs, err)
		}
		if got := c.Match(cs.v); got != cs.want {
			t.Errorf("%q.Match(%q) = %v, want %v", cs.cs, cs.v, got, cs.want)
		}
	}

	// 空约束 = 匹配所有版本
	empty, err := ParseCPEConstraint("")
	if err != nil || !empty.Match("999.999") {
		t.Errorf("空约束应匹配一切: %v", err)
	}

	// 非法输入报错
	for _, bad := range []string{"1.2.3", "1.2.3 4.5", "<=", "== ", "< x"} {
		if _, err := ParseCPEConstraint(bad); err == nil {
			t.Errorf("约束 %q 应报错", bad)
		}
	}
}

// TestMatchAnyConstraint OR 语义与空列表
func TestMatchAnyConstraint(t *testing.T) {
	if !MatchAnyConstraint("1.18.0", nil) {
		t.Error("空约束列表应匹配所有版本")
	}
	if !MatchAnyConstraint("2.4.49", []string{">= 2.4.49, < 2.4.50", "< 1.0"}) {
		t.Error("OR 语义: 任一命中即可")
	}
	if MatchAnyConstraint("9.9.9", []string{">= 2.4.49, < 2.4.50"}) {
		t.Error("无约束命中应返回 false")
	}
}

// TestMatchCPEEngine 产品+版本 -> 结构化 CVE 列表(版本匹配型标记 + 描述 + 修复建议)
func TestMatchCPEEngine(t *testing.T) {
	loadCPEForTest(t)

	ms := MatchCPEEngine("nginx", "1.17.2")
	if len(ms) != 1 {
		t.Fatalf("nginx 1.17.2 应命中 1 个产品, got %+v", ms)
	}
	m := ms[0]
	if m.MatchType != MatchTypeVersion {
		t.Errorf("应标记版本匹配型, got %s", m.MatchType)
	}
	if len(m.CVEs) != 4 {
		t.Fatalf("应命中 4 条 CVE, got %+v", m.CVEs)
	}
	var saw23017 bool
	for _, cv := range m.CVEs {
		if cv.ID == "" || cv.CVSS <= 0 || cv.Description == "" || cv.Fix == "" {
			t.Errorf("CVE 字段应完整(编号/CVSS/描述/修复建议): %+v", cv)
		}
		if !cv.VersionMatched {
			t.Errorf("CVE 应带版本匹配型标记: %+v", cv)
		}
		if !strings.Contains(cv.Description, "CVSS") {
			t.Errorf("描述应含 CVSS 信息: %+v", cv)
		}
		if cv.ID == "CVE-2021-23017" {
			saw23017 = true
		}
	}
	if !saw23017 {
		t.Errorf("应命中 CVE-2021-23017: %+v", m.CVEs)
	}
}

// TestMatchCPEEngineAlias 产品别名映射(归一化 + 字典 aliases)
func TestMatchCPEEngineAlias(t *testing.T) {
	loadCPEForTest(t)

	// 归一化: productKeyMap
	if NormalizeProduct("Apache httpd") != "apache" {
		t.Error(`NormalizeProduct("Apache httpd") 应为 "apache"`)
	}
	if NormalizeProduct("Microsoft IIS") != "iis" {
		t.Error(`NormalizeProduct("Microsoft IIS") 应为 "iis"`)
	}

	// 别名命中: "Apache httpd" 2.4.49
	ms := MatchCPEEngine("Apache httpd", "2.4.49")
	if len(ms) != 1 || len(ms[0].CVEs) != 9 {
		t.Errorf("Apache httpd 2.4.49 应命中 9 条 CVE, got %+v", ms)
	}
	// 字典 aliases: "ssh" -> openssh
	ms = MatchCPEEngine("ssh", "8.2")
	if len(ms) != 1 || len(ms[0].CVEs) != 3 {
		t.Errorf("ssh 8.2 应命中 3 条 openssh CVE, got %+v", ms)
	}
}

// TestMatchCPEEngineEmpty 空输入 / 未知产品
func TestMatchCPEEngineEmpty(t *testing.T) {
	loadCPEForTest(t)
	if got := MatchCPEEngine("nginx", ""); got != nil {
		t.Errorf("版本为空应返回 nil, got %+v", got)
	}
	if got := MatchCPEEngine("", "1.0"); got != nil {
		t.Errorf("产品为空应返回 nil, got %+v", got)
	}
	if got := MatchCPEEngine("unknownproduct", "1.0"); got != nil {
		t.Errorf("未知产品应返回 nil, got %+v", got)
	}
}

// TestCPEEngineFindings 引擎结果 -> Finding(标题标注版本匹配型)
func TestCPEEngineFindings(t *testing.T) {
	loadCPEForTest(t)
	ms := MatchCPEEngine("nginx", "1.17.2")
	if len(ms) != 1 {
		t.Fatalf("nginx 1.17.2 应命中, got %+v", ms)
	}
	fs := ms[0].Findings()
	if len(fs) != 4 {
		t.Fatalf("应产生 4 条 finding, got %d", len(fs))
	}
	for _, f := range fs {
		if !strings.Contains(f.Title, "版本匹配型") {
			t.Errorf("finding 标题应标注版本匹配型: %s", f.Title)
		}
		if f.Fix == "" {
			t.Errorf("finding 应含修复建议: %+v", f)
		}
		if f.Severity == "" {
			t.Error("finding 严重级别不应为空")
		}
	}
}

// TestLoadExternalCPE 外部完整版 CPE 库: 有效加载 + 坏文件/无效条目只告警不中断
func TestLoadExternalCPE(t *testing.T) {
	dir := t.TempDir()
	ext := `{
	  "version": "2.0",
	  "products": [
	    {
	      "cpe": "cpe:2.3:a:acme:widget",
	      "vendor": "acme",
	      "product": "widget",
	      "aliases": ["acme-widget"],
	      "cves": [
	        {"cve": "CVE-2098-1111", "title": "测试漏洞", "cvss": 8.1, "constraints": [">= 1.0, < 2.0"]},
	        {"cve": "CVE-2098-2222", "cvss": 5.0}
	      ]
	    },
	    {
	      "vendor": "acme",
	      "product": "",
	      "cves": [{"cve": "CVE-2098-3333", "cvss": 1.0}]
	    },
	    {
	      "cpe": "cpe:2.3:a:acme:badcve",
	      "vendor": "acme",
	      "product": "badcve",
	      "cves": [{"cve": "CVE-2098-4444", "cvss": 9.0, "constraints": ["not a constraint"]}]
	    }
	  ]
	}`
	if err := os.WriteFile(filepath.Join(dir, "full.json"), []byte(ext), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "broken.json"), []byte("{bad json"), 0o644); err != nil {
		t.Fatal(err)
	}

	prods, warns := LoadExternalCPE(dir)
	if len(prods) != 2 {
		t.Fatalf("应有 2 个有效产品(widget/badcve), got %+v", prods)
	}
	joined := strings.Join(warns, "\n")
	for _, kw := range []string{"broken.json", "缺少 product", "CVE-2098-4444"} {
		if !strings.Contains(joined, kw) {
			t.Errorf("告警应含 %q: %s", kw, joined)
		}
	}
	for _, p := range prods {
		if p.Product == "widget" && len(p.CVEs) != 2 {
			t.Errorf("widget 应有 2 条 CVE, got %+v", p)
		}
	}

	// 目录不存在: 返回告警, 不 panic
	if _, errs := LoadExternalCPE(filepath.Join(dir, "nope")); len(errs) == 0 {
		t.Error("目录不存在应返回告警")
	}
}

// TestRefreshCPE 强制重载 + 热更新(cpe/ 目录新增文件立即生效)
func TestRefreshCPE(t *testing.T) {
	old := cpeExternalDir
	cpeExternalDir = t.TempDir()
	t.Cleanup(func() {
		cpeExternalDir = old
		LoadCPEDictionary()
	})

	n, errs := RefreshCPE()
	if n == 0 {
		t.Fatalf("内置精简版字典应加载成功: %v", errs)
	}

	// 热更新: 新增外部文件后再次刷新, 计数增加且可匹配
	ext := `{"version":"9","products":[{"cpe":"cpe:2.3:a:t:v","vendor":"t","product":"hotprod","cves":[{"cve":"CVE-2099-7777","cvss":9.9}]}]}`
	if err := os.WriteFile(filepath.Join(cpeExternalDir, "hot.json"), []byte(ext), 0o644); err != nil {
		t.Fatal(err)
	}
	n2, _ := RefreshCPE()
	if n2 <= n {
		t.Errorf("热更新后计数应增加: %d -> %d", n, n2)
	}
	got := MatchCPEEngine("hotprod", "1.0")
	if len(got) != 1 || len(got[0].CVEs) != 1 || got[0].CVEs[0].ID != "CVE-2099-7777" {
		t.Errorf("新增外部产品应可匹配, got %+v", got)
	}
}
