package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestCompareVersions 语义版本比较: 缺省段/预发布/构建元数据/前导 v/数字段
func TestCompareVersions(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0", "1.0.0", 0},
		{"1.18", "1.18.0", 0},
		{"1.18.0", "1.19", -1},
		{"1.9", "1.10", -1}, // 数字比较而非字典序
		{"2.4.49", "2.4.50", -1},
		{"2.4.51", "2.4.50", 1},
		{"10.0", "9.5", 1},
		{"18.04", "20.04", -1},
		{"v2.4.41", "2.4.41", 0},
		{"1.0.0-rc1", "1.0.0", -1}, // 预发布 < 正式版
		{"1.0.0-alpha", "1.0.0-beta", -1},
		{"1.0.0-alpha", "1.0.0-alpha.1", -1},
		{"8.2", "8.2p1", -1},          // 数字段 < 非数字段
		{"1.0.0+build.5", "1.0.0", 0}, // 构建元数据忽略
		{"2.4.41", "2.4.41", 0},
	}
	for _, c := range cases {
		if got := CompareVersions(c.a, c.b); got != c.want {
			t.Errorf("CompareVersions(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestParseVersionConstraint 版本约束解析与判定(< <= > >=, 逗号 AND)
func TestParseVersionConstraint(t *testing.T) {
	// 空约束匹配一切
	empty, err := ParseVersionConstraint("")
	if err != nil || !empty.Match("999.999.999") {
		t.Fatalf("空约束应匹配一切: %v", err)
	}

	vc, err := ParseVersionConstraint("< 1.21.0")
	if err != nil {
		t.Fatal(err)
	}
	if !vc.Match("1.18.0") || vc.Match("1.21.0") || vc.Match("1.22") {
		t.Error("< 1.21.0 判定错误")
	}

	vc, err = ParseVersionConstraint(">= 2.4.49, < 2.4.50")
	if err != nil {
		t.Fatal(err)
	}
	if !vc.Match("2.4.49") || vc.Match("2.4.50") || vc.Match("2.4.48") {
		t.Error("范围 [2.4.49, 2.4.50) 判定错误")
	}

	vc, err = ParseVersionConstraint(">= 8.5.0, < 8.5.51")
	if err != nil || !vc.Match("8.5.50") || vc.Match("8.5.51") {
		t.Error("tomcat 8.5 范围判定错误")
	}

	vc, err = ParseVersionConstraint("> 1.0, <= 2.0")
	if err != nil || !vc.Match("1.0.1") || vc.Match("1.0") || !vc.Match("2.0") || vc.Match("2.0.1") {
		t.Error("开区间 (1.0, 2.0] 判定错误")
	}

	for _, bad := range []string{"1.2.3", "<=", "abc 1.0", "<= ", ">=", "< x"} {
		if _, err := ParseVersionConstraint(bad); err == nil {
			t.Errorf("约束 %q 应报错", bad)
		}
	}
}

// loadCPEForTest 以空临时目录为外部目录加载内置字典, 结束后恢复默认
func loadCPEForTest(t *testing.T) {
	t.Helper()
	old := cpeExternalDir
	cpeExternalDir = t.TempDir()
	t.Cleanup(func() {
		cpeExternalDir = old
		LoadCPEDictionary()
	})
	if n, errs := LoadCPEDictionary(); n == 0 {
		t.Fatalf("内置 CPE 字典加载失败: %v", errs)
	}
}

func cveSet(t *testing.T, ms []CPEMatch) map[string]bool {
	t.Helper()
	if len(ms) != 1 {
		t.Fatalf("应命中 1 个产品, got %+v", ms)
	}
	s := map[string]bool{}
	for _, c := range ms[0].CVEs {
		s[c.CVE] = true
	}
	return s
}

// TestMatchCPE 产品+版本 -> CVE 列表(含 CVSS)
func TestMatchCPE(t *testing.T) {
	loadCPEForTest(t)

	// nginx 1.17.2: 23017/3618 (< 1.21.0) + 20372 (<= 1.17.2) + 23471 (< 1.27.4)
	s := cveSet(t, MatchCPE("nginx", "1.17.2"))
	if len(s) != 4 || !s["CVE-2021-23017"] || !s["CVE-2019-20372"] || !s["CVE-2021-3618"] || !s["CVE-2025-23471"] {
		t.Errorf("nginx 1.17.2 = %v", s)
	}

	// nginx 1.18.0: 23017/3618/23471 (20372 已修复于 1.17.3)
	s = cveSet(t, MatchCPE("nginx", "1.18.0"))
	if len(s) != 3 || !s["CVE-2021-23017"] || !s["CVE-2021-3618"] || !s["CVE-2025-23471"] {
		t.Errorf("nginx 1.18.0 = %v", s)
	}

	// nginx 1.25.3: 7347 (>= 1.25.3, < 1.25.4) + 23471 (< 1.27.4); 23017/3618 已在 1.21.0 修复
	s = cveSet(t, MatchCPE("nginx", "1.25.3"))
	if len(s) != 2 || !s["CVE-2024-7347"] || !s["CVE-2025-23471"] {
		t.Errorf("nginx 1.25.3 = %v", s)
	}

	// 服务名归一化: "Apache httpd" -> apache; 2.4.49 命中 42013 + 25690 等(2.4.51 修复前的全部)
	s = cveSet(t, MatchCPE("Apache httpd", "2.4.49"))
	if len(s) != 9 || !s["CVE-2021-42013"] || !s["CVE-2023-25690"] || !s["CVE-2024-38473"] {
		t.Errorf("apache 2.4.49 = %v", s)
	}

	// 2.4.48 命中 41773 + 25690 等(42013 需 >= 2.4.49)
	s = cveSet(t, MatchCPE("apache", "2.4.48"))
	if len(s) != 12 || !s["CVE-2021-41773"] || !s["CVE-2023-25690"] {
		t.Errorf("apache 2.4.48 = %v", s)
	}

	// 新版本无命中(2.4.60 是 2024 年 CVE 的修复版)
	if got := MatchCPE("apache", "2.4.61"); len(got) != 0 {
		t.Errorf("apache 2.4.61 应无命中, got %+v", got)
	}

	// Tomcat 跨大版本 OR 约束: 8.5.50 命中 12617/9484/1938/21733
	s = cveSet(t, MatchCPE("Tomcat", "8.5.50"))
	if len(s) != 4 || !s["CVE-2020-1938"] || !s["CVE-2017-12617"] {
		t.Errorf("tomcat 8.5.50 = %v", s)
	}

	// 别名: ssh -> openssh; 8.2 命中 41617/38408/48795
	s = cveSet(t, MatchCPE("ssh", "8.2"))
	if len(s) != 3 || !s["CVE-2023-38408"] || !s["CVE-2023-48795"] {
		t.Errorf("openssh 8.2 = %v", s)
	}
	if got := MatchCPE("openssh", "9.6"); len(got) != 0 {
		t.Errorf("openssh 9.6 应无命中(最新修复版 9.5 之后), got %+v", got)
	}

	// Redis: 7.0.1 命中 0543/33917/28856(7.0.5/7.0.10 修复前); 7.0.16 无命中
	s = cveSet(t, MatchCPE("redis", "7.0.1"))
	if len(s) != 3 || !s["CVE-2022-0543"] || !s["CVE-2022-33917"] || !s["CVE-2023-28856"] {
		t.Errorf("redis 7.0.1 = %v", s)
	}
	if got := MatchCPE("redis", "7.0.16"); len(got) != 0 {
		t.Errorf("redis 7.0.16 应无命中, got %+v", got)
	}

	// IIS: 10.0 无命中, 6.0 命中(含 11317)
	if got := MatchCPE("Microsoft IIS", "10.0"); len(got) != 0 {
		t.Errorf("iis 10.0 应无命中, got %+v", got)
	}
	s = cveSet(t, MatchCPE("Microsoft IIS", "6.0"))
	if len(s) != 4 || !s["CVE-2017-11317"] || !s["CVE-2017-7269"] {
		t.Errorf("iis 6.0 = %v", s)
	}

	// 空输入 / 未知产品
	if got := MatchCPE("nginx", ""); len(got) != 0 {
		t.Error("版本为空应返回空")
	}
	if got := MatchCPE("", "1.0"); len(got) != 0 {
		t.Error("产品为空应返回空")
	}
	if got := MatchCPE("unknownproduct", "1.0"); len(got) != 0 {
		t.Error("未知产品应返回空")
	}
}

// TestCPEHotUpdate 外部 cpe/*.json 热更新: 同 CPE 覆盖内置 + 新增产品 + 坏文件不中断
func TestCPEHotUpdate(t *testing.T) {
	dir := t.TempDir()
	old := cpeExternalDir
	cpeExternalDir = dir
	t.Cleanup(func() {
		cpeExternalDir = old
		LoadCPEDictionary()
	})

	ext := `{
	  "version": "9.9",
	  "products": [
	    {
	      "cpe": "cpe:2.3:a:nginx:nginx",
	      "vendor": "nginx",
	      "product": "nginx",
	      "cves": [
	        {"cve": "CVE-2099-0001", "title": "测试外部字典条目", "cvss": 9.9, "constraints": ["< 9.0.0"]}
	      ]
	    },
	    {
	      "cpe": "cpe:2.3:a:testvendor:testproduct",
	      "vendor": "testvendor",
	      "product": "testproduct",
	      "cves": [
	        {"cve": "CVE-2099-0002", "cvss": 7.0}
	      ]
	    }
	  ]
	}`
	if err := os.WriteFile(filepath.Join(dir, "hot.json"), []byte(ext), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, errs := LoadCPEDictionary(); n == 0 {
		t.Fatalf("加载失败: %v", errs)
	}

	// nginx 被外部字典覆盖(内置 CVE 不再出现)
	ms := MatchCPE("nginx", "1.18.0")
	if len(ms) != 1 || len(ms[0].CVEs) != 1 || ms[0].CVEs[0].CVE != "CVE-2099-0001" {
		t.Errorf("nginx 应被外部字典覆盖, got %+v", ms)
	}
	// 空约束 = 全部版本受影响
	ms = MatchCPE("testproduct", "1.0")
	if len(ms) != 1 || len(ms[0].CVEs) != 1 || ms[0].CVEs[0].CVE != "CVE-2099-0002" {
		t.Errorf("外部新增产品应可匹配, got %+v", ms)
	}

	// 坏文件只记日志, 不中断加载
	if err := os.WriteFile(filepath.Join(dir, "bad.json"), []byte("{broken"), 0o644); err != nil {
		t.Fatal(err)
	}
	n, errs := LoadCPEDictionary()
	if n == 0 {
		t.Fatalf("坏文件不应中断加载: %v", errs)
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e, "bad.json") {
			found = true
		}
	}
	if !found {
		t.Errorf("错误列表应含 bad.json: %v", errs)
	}
}

// TestNvdSyncOutputFormat NVD 同步产物契约: scripts/nvd_sync.go 的输出形状必须
// 被引擎正确消费。三种关键形状(与 scripts/nvd_sync.go 的真实产物同构):
//  1. AND 组: 四边界合并为一条 ">= a, < b"(拆成多元素会被按 OR 解释 = 全版本误报)
//  2. 多 OR 组: 同一 CVE 两条版本线 -> 两个约束元素
//  3. 无约束: 全版本受影响 -> 省略 constraints 字段
//
// 任一端改动格式都会在这里暴露, 防止再次漂移。
func TestNvdSyncOutputFormat(t *testing.T) {
	dir := t.TempDir()
	old := cpeExternalDir
	cpeExternalDir = dir
	t.Cleanup(func() {
		cpeExternalDir = old
		LoadCPEDictionary()
	})

	ext := `{
	  "version": "nvd-sync 2026-01-01",
	  "products": [
	    {
	      "cpe": "cpe:2.3:a:nginx:nginx", "vendor": "nginx", "product": "nginx",
	      "cves": [
	        {"cve": "CVE-2099-1001", "cvss": 9.8, "constraints": [">= 1.0.0, < 1.21.0"]}
	      ]
	    },
	    {
	      "cpe": "cpe:2.3:a:apache:http_server", "vendor": "apache", "product": "apache",
	      "cves": [
	        {"cve": "CVE-2099-1002", "cvss": 7.5, "constraints": ["> 2.4.48, < 2.4.49", ">= 2.4.0, <= 2.4.48"]}
	      ]
	    },
	    {
	      "cpe": "cpe:2.3:a:openssh:openssh", "vendor": "openssh", "product": "openssh",
	      "cves": [
	        {"cve": "CVE-2099-1003", "cvss": 7.8}
	      ]
	    }
	  ]
	}`
	if err := os.WriteFile(filepath.Join(dir, "nvd-nginx.json"), []byte(ext), 0o644); err != nil {
		t.Fatal(err)
	}
	if n, errs := LoadCPEDictionary(); n == 0 {
		t.Fatalf("加载失败: %v", errs)
	}

	// 1. AND 组: 区间内命中, 区间外不命中(若被拆成 OR, 1.22.0 会误报)
	ms := MatchCPE("nginx", "1.20.0")
	if len(ms) != 1 || len(ms[0].CVEs) != 1 || ms[0].CVEs[0].CVE != "CVE-2099-1001" {
		t.Errorf("nginx 1.20.0 应命中 AND 组, got %+v", ms)
	}
	if got := MatchCPE("nginx", "1.22.0"); len(got) != 0 && len(got[0].CVEs) != 0 {
		t.Errorf("nginx 1.22.0 超出区间不应命中(否则说明约束被按 OR 解释): %+v", got)
	}

	// 2. 多 OR 组: 两条版本线各自独立命中
	ms = MatchCPE("apache", "2.4.48.1")
	if len(ms) != 1 || len(ms[0].CVEs) != 1 || ms[0].CVEs[0].CVE != "CVE-2099-1002" {
		t.Errorf("apache 2.4.48.1 应命中第一条版本线, got %+v", ms)
	}
	ms = MatchCPE("apache", "2.4.30")
	if len(ms) != 1 || len(ms[0].CVEs) != 1 || ms[0].CVEs[0].CVE != "CVE-2099-1002" {
		t.Errorf("apache 2.4.30 应命中第二条版本线, got %+v", ms)
	}
	if got := MatchCPE("apache", "2.5.0"); len(got) != 0 && len(got[0].CVEs) != 0 {
		t.Errorf("apache 2.5.0 两条线都不应命中: %+v", got)
	}

	// 3. 无约束: 全版本命中
	ms = MatchCPE("openssh", "9.9.9")
	if len(ms) != 1 || len(ms[0].CVEs) != 1 || ms[0].CVEs[0].CVE != "CVE-2099-1003" {
		t.Errorf("openssh 任意版本应命中无约束 CVE, got %+v", ms)
	}
}

// TestCVSSSeverity CVSS 基础分 -> 严重级别域
func TestCVSSSeverity(t *testing.T) {
	cases := []struct {
		score float64
		want  string
	}{
		{9.8, "high"},
		{7.0, "high"},
		{6.9, "medium"},
		{4.0, "medium"},
		{3.9, "low"},
		{0, "info"},
	}
	for _, c := range cases {
		if got := CVSSSeverity(c.score); got != c.want {
			t.Errorf("CVSSSeverity(%v) = %s, want %s", c.score, got, c.want)
		}
	}
}

// TestCPEFindings 匹配结果 -> Finding(兼容漏洞列表, 含 CVSS 证据)
func TestCPEFindings(t *testing.T) {
	loadCPEForTest(t)
	ms := MatchCPE("nginx", "1.17.2")
	if len(ms) != 1 {
		t.Fatalf("nginx 1.17.2 应命中, got %+v", ms)
	}
	findings := ms[0].Findings()
	if len(findings) != 4 {
		t.Fatalf("应产生 4 条 finding, got %d", len(findings))
	}
	var found20372 bool
	for _, f := range findings {
		if strings.Contains(f.Title, "CVE-2019-20372") &&
			f.Severity == "high" &&
			strings.Contains(f.Detail, "CVSS 7.5") {
			found20372 = true
		}
	}
	if !found20372 {
		t.Errorf("findings 应含 CVE-2019-20372(high, CVSS 7.5): %+v", findings)
	}
}

// TestVulnLibraryLoadsCPE LoadVulnLibrary 联动加载 CPE 字典(共存, 不影响原规则)
func TestVulnLibraryLoadsCPE(t *testing.T) {
	old := cpeExternalDir
	cpeExternalDir = t.TempDir()
	t.Cleanup(func() {
		cpeExternalDir = old
		LoadCPEDictionary()
	})

	n, errs := LoadVulnLibrary()
	if n == 0 {
		t.Fatalf("漏洞库应加载成功: %v", errs)
	}
	if CPEVulnCount() == 0 {
		t.Error("LoadVulnLibrary 后 CPE 字典应已同步加载")
	}
	if CPEProductCount() == 0 {
		t.Error("CPE 字典应有产品条目")
	}
}
