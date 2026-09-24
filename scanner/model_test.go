package scanner

import "testing"

func TestAssetModel(t *testing.T) {
	a := NewAsset("1.2.3.4", 80, "http", "nginx", "1.25.0")
	b := NewAsset("1.2.3.4", 80, "http", "nginx", "1.25.0")
	if a.ID == "" || len(a.ID) != 16 {
		t.Fatalf("资产 ID 应为 16 位十六进制: %q", a.ID)
	}
	if a.ID != b.ID {
		t.Error("同一资产的 ID 应跨调用稳定")
	}
	// 默认端口省略
	if a.Key() != "1.2.3.4/http" {
		t.Errorf("默认端口键应省略端口: %q", a.Key())
	}
	c := NewAsset("1.2.3.4", 8080, "http", "nginx", "1.25.0")
	if c.Key() == a.Key() {
		t.Error("非默认端口键应含端口")
	}
	// 产品归一化(Apache httpd -> apache)
	d := NewAsset("1.2.3.4", 443, "https", "Apache httpd", "2.4.49")
	if d.Product != "apache" {
		t.Errorf("产品应归一化为 apache, 实际 %q", d.Product)
	}
	// ServiceAsset 转换
	sa := ServiceAsset{IP: "9.9.9.9", Port: 8443, Scheme: "https", Product: "tomcat", Version: "9.0.50"}
	e := AssetFromServiceAsset(sa)
	if e.IP != sa.IP || e.Port != sa.Port || e.Scheme != sa.Scheme || e.Product != "tomcat" {
		t.Errorf("ServiceAsset 转换错误: %+v", e)
	}
	if e.ID == "" {
		t.Error("转换后资产应有 ID")
	}
}

func TestVulnerabilityFromFinding(t *testing.T) {
	RefreshIntel()
	a := NewAsset("10.0.0.1", 443, "https", "tomcat", "9.0.50")
	f := NewFinding("high", "Apache Tomcat 已知漏洞", "detail", "升级到 9.0.98")
	v1 := FromFinding(a, f, VulnSourceBuiltin, "YUGSIGHT-0001", "cve-2021-44228")
	v2 := FromFinding(a, f, VulnSourceBuiltin, "YUGSIGHT-0001", "CVE-2021-44228")
	if v1.ID == "" || v1.ID != v2.ID {
		t.Fatalf("同漏洞 ID 应稳定且归一化: %q vs %q", v1.ID, v2.ID)
	}
	if v1.CVE != "CVE-2021-44228" {
		t.Errorf("CVE 应大写归一化: %q", v1.CVE)
	}
	if !v1.KeV {
		t.Error("应自动填充 KEV 标记")
	}
	if v1.Epss <= 0 {
		t.Error("应自动填充 EPSS 分值")
	}
	if v1.MatchType != MatchTypeVerified {
		t.Errorf("正则规则命中应为验证型: %q", v1.MatchType)
	}
	// 80(verified) + 5(regex) + 5(版本) + 5(已知 CVE) + 3(high) = 98/high
	if v1.Confidence != 98 || v1.ConfidenceLevel != "high" {
		t.Errorf("置信度应为 98/high, 实际 %d/%s", v1.Confidence, v1.ConfidenceLevel)
	}
	if v1.AssetID != a.ID || v1.Asset.IP != a.IP {
		t.Error("资产应正确内嵌")
	}
}

func TestVulnerabilityFromNuclei(t *testing.T) {
	RefreshIntel()
	a := ServiceAsset{IP: "10.0.0.2", Port: 80, Scheme: "http", Product: "nginx", Version: "1.25.0"}
	nf := NucleiFinding{
		Finding:    NewFinding("critical", "Log4j2 RCE", "body 命中", ""),
		Source:     "nuclei-builtin",
		TemplateID: "yugsight-log4j",
		CVE:        "CVE-2021-44228",
		Host:       a.IP,
		Port:       a.Port,
		RawResponse: "HTTP/1.1 200 OK\nX-Powered-By: ...",
	}
	v := FromNucleiFinding(a, nf)
	if !v.KeV || v.Epss <= 0 {
		t.Error("应填充 KEV/EPSS")
	}
	if v.Source != "nuclei-builtin" || v.RuleID != "yugsight-log4j" {
		t.Errorf("来源/规则 ID 错误: %q/%q", v.Source, v.RuleID)
	}
	if v.Evidence == "" {
		t.Error("应保留响应证据")
	}
	// 超长证据限量
	nf.RawResponse = string(make([]byte, 50*1024))
	v2 := FromNucleiFinding(a, nf)
	if len(v2.Evidence) != evidenceLimit {
		t.Errorf("证据应限量 %d 字节, 实际 %d", evidenceLimit, len(v2.Evidence))
	}
}

func TestVulnerabilityFromCPE(t *testing.T) {
	a := NewAsset("10.0.0.3", 22, "", "openssh", "8.2")
	ms := []CPEEngineMatch{{
		Product: "openssh", Vendor: "OpenBSD", Version: "8.2",
		MatchType: MatchTypeVersion,
		CVEs: []CPEEngineCVE{
			{ID: "CVE-2021-41617", Description: "regreSSHion", CVSS: 7.5, Fix: "升级 8.5"},
			{ID: "CVE-2024-0471", Description: "另一漏洞", CVSS: 4.2, Fix: "升级"},
		},
	}}
	out := FromCPEMatches(a, ms)
	if len(out) != 2 {
		t.Fatalf("应产出 2 条漏洞, 实际 %d", len(out))
	}
	v := out[0]
	if v.MatchType != MatchTypeVersion {
		t.Errorf("应为版本匹配型: %q", v.MatchType)
	}
	if v.Source != VulnSourceCPE || v.CVE != "CVE-2021-41617" {
		t.Errorf("来源/CVE 错误: %q/%q", v.Source, v.CVE)
	}
	if v.Severity != "high" || v.CVSS != 7.5 {
		t.Errorf("severity/CVSS 错误: %q/%v", v.Severity, v.CVSS)
	}
	// 版本匹配型置信度: 55 + 5(版本) + 0(无 CVE 情报) + 3(high) = 63/medium
	if v.Confidence != 63 || v.ConfidenceLevel != "medium" {
		t.Errorf("置信度应为 63/medium, 实际 %d/%s", v.Confidence, v.ConfidenceLevel)
	}
}

func TestDedupAndSortVulns(t *testing.T) {
	RefreshIntel()
	a := NewAsset("10.0.1.1", 445, "", "smb", "3.1.1")
	v1 := NewVulnerability(a, VulnSourceCPE, "", "CVE-2017-0144", "SMB EternalBlue", "high", MatchTypeVersion, "", 8.1, "", "", "")
	v2 := NewVulnerability(a, VulnSourceCPE, "", "CVE-2017-0144", "SMB EternalBlue", "high", MatchTypeVersion, "", 8.1, "", "", "")
	v3 := NewVulnerability(a, VulnSourceCPE, "", "CVE-2019-0708", "BlueKeep", "high", MatchTypeVersion, "", 8.1, "", "", "")
	ds := DedupVulns([]*Vulnerability{v1, v2, v3, nil})
	if len(ds) != 2 {
		t.Fatalf("去重后应为 2 条, 实际 %d", len(ds))
	}
	// 2017-0144 EPSS 0.976 > 2019-0708 0.9668, 且两者均 KEV
	sorted := SortByPriority([]*Vulnerability{v3, v1})
	if sorted[0].CVE != "CVE-2017-0144" {
		t.Errorf("高 EPSS 漏洞应排前: %q", sorted[0].CVE)
	}
	// 非 KEV 的漏洞排在 KEV 之后
	v4 := NewVulnerability(a, VulnSourceBuiltin, "YUGSIGHT-0001", "", "本地规则漏洞", "critical", MatchTypeVerified, "regex", 9.8, "", "", "")
	sorted2 := SortByPriority([]*Vulnerability{v4, v1})
	if sorted2[0].CVE != "CVE-2017-0144" {
		t.Errorf("KEV 漏洞应优先于非 KEV: %q", sorted2[0].CVE)
	}
}
