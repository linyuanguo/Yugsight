package models

import "testing"

func TestAssetStableID(t *testing.T) {
	a := NewAsset(" 10.0.0.1 ")
	if a.IP != "10.0.0.1" {
		t.Errorf("IP 应归一化: %q", a.IP)
	}
	if len(a.ID) != 16 {
		t.Fatalf("资产 ID 应为 16 位: %q", a.ID)
	}
	b := NewAsset("10.0.0.1")
	if a.ID != b.ID {
		t.Error("同 IP 资产 ID 应稳定一致")
	}
	if a.Key() != "10.0.0.1" {
		t.Errorf("键应为归一化 IP: %q", a.Key())
	}
}

func TestNormalizeCVE(t *testing.T) {
	cases := map[string]string{
		"cve-2021-44228":  "CVE-2021-44228",
		" CVE_2021_44228 ": "CVE-2021-44228",
		"CVE-2021-44228":  "CVE-2021-44228",
		"":                "",
		"YUGSIGHT-0001":       "YUGSIGHT-0001",
	}
	for in, want := range cases {
		if got := NormalizeCVE(in); got != want {
			t.Errorf("NormalizeCVE(%q) = %q, want %q", in, got, want)
		}
	}
	if !IsCVE("cve-2021-44228") || IsCVE("YUGSIGHT-0001") {
		t.Error("IsCVE 判定错误")
	}
}

func TestNormalizeSeverity(t *testing.T) {
	cases := map[string]string{
		"CRITICAL":      SeverityCritical,
		"crit":          SeverityCritical,
		"High":          SeverityHigh,
		"Medium":        SeverityMedium,
		"moderate":      SeverityMedium,
		"low":           SeverityLow,
		"Informational": SeverityInfo,
		"":              SeverityLow,
		"weird":         SeverityLow,
	}
	for in, want := range cases {
		if got := NormalizeSeverity(in); got != want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCVSSSeverity(t *testing.T) {
	if CVSSSeverity(9.8) != SeverityCritical {
		t.Error("9.8 应为 critical")
	}
	if CVSSSeverity(7.5) != SeverityHigh {
		t.Error("7.5 应为 high")
	}
	if CVSSSeverity(5.0) != SeverityMedium {
		t.Error("5.0 应为 medium")
	}
	if CVSSSeverity(3.9) != SeverityLow {
		t.Error("3.9 应为 low")
	}
	if CVSSSeverity(0) != SeverityInfo {
		t.Error("0 应为 info")
	}
}

func TestVulnMergeKey(t *testing.T) {
	v1 := &Vuln{AssetIP: "10.0.0.1", CVE: "cve-2021-44228"}
	v2 := &Vuln{AssetIP: " 10.0.0.1 ", CVE: "CVE_2021_44228"}
	if v1.MergeKey() != v2.MergeKey() {
		t.Error("同资产+同 CVE（不同写法）应有相同合并键")
	}
	v3 := &Vuln{AssetIP: "10.0.0.1", Port: 80, Protocol: "http", Title: "XSS"}
	v4 := &Vuln{AssetIP: "10.0.0.1", Port: 80, Protocol: "http", Title: "XSS"}
	if v3.MergeKey() != v4.MergeKey() {
		t.Error("无 CVE 时同资产同端口同标题应有相同合并键")
	}
	v5 := &Vuln{AssetIP: "10.0.0.1", Port: 443, Protocol: "http", Title: "XSS"}
	if v3.MergeKey() == v5.MergeKey() {
		t.Error("不同端口应有不同合并键")
	}
	if len(v1.StableID()) != 16 {
		t.Error("漏洞 ID 应为 16 位")
	}
	if v1.StableID() != v2.StableID() {
		t.Error("同合并键漏洞 ID 应稳定一致")
	}
}
