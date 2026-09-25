package normalizer

import (
	"strings"
	"testing"
)

func TestFromNuclei(t *testing.T) {
	b := FromNuclei("10.1.1.1", []NucleiResult{
		{Host: "10.1.1.1", Port: 443, Scheme: "https", TemplateID: "tpl", CVE: "CVE-2021-44228",
			Title: "T", Severity: "critical", RawRequest: "GET /", RawResponse: "HTTP/1.1 200"},
		{Port: 8080, Scheme: "http", Title: "No CVE", Severity: "high"},
	})
	if b.Source != SourceNuclei || len(b.Vulns) != 2 {
		t.Fatalf("批次错误: %+v", b)
	}
	if b.Vulns[0].AssetIP != "10.1.1.1" || b.Vulns[0].Protocol != "https" {
		t.Errorf("字段错误: %+v", b.Vulns[0])
	}
	// host 回退到批次级 host
	if b.Vulns[1].AssetIP != "10.1.1.1" {
		t.Errorf("应回退批次 host: %+v", b.Vulns[1])
	}
	// Fix 并入描述
	nb := FromNuclei("10.1.1.1", []NucleiResult{
		{Title: "T", Detail: "detail", Fix: "upgrade", Severity: "low"},
	})
	if !strings.Contains(nb.Vulns[0].Description, "upgrade") ||
		!strings.Contains(nb.Vulns[0].Description, "detail") {
		t.Errorf("描述应包含 detail 与修复建议: %q", nb.Vulns[0].Description)
	}
}

func TestFromPortScan(t *testing.T) {
	b := FromPortScan([]PortScanHost{{
		IP: "10.1.1.2", MAC: "aa:bb:cc:dd:ee:ff", Hostname: "h2", OS: "Windows",
		Ports: []OpenPort{
			{Port: 22, Protocol: "tcp", Service: "ssh", Version: "8.2", Banner: "OpenSSH 8.2"},
			{Port: 80, Protocol: "tcp", Service: "http", Version: "nginx 1.25"},
			{Port: -1}, // 非法端口应被过滤
		},
		Tags: []string{"web"},
	}})
	if len(b.Assets) != 1 {
		t.Fatalf("资产数错误: %d", len(b.Assets))
	}
	a := b.Assets[0]
	if len(a.Ports) != 2 || a.Ports[0] != 22 || a.Ports[1] != 80 {
		t.Errorf("端口列表错误: %v", a.Ports)
	}
	if a.Service != "ssh" || a.Version != "8.2" || a.Banner != "OpenSSH 8.2" {
		t.Errorf("主服务错误: %+v", a)
	}
	if a.ProbeNode != "" {
		t.Errorf("无探针应无探针节点: %q", a.ProbeNode)
	}
}

func TestFromNmap(t *testing.T) {
	b, err := FromNmapJSON([]byte(nmapSampleMerge))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(b.Assets) != 1 {
		t.Fatalf("资产数错误: %d", len(b.Assets))
	}
	a := b.Assets[0]
	if a.MAC != "aa-bb-cc-dd-ee-ff" || a.Hostname != "srv1" || a.OS != "Linux 5.x" {
		t.Errorf("资产字段错误: %+v", a)
	}
	if a.Service != "http" || a.Version != "9.0.50" {
		t.Errorf("主服务错误: %+v", a)
	}
	if len(b.Vulns) != 1 {
		t.Fatalf("漏洞数错误: %d", len(b.Vulns))
	}
	v := b.Vulns[0]
	if v.CVE != "CVE-2021-44228" || v.Port != 8080 || v.CVSS != 9.8 {
		t.Errorf("漏洞字段错误: %+v", v)
	}
	if !strings.Contains(v.Title, "log4j2") {
		t.Errorf("标题应含插件名: %q", v.Title)
	}

	// 非 CVE 插件 ID: 不进 CVE 字段, 进标题
	b2, err := FromNmapJSON([]byte(`{"hosts":[{"address":"10.9.9.9","ports":[
		{"portid":6379,"protocol":"tcp","state":{"state":"open"},
		 "vulns":[{"id":"redis-uuid","script-id":"redis-brute","state":"vulnerable"}]}]}]}`))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(b2.Vulns) != 1 || b2.Vulns[0].CVE != "" {
		t.Errorf("非 CVE 插件不应占 CVE 字段: %+v", b2.Vulns)
	}
	if !strings.Contains(b2.Vulns[0].Title, "redis-brute") {
		t.Errorf("插件名应进标题: %q", b2.Vulns[0].Title)
	}

	// 非 open 端口不计入
	b3, _ := FromNmapJSON([]byte(`{"hosts":[{"address":"10.9.9.8","ports":[
		{"portid":22,"protocol":"tcp","state":{"state":"closed"}}]}]}`))
	if len(b3.Assets) != 1 || len(b3.Assets[0].Ports) != 0 {
		t.Errorf("closed 端口不应计入: %+v", b3.Assets)
	}

	if _, err := FromNmapJSON([]byte("{bad")); err == nil {
		t.Error("非法 JSON 应报错")
	}
	if _, err := FromNmapJSON(nil); err == nil {
		t.Error("空输出应报错")
	}
}

func TestFromTrivy(t *testing.T) {
	doc := `{
	  "SchemaVersion": 2,
	  "ArtifactName": "nginx:1.25",
	  "Results": [{
	    "Target": "nginx@sha256:abc",
	    "Class": "os",
	    "Vulnerabilities": [
	      {"VulnerabilityID": "CVE-1111-0001", "PkgName": "liba", "InstalledVersion": "1.0",
	       "FixedVersion": "1.1", "Status": "FIXED", "Severity": "CRITICAL", "Title": "已修复项"},
	      {"VulnerabilityID": "CVE-2222-0002", "PkgName": "libb", "InstalledVersion": "2.0",
	       "Status": "UNKNOWN", "Severity": "CRITICAL", "Title": "Path traversal",
	       "Cvss": {"NVD": {"Score": 9.8}}},
	      {"VulnerabilityID": "CVE-3333-0003", "PkgName": "libc", "InstalledVersion": "3.0",
	       "FixedVersion": "3.1", "Status": "WONT_FIX", "Severity": "MEDIUM", "Title": "Info leak",
	       "Cvss": {"GitHub": {"Score": 5.3}}}
	    ]
	  }]
	}`
	b, err := FromTrivyJSON([]byte(doc))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(b.Vulns) != 2 {
		t.Fatalf("应跳过 FIXED, 实际 %d", len(b.Vulns))
	}
	// 适配器保留来源原始等级（归一化由 Normalize 核心完成）
	if !strings.EqualFold(b.Vulns[0].Severity, "critical") || b.Vulns[0].CVSS != 9.8 {
		t.Errorf("等级/CVSS 错误: %+v", b.Vulns[0])
	}
	if b.Vulns[1].CVSS != 5.3 {
		t.Errorf("GitHub CVSS 应取到: %+v", b.Vulns[1])
	}
	if !strings.Contains(b.Vulns[1].Description, "3.1") {
		t.Errorf("应含修复版本: %q", b.Vulns[1].Description)
	}
	if b.Vulns[0].AssetIP != "nginx@sha256:abc" {
		t.Errorf("资产标识应为 target: %q", b.Vulns[0].AssetIP)
	}
	if _, err := FromTrivyJSON([]byte(`[1,2`)); err == nil {
		t.Error("非法 JSON 应报错")
	}
	if _, err := FromTrivyJSON([]byte("  ")); err == nil {
		t.Error("空输出应报错")
	}
}

func TestFromZAP(t *testing.T) {
	doc := `{
	  "site": [{
	    "name": "https://10.1.1.3:8443",
	    "alerts": [
	      {"name": "XSS (Reflected)", "riskcode": 2, "confidencecode": 3, "riskdesc": "Medium",
	       "desc": "XSS", "evidence": "alert(1)", "uri": "https://10.1.1.3:8443/x?y=1",
	       "method": "GET", "parameter": "y", "solution": "escape output"}
	    ]
	  }]
	}`
	b, err := FromZAPJSON([]byte(doc))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(b.Assets) != 1 || b.Assets[0].IP != "10.1.1.3" || b.Assets[0].Ports[0] != 8443 {
		t.Fatalf("资产错误: %+v", b.Assets)
	}
	if len(b.Vulns) != 1 {
		t.Fatalf("漏洞数错误: %d", len(b.Vulns))
	}
	v := b.Vulns[0]
	if v.Severity != "medium" || v.Confidence != 60 || v.Port != 8443 {
		t.Errorf("漏洞字段错误: %+v", v)
	}
	if !strings.Contains(v.Request, "GET") || !strings.Contains(v.Request, "x?y=1") {
		t.Errorf("请求错误: %q", v.Request)
	}
	if !strings.Contains(v.Description, "escape output") {
		t.Errorf("应含修复建议: %q", v.Description)
	}
	// 裸 IP 站点
	b2, _ := FromZAPJSON([]byte(`{"site":[{"name":"10.2.2.2","alerts":[
		{"name":"A","riskcode":3,"confidencecode":5,"uri":"http://10.2.2.2/p","method":"GET"}]}]}`))
	if b2.Assets[0].IP != "10.2.2.2" || b2.Assets[0].Ports[0] != 80 {
		t.Errorf("裸 IP 站点解析错误: %+v", b2.Assets)
	}
	if b2.Vulns[0].Severity != "high" || b2.Vulns[0].Confidence != 100 {
		t.Errorf("风险/置信度错误: %+v", b2.Vulns[0])
	}
	if _, err := FromZAPJSON([]byte(`{"site":`)); err == nil {
		t.Error("非法 JSON 应报错")
	}
}

func TestFromProbe(t *testing.T) {
	b, err := FromProbeJSON([]byte(probeSampleMerge))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if b.Source != SourceProbe || b.ScanID != "scan-1" {
		t.Errorf("批次字段错误: %+v", b)
	}
	if len(b.Assets) != 1 || b.Assets[0].ProbeNode != "probe-01" {
		t.Errorf("资产错误: %+v", b.Assets)
	}
	if len(b.Vulns) != 1 || b.Vulns[0].PcapFile != "/pcap/p1.pcap" {
		t.Errorf("漏洞错误: %+v", b.Vulns)
	}
	// 结构化入口
	rb := FromProbeReport(ProbeReport{NodeID: "n2", Assets: []ProbeAsset{{IP: " "}}})
	if len(rb.Assets) != 0 {
		t.Errorf("空 IP 资产应被过滤: %+v", rb.Assets)
	}
	if _, err := FromProbeJSON([]byte(`{"nodeId":`)); err == nil {
		t.Error("非法 JSON 应报错")
	}
}
