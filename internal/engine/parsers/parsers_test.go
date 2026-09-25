package parsers

import (
	"strings"
	"testing"

	"yugsight/internal/models"
	"yugsight/internal/normalizer"
)

// ===== Nmap XML 解析 =====

const nmapXMLSample = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sT -sV -oX - 10.0.0.1" start="1757980000">
<host starttime="1757980001" endtime="1757980010">
  <status state="up" reason="syn-ack"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <address addr="AA-BB-CC-DD-EE-FF" addrtype="mac" vendor="VMware"/>
  <hostnames><hostname name="srv1.local" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="22">
      <state state="open" reason="syn-ack"/>
      <service name="ssh" product="OpenSSH" version="8.2p1" extrainfo="Ubuntu" method="probed" conf="10">
        <cpe>cpe:/a:openbsd:openssh:8.2p1</cpe>
      </service>
    </port>
    <port protocol="tcp" portid="445">
      <state state="open" reason="syn-ack"/>
      <service name="microsoft-ds" method="probed" conf="10"/>
      <script id="smb-vuln-ms17-010" output="VULNERABLE:&#xA;Remote Code Execution vulnerability in Microsoft SMBv1 (CVE-2017-0143)">
        <table key="ids">
          <elem key="title">Remote Code Execution vulnerability in Microsoft SMBv1</elem>
        </table>
      </script>
    </port>
    <port protocol="tcp" portid="8080">
      <state state="closed" reason="reset"/>
      <service name="http"/>
    </port>
  </ports>
  <hostscript>
    <script id="smb2-security-mode" output="Message signing enabled but not required"/>
  </hostscript>
  <os>
    <osmatch name="Linux 5.4 - 5.15" accuracy="98"/>
    <osmatch name="Linux 4.x" accuracy="90"/>
  </os>
</host>
<host>
  <status state="down" reason="no-response"/>
  <address addr="10.0.0.9" addrtype="ipv4"/>
</host>
<runstats><finished elapsed="12.34" exit="success" summary="Nmap done"/></runstats>
</nmaprun>`

func TestParseNmapXML(t *testing.T) {
	b, err := ParseNmap([]byte(nmapXMLSample))
	if err != nil {
		t.Fatalf("解析 nmap XML 失败: %v", err)
	}
	if b.Source != normalizer.SourceNmap {
		t.Fatalf("来源应为 nmap, 实际 %s", b.Source)
	}
	// 主机资产: 两个 host(含 down 主机)
	assets := b.AllAssets()
	if len(assets) != 2 {
		t.Fatalf("应有 2 个主机资产, 实际 %d", len(assets))
	}
	var up *normalizer.RawAsset
	for i := range assets {
		if assets[i].IP == "10.0.0.1" {
			up = &assets[i]
		}
	}
	if up == nil {
		t.Fatal("未找到 10.0.0.1 资产")
	}
	if up.MAC != "AA-BB-CC-DD-EE-FF" {
		t.Errorf("MAC 提取错误: %q", up.MAC)
	}
	if up.Hostname != "srv1.local" {
		t.Errorf("主机名提取错误: %q", up.Hostname)
	}
	if up.OS != "Linux 5.4 - 5.15" {
		t.Errorf("OS 应取 accuracy 最高项, 实际 %q", up.OS)
	}
	// 只收 open 端口(8080 closed 必须排除)
	if len(up.Ports) != 2 || up.Ports[0] != 22 || up.Ports[1] != 445 {
		t.Errorf("开放端口应为 [22 445], 实际 %v", up.Ports)
	}
	if up.Service != "ssh" || up.Version != "OpenSSH 8.2p1" || up.Banner != "Ubuntu" {
		t.Errorf("服务/版本/Banner 提取错误: %q/%q/%q", up.Service, up.Version, up.Banner)
	}
	// 漏洞: 仅 smb-vuln-ms17-010 命中(hostscript 的正常输出不产漏洞)
	if len(b.Vulns) != 1 {
		t.Fatalf("应有 1 条 NSE 漏洞, 实际 %d: %+v", len(b.Vulns), b.Vulns)
	}
	v := b.Vulns[0]
	if v.CVE != "CVE-2017-0143" {
		t.Errorf("CVE 提取错误: %q", v.CVE)
	}
	if v.Port != 445 || v.Protocol != "tcp" {
		t.Errorf("漏洞端口/协议错误: %d/%q", v.Port, v.Protocol)
	}
	if !strings.Contains(v.Title, "smb-vuln-ms17-010") || !strings.Contains(v.Title, "CVE-2017-0143") {
		t.Errorf("标题应包含规则 ID 与 CVE: %q", v.Title)
	}
	if !strings.Contains(v.Evidence, "VULNERABLE") {
		t.Errorf("证据应保留脚本原始输出: %q", v.Evidence)
	}
}

// DTD 与注释必须不影响解析(xml 标准库遇 DOCTYPE 会报错, 解析器需清洗后重试)
func TestParseNmapXMLWithDTD(t *testing.T) {
	data := `<!DOCTYPE nmaprun>
<!-- nmap 输出注释 -->
<nmaprun>
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports><port protocol="tcp" portid="80">
      <state state="open"/>
      <service name="http" product="nginx" version="1.21.0"/>
    </port></ports>
  </host>
</nmaprun>`
	b, err := ParseNmap([]byte(data))
	if err != nil {
		t.Fatalf("带 DTD/注释的 XML 解析失败: %v", err)
	}
	if len(b.SetupAssets) != 1 || b.SetupAssets[0].IP != "192.168.1.10" {
		t.Fatalf("主机资产解析错误: %+v", b.SetupAssets)
	}
	if b.SetupAssets[0].Version != "nginx 1.21.0" {
		t.Errorf("版本拼接错误: %q", b.SetupAssets[0].Version)
	}
}

// 损坏 XML: 返回错误但不 panic
func TestParseNmapXMLBroken(t *testing.T) {
	if _, err := ParseNmap([]byte(`<nmaprun><host><address addr="1.2.3.4"`)); err == nil {
		t.Fatal("残缺 XML 应返回错误")
	}
	if _, err := ParseNmap([]byte("   ")); err == nil {
		t.Fatal("空输出应返回错误")
	}
}

// JSON 分支复用归一化适配器
func TestParseNmapJSON(t *testing.T) {
	data := `{"hosts":[{"address":"10.1.1.1","ports":[
	  {"portid":443,"protocol":"tcp","state":{"state":"open"},"service":{"name":"https","product":"nginx","version":"1.24"}}
	]}]}`
	b, err := ParseNmap([]byte(data))
	if err != nil {
		t.Fatalf("解析 nmap JSON 失败: %v", err)
	}
	if len(b.Assets) != 1 || len(b.Assets[0].Ports) != 1 || b.Assets[0].Ports[0] != 443 {
		t.Fatalf("JSON 资产解析错误: %+v", b.Assets)
	}
}

// ===== Trivy 解析 =====

const trivySample = `{
  "SchemaVersion": 2,
  "ArtifactName": "nginx:1.21",
  "ArtifactType": "container_image",
  "Metadata": {"OS": {"Family": "debian", "Name": "11.6"}, "ImageConfig": {"architecture": "amd64"}},
  "Results": [
    {
      "Target": "nginx:1.21 (debian 11.6)",
      "Class": "os-pkgs",
      "Type": "debian",
      "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2021-3711", "PkgName": "libssl1.1", "InstalledVersion": "1.1.1k-1",
         "FixedVersion": "1.1.1k-1+deb11u1", "Severity": "CRITICAL", "Title": "OpenSSL SM2 buffer overflow",
         "Description": "SM2 decryption buffer overflow.", "PrimaryURL": "https://avd.aquasec.com/CVE-2021-3711",
         "Cvss": {"NVD": {"V3Score": 9.8}, "RedHat": {"V3Score": 9.8}}},
        {"VulnerabilityID": "CVE-2020-0001", "PkgName": "old-pkg", "InstalledVersion": "1.0",
         "Status": "fixed", "Severity": "HIGH", "Title": "已修复项应被过滤"}
      ],
      "Misconfigurations": [
        {"ID": "DS002", "AVDID": "AVD-DS-0002", "Title": "Image user should not be 'root'",
         "Description": "Running as root", "Resolution": "Add USER directive", "Severity": "HIGH",
         "CauseMetadata": {"Resource": "nginx:1.21", "StartLine": 3}}
      ],
      "Secrets": [
        {"RuleID": "aws-access-key-id", "Category": "AWS", "Severity": "CRITICAL",
         "Title": "AWS Access Key ID", "StartLine": 12, "Match": "AKIA...REDACTED"}
      ]
    }
  ]
}`

func TestParseTrivy(t *testing.T) {
	b, err := ParseTrivy([]byte(trivySample))
	if err != nil {
		t.Fatalf("解析 trivy 失败: %v", err)
	}
	if b.Source != normalizer.SourceTrivy {
		t.Fatalf("来源应为 trivy, 实际 %s", b.Source)
	}
	// 漏洞 = 1 个 CVE + 1 配置缺陷 + 1 凭据, fixed 项被过滤
	if len(b.Vulns) != 3 {
		t.Fatalf("应有 3 条结果(漏洞/配置/凭据), 实际 %d: %+v", len(b.Vulns), b.Vulns)
	}
	var cve, misconf, secret *normalizer.RawVuln
	for i := range b.Vulns {
		v := &b.Vulns[i]
		switch {
		case v.CVE != "":
			cve = v
		case strings.Contains(v.Title, "AVD-DS-0002"):
			misconf = v
		case strings.Contains(v.Title, "AWS"):
			secret = v
		}
	}
	if cve == nil {
		t.Fatal("未解析出 CVE 漏洞")
	}
	if cve.CVSS != 9.8 {
		t.Errorf("CVSS 应取最高分 9.8, 实际 %v", cve.CVSS)
	}
	if !strings.Contains(cve.Description, "升级 libssl1.1 到 1.1.1k-1+deb11u1") {
		t.Errorf("修复建议缺失: %q", cve.Description)
	}
	if cve.AssetIP != "nginx:1.21 (debian 11.6)" {
		t.Errorf("资产归属应为 Target, 实际 %q", cve.AssetIP)
	}
	if misconf == nil {
		t.Fatal("未解析出配置缺陷")
	}
	if !strings.Contains(misconf.Description, "Add USER directive") {
		t.Errorf("配置缺陷修复建议缺失: %q", misconf.Description)
	}
	if misconf.Severity != "HIGH" {
		t.Errorf("配置缺陷等级错误: %q", misconf.Severity)
	}
	if secret == nil {
		t.Fatal("未解析出泄露凭据")
	}
	// 凭据不得落原始密文
	if strings.Contains(secret.Description, "AKIA") || strings.Contains(secret.Evidence, "AKIA") {
		t.Errorf("凭据内容必须脱敏: %+v", secret)
	}
	// 资产: 工件 + Target
	if len(b.Assets) < 2 {
		t.Fatalf("应有工件与 Target 资产, 实际 %+v", b.Assets)
	}
	if b.Assets[0].IP != "nginx:1.21" {
		t.Errorf("首个资产应为工件名, 实际 %q", b.Assets[0].IP)
	}
	if b.Assets[0].OS != "debian 11.6" {
		t.Errorf("OS 提取错误: %q", b.Assets[0].OS)
	}
}

// Trivy 结构不符时降级宽松适配器, 不返回错误
func TestParseTrivyFallbackShape(t *testing.T) {
	// 顶层是数组(非预期结构) → 宽松适配器同样失败, 返回错误
	if _, err := ParseTrivy([]byte(`[]`)); err == nil {
		t.Fatal("非预期结构应返回错误")
	}
	// 标准结构但字段为旧格式 → 主解析器可处理
	b, err := ParseTrivy([]byte(`{"ArtifactName":"img:1","Results":[{"Target":"img:1","Vulnerabilities":[
	  {"VulnerabilityID":"CVE-2022-1234","PkgName":"p","InstalledVersion":"1","Severity":"HIGH","Title":"t"}]}]}`))
	if err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if len(b.Vulns) != 1 || b.Vulns[0].CVE != "CVE-2022-1234" {
		t.Fatalf("漏洞解析错误: %+v", b.Vulns)
	}
}

// ===== ZAP 解析 =====

const zapSample = `{
  "site": [{
    "name": "http://10.0.0.5:8080",
    "@name": "http://10.0.0.5:8080",
    "host": "10.0.0.5",
    "port": "8080",
    "ssl": false,
    "alerts": [{
      "pluginid": "40012",
      "alertRef": "40012",
      "name": "Cross Site Scripting (Reflected)",
      "riskcode": "3",
      "confidence": "High",
      "confidencecode": "3",
      "riskdesc": "High (High)",
      "desc": "Reflected XSS in parameter q.",
      "solution": "Encode user input.",
      "reference": "https://owasp.org/xss",
      "cweid": "79",
      "instances": [
        {"uri": "http://10.0.0.5:8080/search?q=%3Cscript%3E", "method": "GET",
         "param": "q", "attack": "<script>alert(1)</script>", "evidence": "<script>",
         "otherinfo": "Raised with payload 1"},
        {"uri": "http://10.0.0.5:8080/find?q=x", "method": "GET",
         "param": "q", "attack": "\"><img src=x>", "evidence": "img"}
      ]
    }, {
      "pluginid": "10021",
      "name": "X-Content-Type-Options Header Missing",
      "riskcode": "1",
      "confidencecode": "2",
      "riskdesc": "Low (Medium)",
      "desc": "Header missing.",
      "solution": "Set the header.",
      "instances": [{"uri": "http://10.0.0.5:8080/", "method": "GET"}]
    }]
  }]
}`

func TestParseZap(t *testing.T) {
	b, err := ParseZap([]byte(zapSample))
	if err != nil {
		t.Fatalf("解析 zap 失败: %v", err)
	}
	if b.Source != normalizer.SourceZAP {
		t.Fatalf("来源应为 zap, 实际 %s", b.Source)
	}
	if len(b.Assets) != 1 || b.Assets[0].IP != "10.0.0.5" || b.Assets[0].Ports[0] != 8080 {
		t.Fatalf("资产解析错误: %+v", b.Assets)
	}
	// 2 个实例 + 1 个高风险 + 1 个低风险 = 3 条
	if len(b.Vulns) != 3 {
		t.Fatalf("应有 3 条告警实例, 实际 %d: %+v", len(b.Vulns), b.Vulns)
	}
	var xss *normalizer.RawVuln
	for i := range b.Vulns {
		if strings.Contains(b.Vulns[i].Title, "Cross Site Scripting") {
			xss = &b.Vulns[i]
			break
		}
	}
	if xss == nil {
		t.Fatal("未解析出 XSS 告警")
	}
	if xss.Severity != models.SeverityHigh {
		t.Errorf("riskcode=3 应为 high, 实际 %q", xss.Severity)
	}
	if xss.Confidence != 60 {
		t.Errorf("confidencecode=3 → 60, 实际 %d", xss.Confidence)
	}
	if xss.Port != 8080 || xss.Protocol != "http" {
		t.Errorf("端口/协议错误: %d/%q", xss.Port, xss.Protocol)
	}
	if !strings.Contains(xss.Request, "GET http://10.0.0.5:8080/search") {
		t.Errorf("请求应含方法与完整 URL: %q", xss.Request)
	}
	if !strings.Contains(xss.Request, "参数: q") || !strings.Contains(xss.Request, "载荷:") {
		t.Errorf("请求应含参数与载荷: %q", xss.Request)
	}
	if xss.Evidence != "<script>" {
		t.Errorf("证据提取错误: %q", xss.Evidence)
	}
	if !strings.Contains(xss.Description, "CWE-79") {
		t.Errorf("描述应含 CWE 编号: %q", xss.Description)
	}
	if !strings.Contains(xss.Description, "修复建议: Encode user input.") {
		t.Errorf("描述应含修复建议: %q", xss.Description)
	}
}

// 平铺结构(无 instances)与 Report 包裹结构
func TestParseZapFlatAndWrapped(t *testing.T) {
	flat := `{"site":[{"name":"https://example.com","alerts":[{
	  "name":"SQL Injection","riskcode":3,"uri":"https://example.com/login","method":"POST",
	  "parameter":"user","attack":"' OR 1=1--","evidence":"SQL syntax error","solution":"Use parameters"
	}]}]}`
	b, err := ParseZap([]byte(flat))
	if err != nil {
		t.Fatalf("平铺结构解析失败: %v", err)
	}
	if len(b.Vulns) != 1 {
		t.Fatalf("应有 1 条告警, 实际 %d", len(b.Vulns))
	}
	if b.Vulns[0].Port != 443 || b.Vulns[0].Protocol != "https" {
		t.Errorf("默认端口/协议错误: %d/%q", b.Vulns[0].Port, b.Vulns[0].Protocol)
	}
	if !strings.Contains(b.Vulns[0].Request, "' OR 1=1--") {
		t.Errorf("载荷应进请求: %q", b.Vulns[0].Request)
	}

	wrapped := `{"Report":{"site":[{"name":"http://1.2.3.4","alerts":[{
	  "name":"Path Traversal","riskcode":2,"instances":[{"uri":"http://1.2.3.4/../../etc/passwd","method":"GET","param":"file"}]
	}]}]}}`
	b2, err := ParseZap([]byte(wrapped))
	if err != nil {
		t.Fatalf("Report 包裹结构解析失败: %v", err)
	}
	if len(b2.Vulns) != 1 || b2.Vulns[0].Severity != models.SeverityMedium {
		t.Fatalf("包裹结构解析错误: %+v", b2.Vulns)
	}
}

// 空报告: 返回错误而非 panic
func TestParseZapEmpty(t *testing.T) {
	if _, err := ParseZap([]byte(``)); err == nil {
		t.Fatal("空输入应返回错误")
	}
	if _, err := ParseZap([]byte(`{"site":[]}`)); err == nil {
		t.Fatal("无站点应返回错误")
	}
}

// ===== 统一入口 =====

func TestParseDispatch(t *testing.T) {
	if _, err := Parse("nmap", []byte(nmapXMLSample)); err != nil {
		t.Errorf("nmap 分发失败: %v", err)
	}
	if _, err := Parse("trivycore", []byte(trivySample)); err != nil {
		t.Errorf("trivy 分发失败: %v", err)
	}
	if _, err := Parse("zapcore", []byte(zapSample)); err != nil {
		t.Errorf("zap 分发失败: %v", err)
	}
	if _, err := Parse("unknown", []byte("{}")); err == nil {
		t.Error("未知引擎应返回错误")
	}
}
