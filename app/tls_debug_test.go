package main

import (
	"crypto/x509"
	"testing"
)

// 调试: 确认即时签发各函数的真实 SAN 产出(不连 TCP, 纯逻辑)。
// 目的: 定位为何运行时浏览器抓到的是无 IP 的 fallback 证书。
func TestDebugIssueCerts(t *testing.T) {
	dir := `E:\project\Yugsight\dist\data\cert`
	if err := loadCertAssets(dir+`\server.pem`, dir+`\server-key.pem`); err != nil {
		t.Fatalf("loadCertAssets 失败: %v", err)
	}

	c1, err1 := issueCertForAllLocal()
	if err1 != nil {
		t.Logf("issueCertForAllLocal 失败: %v", err1)
	} else if x1, e := x509.ParseCertificate(c1.Certificate[0]); e == nil {
		t.Logf("issueCertForAllLocal => DNS=%v IP=%v", x1.DNSNames, x1.IPAddresses)
	}

	c2, err2 := issueCertForHost("192.168.1.143")
	if err2 != nil {
		t.Logf("issueCertForHost(192.168.1.143) 失败: %v", err2)
	} else if x2, e := x509.ParseCertificate(c2.Certificate[0]); e == nil {
		t.Logf("issueCertForHost(192.168.1.143) => DNS=%v IP=%v", x2.DNSNames, x2.IPAddresses)
	}

	// certSANs 直接输出(含 127.0.0.1 与本机 IP)
	dns, ips := certSANs()
	t.Logf("certSANs => DNS=%v IP=%v", dns, ips)
}
