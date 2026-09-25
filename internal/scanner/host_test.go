package scanner

import (
	"context"
	"strings"
	"testing"
	"time"
)

// 主机扫描的关键辅助函数单测(不依赖外网, 沙箱可跑)

func TestVersionFromBanner(t *testing.T) {
	cases := []struct{ in, want string }{
		{"Server: nginx/1.18.0", "nginx 1.18.0"},
		{"Apache/2.4.41 (Ubuntu)", "Apache 2.4.41"},
		{"SSH-2.0-OpenSSH_8.2p1 Ubuntu", "OpenSSH 8.2"},
		{"Server: Microsoft-IIS/10.0", "IIS 10.0"},
		{"no version here", ""},
	}
	for _, c := range cases {
		if got := versionFromBanner(c.in); got != c.want {
			t.Errorf("versionFromBanner(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

func TestGuessOS(t *testing.T) {
	cases := []struct {
		banners []string
		ports   []int
		want    string
	}{
		{[]string{"Server: Microsoft-IIS/10.0"}, []int{80, 445}, "Windows"},
		{[]string{"SSH-2.0-OpenSSH_8.2p1 Ubuntu"}, []int{22}, "Linux (Ubuntu)"},
		{[]string{"SSH-2.0-OpenSSH_8.2p1"}, []int{22}, "Linux / Unix (OpenSSH)"},
		{nil, []int{135, 139, 445, 3389}, "Windows"},
		{nil, []int{22}, "Linux / Unix"},
		{nil, []int{9999}, "未知"},
	}
	for _, c := range cases {
		got, _ := guessOS(c.banners, c.ports)
		if got != c.want {
			t.Errorf("guessOS(%v, %v) = %q, 期望 %q", c.banners, c.ports, got, c.want)
		}
	}
}

// TestHostScanNoOpenPorts 无开放端口时: 不报端口行, 明确说明"未发现开放端口"
func TestHostScanNoOpenPorts(t *testing.T) {
	var kinds []string
	var findings []Finding
	emit := func(kind string, data any) {
		kinds = append(kinds, kind)
		if kind == "finding" {
			if f, ok := data.(Finding); ok {
				findings = append(findings, f)
			}
		}
	}
	// 127.0.0.1 上选一个几乎不可能开放的端口段
	HostScan(context.Background(), "127.0.0.1", []int{1, 2}, 300*time.Millisecond, 4, emit)

	for _, k := range kinds {
		if k == "port" {
			t.Error("主机扫描不应输出 port 行(端口清单属端口扫描职责)")
		}
	}
	found := false
	for _, f := range findings {
		if strings.Contains(f.Title, "未发现开放端口") {
			found = true
		}
	}
	if !found {
		t.Errorf("无开放端口时应给出明确提示, 实际 findings=%+v", findings)
	}
}

// TestComponentRulesCoverage 已知漏洞规则必须能用横幅文本命中
func TestComponentRulesCoverage(t *testing.T) {
	// Apache 2.4.49 -> 应命中 CVE-2021-41773 规则
	banner := "apache/2.4.49"
	hit := false
	for _, vr := range componentVulnRules {
		if strings.Contains(banner, vr.contains) {
			for _, bv := range vr.badVersions {
				if strings.Contains(banner, bv) {
					hit = true
				}
			}
		}
	}
	if !hit {
		t.Error("apache/2.4.49 应命中已知漏洞规则(CVE-2021-41773)")
	}

	// 新版本不应误报
	banner = "apache/2.4.58"
	for _, vr := range componentVulnRules {
		if strings.Contains(banner, vr.contains) {
			for _, bv := range vr.badVersions {
				if strings.Contains(banner, bv) {
					t.Errorf("apache/2.4.58 被误报为 %s", bv)
				}
			}
		}
	}
}

func TestExtractSMBName(t *testing.T) {
	// 构造含机器名的 SMB 响应片段
	buf := make([]byte, 80)
	copy(buf[40:], []byte("WIN-DEV01\x00"))
	if got := extractSMBName(buf); got != "WIN-DEV01" {
		t.Errorf("extractSMBName = %q, 期望 WIN-DEV01", got)
	}
	if got := extractSMBName([]byte("SMB\x00\x00")); got != "" {
		t.Errorf("协议关键字不应被当成主机名, 得到 %q", got)
	}
}

// TestIsWebPort Web 端口判定(与主动探测/模板执行的端口集合一致)
func TestIsWebPort(t *testing.T) {
	for _, p := range []int{80, 443, 8080, 8443, 8000, 8888, 9000, 3000} {
		if !IsWebPort(p) {
			t.Errorf("端口 %d 应判定为 Web 端口", p)
		}
	}
	for _, p := range []int{22, 3389, 445, 6379, 3306, 2375} {
		if IsWebPort(p) {
			t.Errorf("端口 %d 不应判定为 Web 端口", p)
		}
	}
}
