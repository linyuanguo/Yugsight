package scanner

import (
	"strings"
	"testing"
)

// ===== EOL(停止支持)检测 =====

func TestMatchEOL(t *testing.T) {
	cases := []struct {
		product, version string
		want             bool
		high             bool
	}{
		// IIS -> Windows 停补(确定性映射)
		{"iis", "6.0", true, true},
		{"iis", "7.0", true, true},
		{"iis", "7.5", true, true},
		{"iis", "8.0", true, false},
		{"iis", "8.5", true, false},
		{"iis", "10.0", false, false},
		// Web 服务器
		{"apache", "2.2.34", true, true},
		{"apache", "2.4.58", false, false},
		{"nginx", "0.6.15", true, true},
		{"nginx", "1.18.0", false, false},
		{"tomcat", "7.0.109", true, false},
		{"tomcat", "8.0.53", true, false},
		{"tomcat", "8.5.88", false, false},
		{"tomcat", "9.0.85", false, false},
		// PHP
		{"php", "5.6.40", true, true},
		{"php", "7.4.33", true, false},
		{"php", "8.2.15", false, false},
		// 数据库
		{"mysql", "5.6.51", true, false},
		{"mysql", "5.7.44", true, false},
		{"mysql", "8.0.35", false, false},
		{"mongodb", "3.6.20", true, false},
		{"mongodb", "4.4.20", false, false},
		{"elasticsearch", "6.8.23", true, false},
		{"elasticsearch", "7.6.2", true, false},
		{"elasticsearch", "7.17.0", false, false},
		// 其它
		{"jetty", "8.1.14", true, false},
		{"jetty", "9.4.48", false, false},
		// 未知产品 / 空版本: 不命中
		{"unknown", "1.0", false, false},
		{"nginx", "", false, false},
	}
	for _, c := range cases {
		got := matchEOL(c.product, c.version)
		if (got != nil) != c.want {
			t.Errorf("matchEOL(%q, %q) 命中=%v, 期望 %v (%+v)", c.product, c.version, got != nil, c.want, got)
		}
		if got != nil && got.High != c.high {
			t.Errorf("matchEOL(%q, %q) High=%v, 期望 %v", c.product, c.version, got.High, c.high)
		}
	}
}

func TestIISVersionFromBanners(t *testing.T) {
	cases := []struct {
		banners []string
		want    string
	}{
		{[]string{"Server: Microsoft-IIS/10.0\r\n"}, "10.0"},
		{[]string{"Date: Mon, 1 Jan 2026\r\n", "Server: Microsoft-IIS/7.5\r\nX-Powered-By: ASP.NET\r\n"}, "7.5"},
		{[]string{"Server: nginx/1.18.0\r\n"}, ""},
		{[]string{}, ""},
		{[]string{"Server: Microsoft-IIS/\r\n"}, ""},
	}
	for i, c := range cases {
		if got := iisVersionFromBanners(c.banners); got != c.want {
			t.Errorf("case %d: iisVersionFromBanners = %q, 期望 %q", i, got, c.want)
		}
	}
}

// ===== 主动验证探测的纯函数部分 =====

func TestParseMemcachedVersion(t *testing.T) {
	cases := []struct {
		resp, want string
	}{
		{"VERSION 1.5.6\r\n", "1.5.6"},
		{"VERSION 1.4.4\r\n", "1.4.4"},
		{"ERROR\r\n", ""},
		{"", ""},
		{"version 1.6.25\n", "1.6.25"},
	}
	for i, c := range cases {
		if got := parseMemcachedVersion(c.resp); got != c.want {
			t.Errorf("case %d: parseMemcachedVersion(%q) = %q, 期望 %q", i, c.resp, got, c.want)
		}
	}
}

func TestParseRedisVersion(t *testing.T) {
	info := "redis_version:6.2.6\r\nredis_git_sha1:00000000\r\nredis_mode:standalone\r\n"
	if got := parseRedisVersion(info); got != "6.2.6" {
		t.Errorf("parseRedisVersion = %q, 期望 6.2.6", got)
	}
	if got := parseRedisVersion("NOAUTH Authentication required.\r\n"); got != "" {
		t.Errorf("已设密码的响应不应解析出版本: %q", got)
	}
}

func TestSMB1DialectIn(t *testing.T) {
	// 模拟 SMB1 negotiate 响应: 方言段含 "NT LM 0.12"
	resp := []byte{0x00, 0x00, 0x00, 0x54, 0xFF, 0x53, 0x4D, 0x42, 0x72}
	resp = append(resp, []byte("lanman1.0\x00NT LM 0.12\x00")...)
	if !smb1DialectIn(resp) {
		t.Error("含 NT LM 0.12 方言应判定 SMBv1 启用")
	}
	// SMB2/3 negotiate 响应: Dialect 0x0202/0x0302, 无该字符串
	resp2 := []byte{0x00, 0x00, 0x00, 0x25, 0xFE, 0x53, 0x4D, 0x42}
	resp2 = append(resp2, []byte{0x02, 0x02, 0x03, 0x02}...)
	if smb1DialectIn(resp2) {
		t.Error("SMB2/3 响应不应误判为 SMBv1")
	}
	if smb1DialectIn(nil) || smb1DialectIn([]byte("SMB")) {
		t.Error("空/短响应不应误判")
	}
}

func TestVersionMajorMinor(t *testing.T) {
	cases := []struct {
		v           string
		major, minor int
		ok          bool
	}{
		{"10.0", 10, 0, true},
		{"2.4.49", 2, 4, true}, // major.minor = 前两段(版本线), 2.4.49 属于 2.4 线
		{"7", 7, 0, true},
		{"1.25.3", 1, 25, true},
		{"", 0, 0, false},
		{"abc", 0, 0, false},
		{"1.x", 1, 0, true}, // 次段非数字按 0(不 panic)
	}
	for i, c := range cases {
		ma, mi, ok := versionMajorMinor(c.v)
		if ok != c.ok || ma != c.major || mi != c.minor {
			t.Errorf("case %d: versionMajorMinor(%q) = (%d,%d,%v), 期望 (%d,%d,%v)", i, c.v, ma, mi, ok, c.major, c.minor, c.ok)
		}
	}
}

// TestEOLFindingText EOL 提示文案关键信息齐全(用户要能直接读懂"为什么是风险")
func TestEOLFindingText(t *testing.T) {
	e := matchEOL("apache", "2.2.34")
	if e == nil {
		t.Fatal("apache 2.2.34 应命中 EOL")
	}
	for _, kw := range []string{"停止支持", "2020-07-01", "补丁"} {
		if !strings.Contains(e.Label+e.Note, kw) {
			t.Errorf("EOL 文案缺少关键信息 %q: %s | %s", kw, e.Label, e.Note)
		}
	}
}
