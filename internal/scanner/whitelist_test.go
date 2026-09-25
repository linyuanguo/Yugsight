package scanner

import (
	"os"
	"testing"
	"time"
)

// wlTestSettingsPath 当前用例使用的 settings.json 路径(夹具记录, 供断言持久化落点)。
//
// 红线「配置唯一」(2026-09-23 整改): 白名单不再落 whitelist.json, 而是
// settings.json 的 whitelist 节 —— 夹具与断言都要跟着改, 否则测试断言的
// 是一个"产品不应该再产生的文件"。
var wlTestSettingsPath string

// setupWhitelist 白名单测试夹具: 隔离全局状态并把配置指向临时目录。
//
// 为什么必须隔离: wlEntries / wlOn 是包级全局, 用例之间会互相污染(单跑通过、
// 全量跑失败); 配置路径也必须改指临时目录, 否则会写坏开发机配置。
func setupWhitelist(t *testing.T) {
	t.Helper()
	tmp := t.TempDir()
	oldFile := whitelistFile
	var oldEntries []WhitelistEntry
	oldOn := false
	wlMu.Lock()
	oldEntries, oldOn = wlEntries, wlOn
	wlEntries, wlOn = nil, false
	wlMu.Unlock()
	wlTestSettingsPath = tmp + "/settings.json"
	SetWhitelistSettingsPath(wlTestSettingsPath)
	whitelistFile = tmp + "/whitelist.json"
	t.Cleanup(func() {
		SetWhitelistSettingsPath("")
		whitelistFile = oldFile
		wlMu.Lock()
		wlEntries, wlOn = oldEntries, oldOn
		wlMu.Unlock()
	})
}

// wlVuln 构造用于白名单判定的漏洞样本。
func wlVuln(cve, ruleID, ip string, port int, title string) *Vulnerability {
	return &Vulnerability{
		CVE:    cve,
		RuleID: ruleID,
		Title:  title,
		Asset:  Asset{IP: ip},
		AssetID: ip,
		FoundAt: time.Now(),
	}
}

// TestWhitelistAddMatchRemove 白名单核心契约: 新增 -> 判定命中 -> 持久化 ->
// 重新加载仍然生效 -> 移除后不再命中。
func TestWhitelistAddMatchRemove(t *testing.T) {
	setupWhitelist(t)
	if WhitelistEnabled() {
		t.Fatal("白名单开关应默认关闭")
	}
	e, err := AddWhitelistEntry(WhitelistEntry{Type: "cve", Match: "CVE-2021-44228", Reason: "测试排除"})
	if err != nil {
		t.Fatal(err)
	}
	if !WhitelistEnabled() {
		t.Fatal("新增条目应自动开启开关")
	}
	if e.ID == "" || e.Created.IsZero() {
		t.Fatalf("条目 ID/Created 应自动补全: %+v", e)
	}
	// 命中
	if hit, _ := IsWhitelisted(wlVuln("CVE-2021-44228", "", "10.0.0.1", 80, "x")); !hit {
		t.Fatal("同 CVE 应命中白名单")
	}
	// 不命中
	if hit, _ := IsWhitelisted(wlVuln("CVE-2021-44229", "", "10.0.0.1", 80, "x")); hit {
		t.Fatal("不同 CVE 不应命中")
	}
	// 持久化 + 重新加载(落点必须是 settings.json)
	if _, err := os.Stat(wlTestSettingsPath); err != nil {
		t.Fatal("白名单应已持久化到 settings.json")
	}
	wlMu.Lock()
	wlEntries = nil
	wlMu.Unlock()
	n, err := LoadWhitelist()
	if err != nil || n != 1 {
		t.Fatalf("重新加载应得到 1 条: n=%d err=%v", n, err)
	}
	if hit, _ := IsWhitelisted(wlVuln("CVE-2021-44228", "", "10.0.0.1", 80, "x")); !hit {
		t.Fatal("重载后仍应命中")
	}
	// 移除
	ok, err := RemoveWhitelistEntry(e.ID)
	if err != nil || !ok {
		t.Fatalf("移除失败: ok=%v err=%v", ok, err)
	}
	if hit, _ := IsWhitelisted(wlVuln("CVE-2021-44228", "", "10.0.0.1", 80, "x")); hit {
		t.Fatal("移除后不应命中")
	}
}

// TestWhitelistTypes 五类匹配口径: cve / rule / host / port / title。
func TestWhitelistTypes(t *testing.T) {
	setupWhitelist(t)
	cases := []struct {
		entry WhitelistEntry
		vuln  *Vulnerability
		want  bool
	}{
		{WhitelistEntry{Type: "cve", Match: "CVE-2021-44228"}, wlVuln("CVE-2021-44228", "", "10.0.0.1", 80, "t"), true},
		{WhitelistEntry{Type: "rule", Match: "yugsight-0001"}, wlVuln("", "yugsight-0001", "10.0.0.1", 80, "t"), true},
		{WhitelistEntry{Type: "host", Match: "10.0.0.1"}, wlVuln("CVE-9", "", "10.0.0.1", 80, "t"), true},
		{WhitelistEntry{Type: "host", Match: "10.0.0.2"}, wlVuln("CVE-9", "", "10.0.0.1", 80, "t"), false},
		{WhitelistEntry{Type: "title", Match: "测试标题"}, wlVuln("CVE-9", "", "10.0.0.3", 80, "测试标题"), true},
	}
	for i, c := range cases {
		wlMu.Lock()
		wlEntries = nil
		wlMu.Unlock()
		if _, err := AddWhitelistEntry(c.entry); err != nil {
			t.Fatalf("用例 %d 新增失败: %v", i, err)
		}
		if hit, _ := IsWhitelisted(c.vuln); hit != c.want {
			t.Fatalf("用例 %d 命中=%v 期望 %v", i, hit, c.want)
		}
	}
}

// TestWhitelistExpired 过期条目失效(有效期是白名单的"临时放行"语义)。
func TestWhitelistExpired(t *testing.T) {
	setupWhitelist(t)
	if _, err := AddWhitelistEntry(WhitelistEntry{
		Type: "cve", Match: "CVE-2020-1", Expires: time.Now().Add(-time.Hour),
	}); err != nil {
		t.Fatal(err)
	}
	if hit, _ := IsWhitelisted(wlVuln("CVE-2020-1", "", "10.0.0.1", 80, "t")); hit {
		t.Fatal("已过期条目不应命中")
	}
}

// TestWhitelistDisabled 总开关关闭时一律不命中(默认关闭 = 零行为变化)。
func TestWhitelistDisabled(t *testing.T) {
	setupWhitelist(t)
	if _, err := AddWhitelistEntry(WhitelistEntry{Type: "cve", Match: "CVE-2020-2"}); err != nil {
		t.Fatal(err)
	}
	SetWhitelistEnabled(false)
	if hit, _ := IsWhitelisted(wlVuln("CVE-2020-2", "", "10.0.0.1", 80, "t")); hit {
		t.Fatal("开关关闭时不应命中")
	}
}

// TestWhitelistUnknownType 未知类型必须拒绝(静默接受会让"白名单配了却不生效")。
func TestWhitelistUnknownType(t *testing.T) {
	setupWhitelist(t)
	if _, err := AddWhitelistEntry(WhitelistEntry{Type: "weird", Match: "x"}); err == nil {
		t.Fatal("未知类型应报错")
	}
	if _, err := AddWhitelistEntry(WhitelistEntry{Type: "cve", Match: ""}); err == nil {
		t.Fatal("空匹配值应报错")
	}
}
