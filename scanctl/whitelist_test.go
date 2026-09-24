//go:build !windows || windows

package scanctl

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"yugsight/models"
)

func wlTestEnv(t *testing.T) *Whitelist {
	t.Helper()
	dir := t.TempDir()
	d, err := NewFileDAO[WhitelistEntry](filepath.Join(dir, "wl.jsonl"), func() WhitelistEntry { return WhitelistEntry{} })
	if err != nil {
		t.Fatal(err)
	}
	w, err := NewWhitelist(d)
	if err != nil {
		t.Fatal(err)
	}
	return w
}

func wlAsset(ip string, tags ...string) *models.Asset {
	return &models.Asset{ID: "x", IP: models.NormIP(ip), Tags: tags}
}

func wlVuln(ip string, port int, cve, title string) *models.Vuln {
	return &models.Vuln{AssetIP: models.NormIP(ip), Port: port, CVE: models.NormalizeCVE(cve), Title: title}
}

// TestWhitelistFiveTypes 五种类型匹配: IP / IP段 / 端口 / CVE / 资产标签
func TestWhitelistFiveTypes(t *testing.T) {
	w := wlTestEnv(t)
	mustAdd := func(e WhitelistEntry) {
		t.Helper()
		if _, err := w.Add(e); err != nil {
			t.Fatalf("Add %s/%s: %s", e.Type, e.Match, err)
		}
	}
	mustAdd(WhitelistEntry{Type: WLTypeIP, Match: "10.0.0.1"})
	mustAdd(WhitelistEntry{Type: WLTypeCIDR, Match: "192.168.1.0/24"})
	mustAdd(WhitelistEntry{Type: WLTypePort, Match: "6379"})
	mustAdd(WhitelistEntry{Type: WLTypeCVE, Match: "cve-2021-44228"}) // 小写, 应归一化
	mustAdd(WhitelistEntry{Type: WLTypeTag, Match: "PROD"})          // 大写, 应不区分大小写

	cases := []struct {
		name    string
		a       *models.Asset
		v       *models.Vuln
		wantHit bool
	}{
		{"精确 IP 命中", wlAsset("10.0.0.1"), wlVuln("10.0.0.1", 80, "", "x"), true},
		{"精确 IP 未命中", wlAsset("10.0.0.2"), wlVuln("10.0.0.2", 80, "", "x"), false},
		{"IP 段命中", wlAsset("192.168.1.77"), wlVuln("192.168.1.77", 80, "", "x"), true},
		{"IP 段未命中", wlAsset("192.168.2.1"), wlVuln("192.168.2.1", 80, "", "x"), false},
		{"端口命中", wlAsset("10.9.9.9"), wlVuln("10.9.9.9", 6379, "", "x"), true},
		{"端口未命中", wlAsset("10.9.9.9"), wlVuln("10.9.9.9", 80, "", "x"), false},
		{"CVE 命中(大小写)", wlAsset("10.8.8.8"), wlVuln("10.8.8.8", 80, "CVE-2021-44228", "x"), true},
		{"CVE 未命中", wlAsset("10.8.8.8"), wlVuln("10.8.8.8", 80, "CVE-2021-44229", "x"), false},
		{"资产标签命中(大小写)", wlAsset("10.7.7.7", "prod"), wlVuln("10.7.7.7", 80, "", "x"), true},
		{"资产标签未命中", wlAsset("10.7.7.7", "dev"), wlVuln("10.7.7.7", 80, "", "x"), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hit, _ := w.Match(c.a, c.v)
			if hit != c.wantHit {
				t.Fatalf("hit = %v, want %v", hit, c.wantHit)
			}
		})
	}
}

// TestWhitelistDisabled 默认关闭: Add 前恒不命中
func TestWhitelistDisabled(t *testing.T) {
	w := wlTestEnv(t)
	if w.Enabled() {
		t.Fatal("新建白名单应默认关闭")
	}
	if hit, _ := w.Match(wlAsset("10.0.0.1"), wlVuln("10.0.0.1", 80, "", "x")); hit {
		t.Fatal("关闭时不应命中")
	}
	if _, err := w.Add(WhitelistEntry{Type: WLTypeIP, Match: "10.0.0.1"}); err != nil {
		t.Fatal(err)
	}
	if !w.Enabled() {
		t.Fatal("Add 后应自动开启")
	}
	if hit, _ := w.Match(wlAsset("10.0.0.1"), wlVuln("10.0.0.1", 80, "", "x")); !hit {
		t.Fatal("开启后应命中")
	}
	w.SetEnabled(false)
	if hit, _ := w.Match(wlAsset("10.0.0.1"), wlVuln("10.0.0.1", 80, "", "x")); hit {
		t.Fatal("强制关闭后不应命中")
	}
}

// TestWhitelistExpiry 过期条目自动失效
func TestWhitelistExpiry(t *testing.T) {
	w := wlTestEnv(t)
	if _, err := w.Add(WhitelistEntry{Type: WLTypeIP, Match: "10.0.0.9", ExpiresAt: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if hit, _ := w.Match(wlAsset("10.0.0.9"), wlVuln("10.0.0.9", 80, "", "x")); hit {
		t.Fatal("过期条目不应命中")
	}
}

// TestWhitelistValidate 非法条目拒绝
func TestWhitelistValidate(t *testing.T) {
	w := wlTestEnv(t)
	bad := []WhitelistEntry{
		{Type: "weird", Match: "x"},
		{Type: WLTypeCIDR, Match: "not-a-cidr"},
		{Type: WLTypePort, Match: "99999"},
		{Type: WLTypeIP, Match: "  "},
	}
	for i, e := range bad {
		if _, err := w.Add(e); err == nil {
			t.Errorf("case %d 应拒绝: %+v", i, e)
		}
	}
	if w.Count() != 0 {
		t.Fatal("非法条目不应落盘")
	}
}

// TestWhitelistFilterAndRemove 批量过滤 + 删除
func TestWhitelistFilterAndRemove(t *testing.T) {
	w := wlTestEnv(t)
	if _, err := w.Add(WhitelistEntry{Type: WLTypeCVE, Match: "CVE-2021-44228"}); err != nil {
		t.Fatal(err)
	}
	vulns := []*models.Vuln{
		wlVuln("10.0.0.1", 80, "CVE-2021-44228", "A"),
		wlVuln("10.0.0.2", 80, "CVE-2021-44229", "B"),
	}
	kept, filtered := w.Filter(nil, vulns)
	if len(kept) != 1 || len(filtered) != 1 {
		t.Fatalf("kept=%d filtered=%d, want 1/1", len(kept), len(filtered))
	}
	if kept[0].CVE != "CVE-2021-44229" {
		t.Fatalf("保留项错误: %s", kept[0].CVE)
	}
	// 删除: 条目 ID = wl-cve-CVE-2021-44228
	if ok, err := w.Remove("wl-cve-CVE-2021-44228"); err != nil || !ok {
		t.Fatalf("删除失败: %v %v", ok, err)
	}
	if w.Count() != 0 {
		t.Fatal("删除后应为空")
	}
}

// TestWhitelistPersist 持久化: 重新加载后条目仍在且自动开启
func TestWhitelistPersist(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wl.jsonl")
	d1, _ := NewFileDAO[WhitelistEntry](p, func() WhitelistEntry { return WhitelistEntry{} })
	w1, _ := NewWhitelist(d1)
	if _, err := w1.Add(WhitelistEntry{Type: WLTypeCIDR, Match: "172.16.0.0/12", Reason: "测试网段"}); err != nil {
		t.Fatal(err)
	}
	// 重新加载
	d2, err := NewFileDAO[WhitelistEntry](p, func() WhitelistEntry { return WhitelistEntry{} })
	if err != nil {
		t.Fatal(err)
	}
	w2, _ := NewWhitelist(d2)
	if w2.Count() != 1 {
		t.Fatalf("重载后条目数 = %d, want 1", w2.Count())
	}
	if !w2.Enabled() {
		t.Fatal("存量条目应自动开启")
	}
	hit, e := w2.Match(wlAsset("172.16.5.5"), wlVuln("172.16.5.5", 443, "", "x"))
	if !hit || e.Reason != "测试网段" {
		t.Fatalf("重载后匹配失败: hit=%v entry=%+v", hit, e)
	}
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("文件应存在: %s", err)
	}
}

// TestWhitelistCorruptLine 坏行降级: 跳过坏行不报错
func TestWhitelistCorruptLine(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "wl.jsonl")
	// 直接写"坏行 + 好行"文件, 验证降级
	if err := os.WriteFile(p, []byte("not-json\n"+`{"id":"wl-ip-10.0.0.1","type":"ip","match":"10.0.0.1","enabled":true}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := NewFileDAO[WhitelistEntry](p, func() WhitelistEntry { return WhitelistEntry{} })
	if err != nil {
		t.Fatalf("含坏行应降级不报错: %s", err)
	}
	w, _ := NewWhitelist(d)
	if w.Count() != 1 {
		t.Fatalf("应跳过坏行保留 1 条, got %d", w.Count())
	}
}
