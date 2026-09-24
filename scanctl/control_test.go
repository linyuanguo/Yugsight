//go:build !windows || windows

package scanctl

import (
	"path/filepath"
	"testing"

	"yugsight/models"
)

func ctlTestEnv(t *testing.T) *Controller {
	t.Helper()
	c, err := NewController(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestControllerFilterVulns 门面: 误报自动标记 + 白名单过滤
func TestControllerFilterVulns(t *testing.T) {
	c := ctlTestEnv(t)
	// 无任何条目: 零行为
	vs := []*models.Vuln{{AssetIP: "10.0.0.1", CVE: "CVE-1", Title: "a"}}
	kept, filtered, fp := c.FilterVulns(nil, vs)
	if len(kept) != 1 || len(filtered) != 0 || fp != 0 {
		t.Fatalf("无条目应零行为: kept=%d filtered=%d fp=%d", len(kept), len(filtered), fp)
	}

	// 配置: 误报规则 + 白名单条目
	if _, err := c.FPS().Mark("10.0.0.1", "CVE-1", "", "误报", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Whitelist().Add(WhitelistEntry{Type: WLTypeIP, Match: "10.0.0.2"}); err != nil {
		t.Fatal(err)
	}

	vulns := []*models.Vuln{
		{AssetIP: "10.0.0.1", CVE: "CVE-1", Title: "a"},  // 误报命中
		{AssetIP: "10.0.0.2", CVE: "CVE-2", Title: "b"},  // 白名单命中
		{AssetIP: "10.0.0.3", CVE: "CVE-3", Title: "c"},  // 保留
	}
	assets := []*models.Asset{
		{ID: "a1", IP: "10.0.0.1"},
		{ID: "a2", IP: "10.0.0.2"},
		{ID: "a3", IP: "10.0.0.3"},
	}
	kept, filtered, fp = c.FilterVulns(assets, vulns)
	if fp != 1 {
		t.Fatalf("误报标记数 = %d, want 1", fp)
	}
	if len(kept) != 2 || len(filtered) != 1 {
		t.Fatalf("kept=%d filtered=%d, want 2/1", len(kept), len(filtered))
	}
	if !vulns[0].FalsePositive || vulns[0].FPNote != "误报" {
		t.Fatalf("误报标记错误: %+v", vulns[0])
	}
	if filtered[0].AssetIP != "10.0.0.2" {
		t.Fatalf("白名单过滤项错误: %+v", filtered[0])
	}
}

// TestControllerCheckFinding 门面: 管线 finding 逐条判定
func TestControllerCheckFinding(t *testing.T) {
	c := ctlTestEnv(t)
	if _, err := c.Whitelist().Add(WhitelistEntry{Type: WLTypeCIDR, Match: "192.168.9.0/24"}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.FPS().Mark("10.0.0.7", "CVE-777", "", "备注", "op"); err != nil {
		t.Fatal(err)
	}

	// 白名单命中
	wlHit, e, _ := c.CheckFinding("192.168.9.55", 80, "", "任意")
	if !wlHit || e.Match != "192.168.9.0/24" {
		t.Fatalf("白名单应命中: %v %+v", wlHit, e)
	}
	// 误报命中
	_, _, r := c.CheckFinding("10.0.0.7", 443, "cve-777", "任意")
	if r.ID == "" || r.Note != "备注" {
		t.Fatalf("误报应命中: %+v", r)
	}
	// 都不命中
	wlHit2, _, r2 := c.CheckFinding("10.9.9.9", 80, "", "x")
	if wlHit2 || r2.ID != "" {
		t.Fatalf("不应命中: %v %+v", wlHit2, r2)
	}
}

// TestControllerStatus 状态接口
func TestControllerStatus(t *testing.T) {
	c := ctlTestEnv(t)
	st := c.StatusOf()
	if st.Enabled || st.WhitelistCount != 0 || st.FPSCount != 0 {
		t.Fatalf("空门面状态错误: %+v", st)
	}
	if len(st.Scoring.Tiers) != 4 {
		t.Fatalf("打分模型应 4 级: %+v", st.Scoring)
	}
	if _, err := c.FPS().Mark("10.0.0.1", "CVE-1", "", "", ""); err != nil {
		t.Fatal(err)
	}
	if !c.StatusOf().Enabled {
		t.Fatal("有条目后应 enabled")
	}
}

// TestControllerFilePersist 门面默认目录持久化(whitelist.jsonl / fps.jsonl)
func TestControllerFilePersist(t *testing.T) {
	dir := t.TempDir()
	c1, err := NewController(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = c1.Whitelist().Add(WhitelistEntry{Type: WLTypePort, Match: "8080"})
	_, _ = c1.FPS().Mark("10.0.0.1", "CVE-1", "", "n", "")

	c2, err := NewController(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Whitelist().Count() != 1 || c2.FPS().Count() != 1 {
		t.Fatalf("重载失败: wl=%d fps=%d", c2.Whitelist().Count(), c2.FPS().Count())
	}
	_ = filepath.Join(dir, "whitelist.jsonl") // 路径约定(存在性由上面行为保证)
}
