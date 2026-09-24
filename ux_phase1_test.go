package main

// ux_phase1_test.go 第一步功能审计 P0 改动的契约测试(2026-09-20)。
//
// 只写"被改坏会静默失效"的契约, 不复述实现细节(测试规则 9):
//  1. 存活判定回写资产 Alive —— 大屏"在线资产"与资产页 Alive 列的唯一数据源,
//     收集链断掉时页面不报错, 只会永远显示 0(审计 §2-3 的原故障形态);
//  2. 漏洞状态"开放"筛选口径 —— 库内 new/duplicate/open 三个细态必须全部
//     命中"开放", 漏一个前端选"开放"就少数据;
//  3. 已修复漏洞再次命中回退 open —— 修复未生效的漏洞若停在 fixed,
//     与事实相反(重新扫出来却显示"已修复");
//  4. 探针一键开启 —— 保留用户已有 listen/token、缺省补齐、落盘 settings.json。

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"yugsight/db"
	"yugsight/models"
)

// TestScanSinkAliveWriteback 存活判定 + 开放端口经事件流回写资产表。
//
// 守的判据:
//   - excludedByStrict(严格模式仅端口推断)不算存活, 但端口仍入账;
//   - "存活但无开放端口"的主机也要生成最小资产(大屏 assetsAlive 依赖它);
//   - closed 端口不入资产。
func TestScanSinkAliveWriteback(t *testing.T) {
	_, d := newV2TestEnv(t)
	sink := newScanSink(scanReq{Type: "unified"}, "", 0)
	sink.observe("ip", map[string]any{"ip": "10.0.0.1", "alive": true, "mac": "aa:bb:cc:dd:ee:01"})
	sink.observe("ip", map[string]any{"ip": "10.0.0.2", "alive": true}) // 存活但无端口
	sink.observe("ip", map[string]any{"ip": "10.0.0.3", "alive": true, "excludedByStrict": true})
	sink.observe("ip", map[string]any{"ip": "10.0.0.4", "alive": false})
	sink.observe("port", map[string]any{"ip": "10.0.0.1", "port": 80, "state": "open", "service": "http"})
	sink.observe("port", map[string]any{"ip": "10.0.0.1", "port": 81, "state": "closed"})
	sink.observe("status", map[string]any{"msg": "非目标事件应忽略"})

	sink.flush()

	assets, err := d.Assets().List()
	if err != nil {
		t.Fatalf("读资产失败: %v", err)
	}
	if len(assets) != 4 {
		t.Fatalf("应有 4 台资产, 实际 %d: %+v", len(assets), assets)
	}
	byIP := map[string]*db.Asset{}
	for _, a := range assets {
		byIP[a.IP] = a
	}
	a1 := byIP["10.0.0.1"]
	if a1 == nil {
		t.Fatal("10.0.0.1 资产缺失")
	}
	if !a1.Alive {
		t.Error("10.0.0.1 应判为存活")
	}
	if len(a1.Ports) != 1 || a1.Ports[0] != 80 {
		t.Errorf("10.0.0.1 应只有开放端口 80(closed 不入账), 实际 %v", a1.Ports)
	}
	if a1.MAC != "aa:bb:cc:dd:ee:01" {
		t.Errorf("MAC 未回写: %s", a1.MAC)
	}
	if a2 := byIP["10.0.0.2"]; a2 == nil || !a2.Alive {
		t.Error("10.0.0.2 存活但无端口, 仍应生成最小资产并标记存活")
	}
	if a3 := byIP["10.0.0.3"]; a3 == nil || a3.Alive {
		t.Error("excludedByStrict(严格模式仅端口推断)不应计入存活")
	}
	if a4 := byIP["10.0.0.4"]; a4 == nil || a4.Alive {
		t.Error("alive=false 不应被写成存活")
	}
}

// TestVulnQueryOpenStatus "开放"筛选口径: new/duplicate/open 全部命中, fixed 不命中。
//
// 用户视角漏洞只有"开放/已修复"两态, 而库内有三个"开放"细态 ——
// 漏掉任何一个, 前端选"开放"就会静默少数据。
func TestVulnQueryOpenStatus(t *testing.T) {
	mk := func(status string) *db.Vuln {
		return &db.Vuln{Vuln: models.Vuln{AssetIP: "10.0.0.9", Title: "t", Status: status}}
	}
	openQ := db.VulnQuery{Status: models.VulnStatusOpen}
	for _, c := range []struct {
		status string
		want   bool
	}{
		{models.VulnStatusNew, true},
		{models.VulnStatusDuplicate, true},
		{models.VulnStatusOpen, true},
		{models.VulnStatusFixed, false},
	} {
		if got := openQ.Match(mk(c.status)); got != c.want {
			t.Errorf("status=%q 匹配 open = %v, want %v", c.status, got, c.want)
		}
	}
	// 精确态筛选不受影响(fixed 仍按精确匹配)
	fixedQ := db.VulnQuery{Status: models.VulnStatusFixed}
	if !fixedQ.Match(mk(models.VulnStatusFixed)) || fixedQ.Match(mk(models.VulnStatusOpen)) {
		t.Error("fixed 精确筛选口径被破坏")
	}
}

// TestUpsertProbeVulnReopenFixed 已修复漏洞被再次命中 → 回退 open 并清除修复时间。
func TestUpsertProbeVulnReopenFixed(t *testing.T) {
	d := openTestDB(t)
	mk := func() *models.Vuln {
		return &models.Vuln{
			AssetIP: "10.0.0.9", Port: 80, Title: "测试漏洞",
			Severity: "high", CVE: "CVE-2021-9999",
		}
	}
	if err := upsertProbeVuln(d.Vulns(), "probe-x", mk()); err != nil {
		t.Fatalf("首次落库失败: %v", err)
	}
	id := mk().StableID()
	// 人工标记已修复
	cur, err := d.Vulns().Get(id)
	if err != nil || cur == nil {
		t.Fatalf("读漏洞失败: %v", err)
	}
	cur.Status = models.VulnStatusFixed
	now := time.Now()
	cur.FixedAt = &now
	if err := d.Vulns().Update(cur); err != nil {
		t.Fatalf("标记已修复失败: %v", err)
	}
	// 下一轮扫描再次命中
	if err := upsertProbeVuln(d.Vulns(), "probe-x", mk()); err != nil {
		t.Fatalf("再次落库失败: %v", err)
	}
	got, err := d.Vulns().Get(id)
	if err != nil || got == nil {
		t.Fatalf("读漏洞失败: %v", err)
	}
	if models.IsFixedStatus(got.Status) {
		t.Fatalf("再次命中后不应仍为 fixed, 实际 %q", got.Status)
	}
	if got.FixedAt != nil {
		t.Error("回退 open 后修复时间应清空")
	}
	if !got.LastSeenAt.After(now.Add(-time.Second)) {
		t.Error("最后命中时间应刷新")
	}
}

// TestProbeEnableAPI 探针一键开启: 保留已有配置、缺省补齐、落盘 settings.json。
//
// 用户手写的 listen/token 是最容易被覆盖的东西 —— 覆盖一次, 所有已部署探针全部掉线。
func TestProbeEnableAPI(t *testing.T) {
	probeAPITestMode(t)
	h, _ := newV2TestEnv(t)

	// settings.json 指向临时目录(隔离开发机真实配置)
	dir := t.TempDir()
	setSettingsTestPath(filepath.Join(dir, "settings.json"))
	resetSettingsCache()
	t.Cleanup(func() { setSettingsTestPath(""); resetSettingsCache() })

	// 复位探针单例, 防止 Do 内真实启动中心端
	prevOnce, prevCfg, prevCenter, prevRole := probeOnce, probeCfg, probeCenter, probeOverrideRole
	probeOnce, probeCfg, probeCenter = &sync.Once{}, ProbeConfig{}, nil
	probeOverrideRole = ""
	t.Cleanup(func() {
		probeOnce, probeCfg, probeCenter, probeOverrideRole = prevOnce, prevCfg, prevCenter, prevRole
	})

	// 场景 1: 已有 probe 节(用户自定义 listen/token) → 全部保留
	path := filepath.Join(dir, "settings.json")
	if err := os.WriteFile(path, []byte(
		`{"probe":{"center":{"enabled":false,"listen":"127.0.0.1:9999","token":"mytoken"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resetSettingsCache()
	w := doReq(t, h, http.MethodPost, "/api/v2/probe/enable", "")
	if w.Code != http.StatusOK {
		t.Fatalf("开启接口 HTTP %d: %s", w.Code, w.Body.String())
	}
	data, got := probeEnableData(t, w.Body.String())
	if !data.Enabled || !data.RestartRequired {
		t.Errorf("应提示 enabled=true restartRequired=true: %s", w.Body.String())
	}
	if got["listen"] != "127.0.0.1:9999" || got["token"] != "mytoken" {
		t.Errorf("用户已有 listen/token 被覆盖: %v", got)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "127.0.0.1:9999") || !strings.Contains(string(raw), "mytoken") {
		t.Error("settings.json 未落盘或配置丢失")
	}

	// 场景 2: 无 probe 节 → 默认补齐 listen=:8600 + 自动生成 token
	if err := os.WriteFile(path, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	resetSettingsCache()
	w = doReq(t, h, http.MethodPost, "/api/v2/probe/enable", "")
	if w.Code != http.StatusOK {
		t.Fatalf("第二次开启 HTTP %d: %s", w.Code, w.Body.String())
	}
	data2, got2 := probeEnableData(t, w.Body.String())
	if !data2.Enabled {
		t.Error("enabled 应为 true")
	}
	if got2["listen"] != ":8600" {
		t.Errorf("缺省 listen 应补齐 :8600, 实际 %v", got2["listen"])
	}
	if tok, _ := got2["token"].(string); len(tok) < 16 {
		t.Errorf("空 token 应自动生成, 实际 %v", got2["token"])
	}
}

type probeEnableResp struct {
	Enabled         bool `json:"enabled"`
	RestartRequired bool `json:"restartRequired"`
}

func probeEnableData(t *testing.T, body string) (probeEnableResp, map[string]any) {
	t.Helper()
	var resp struct {
		Code int            `json:"code"`
		Data map[string]any `json:"data"`
	}
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("响应解析失败: %v (%s)", err, body)
	}
	if resp.Code != 0 {
		t.Fatalf("业务错误: %s", body)
	}
	return probeEnableResp{
		Enabled:         resp.Data["enabled"] == true,
		RestartRequired: resp.Data["restartRequired"] == true,
	}, resp.Data
}
