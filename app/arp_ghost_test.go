// arp_ghost_test.go 代理 ARP 幽灵排除的契约测试。
//
// 守什么(改坏会静默失效的契约):
//  1. 开关默认开(用户 2026-09-26 拍板)—— 配置缺失/解析失败都必须是"开",
//     一旦默认值翻成 false, 幽灵资产会静默回流资产表, 无任何报错;
//  2. 本地扫描落库前剔除: 同 MAC 组内"仅 ARP"的 IP 不入资产表, 真身保留;
//     显式关开关后回退旧行为(照旧入账)—— 开关是用户回退的唯一出口;
//  3. 存量清理: 预览→删除→审计留痕, 且幂等(删完再清不删东西);
//  4. 探针链路口径(无 ICMP 证据, 按开放端口判)与"全组无真身不删"红线。
package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"yugsight/internal/db"
	"yugsight/internal/models"
)

// ===== 开关默认值(静默失效型契约, 必须守住) =====

func TestArpGhostExcludeDefaultOn(t *testing.T) {
	withTempExeDir(t) // 独占配置目录 + 重置缓存(清理在 Cleanup)
	if !arpGhostExcludeEnabled() {
		t.Fatal("settings.json 缺失时排除必须默认开(用户 2026-09-26 口径)")
	}
}

func TestArpGhostExcludeExplicitFalse(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"arpproxy":{"exclude":false}}`)
	if arpGhostExcludeEnabled() {
		t.Fatal("显式 exclude=false 必须生效(用户回退出口)")
	}
}

func TestArpGhostExcludeMalformedFallsBackOn(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"arpproxy":{not-json}}`)
	if !arpGhostExcludeEnabled() {
		t.Fatal("节解析失败必须回落默认开(与 settings 中心'解析失败走默认值'口径一致)")
	}
	// BOM: Windows 记事本/PowerShell 写配置的既知坑, 配置中心统一剥
	writeTestSettings(t, "\xEF\xBB\xBF" + `{"arpproxy":{"exclude":false}}`)
	if arpGhostExcludeEnabled() {
		t.Fatal("带 BOM 的显式 false 必须生效(配置中心剥 BOM 契约)")
	}
}

// ===== 落点 1: 本地扫描落库前剔除 =====

// feedProxyARPScan 喂一份"整段代答"扫描事件: 真身 10.1.0.1(回 ICMP+80 端口),
// 幽灵 10.1.0.2/.3(同 MAC 仅 ARP), 无关真实主机 10.1.0.9(独立 MAC 回 ICMP)。
func feedProxyARPScan(sink *scanSink) {
	sink.observe("ip", map[string]any{"ip": "10.1.0.1", "alive": true, "mac": "aa:bb:cc:dd:ee:01", "icmp": true})
	sink.observe("port", map[string]any{"ip": "10.1.0.1", "port": 80, "state": "open", "service": "http"})
	sink.observe("ip", map[string]any{"ip": "10.1.0.2", "alive": true, "mac": "aa:bb:cc:dd:ee:01", "icmp": false})
	sink.observe("ip", map[string]any{"ip": "10.1.0.3", "alive": true, "mac": "aa:bb:cc:dd:ee:01", "icmp": false})
	sink.observe("ip", map[string]any{"ip": "10.1.0.9", "alive": true, "mac": "bb:cc:dd:ee:ff:09", "icmp": true})
}

func TestScanSinkGhostExcluded(t *testing.T) {
	withTempExeDir(t) // 默认开
	_, d := newV2TestEnv(t)
	sink := newScanSink(scanReq{Type: "unified"}, "", 0)
	feedProxyARPScan(sink)
	sink.flush()

	got := map[string]bool{}
	list, err := d.Assets().List()
	if err != nil {
		t.Fatalf("读资产: %v", err)
	}
	for _, a := range list {
		got[a.IP] = true
	}
	if !got["10.1.0.1"] || !got["10.1.0.9"] {
		t.Fatalf("真身(端口证据/独立 MAC)必须入账: %v", got)
	}
	if got["10.1.0.2"] || got["10.1.0.3"] {
		t.Fatalf("仅 ARP 的同 MAC 幽灵不得入账: %v", got)
	}
	if len(list) != 2 {
		t.Fatalf("应恰好 2 台资产: %v", got)
	}
}

func TestScanSinkGhostKeptWhenDisabled(t *testing.T) {
	withTempExeDir(t)
	writeTestSettings(t, `{"arpproxy":{"exclude":false}}`) // 回退旧行为
	_, d := newV2TestEnv(t)
	sink := newScanSink(scanReq{Type: "unified"}, "", 0)
	feedProxyARPScan(sink)
	sink.flush()

	list, err := d.Assets().List()
	if err != nil {
		t.Fatalf("读资产: %v", err)
	}
	if len(list) != 4 {
		t.Fatalf("开关关闭时必须回退旧行为(4 台全入账), got %d", len(list))
	}
}

// 全组无真身: 一个都不删, 但资产照常入账(判定失败不回退成误删)
func TestScanSinkUnresolvedGroupNotDeleted(t *testing.T) {
	withTempExeDir(t)
	_, d := newV2TestEnv(t)
	sink := newScanSink(scanReq{Type: "unified"}, "", 0)
	sink.observe("ip", map[string]any{"ip": "10.2.0.1", "alive": true, "mac": "aa:bb:cc:dd:ee:07", "icmp": false})
	sink.observe("ip", map[string]any{"ip": "10.2.0.2", "alive": true, "mac": "aa:bb:cc:dd:ee:07", "icmp": false})
	sink.flush()

	list, err := d.Assets().List()
	if err != nil {
		t.Fatalf("读资产: %v", err)
	}
	if len(list) != 2 {
		t.Fatalf("无真身证据的组不得删除(宁可漏删不可误删): got %d", len(list))
	}
}

// ===== 落点 2: 探针口径(纯函数) =====

func TestFilterProbeGhostAssets(t *testing.T) {
	mk := func(ip, mac string, ports ...int) *models.Asset {
		return &models.Asset{IP: ip, MAC: mac, Ports: ports}
	}
	// 场景 1: 代答组(1 真身有端口 + 2 幽灵无端口) → 剔 2
	kept, ghosts := filterProbeGhostAssets([]*models.Asset{
		mk("10.5.0.1", "aa:bb:cc:dd:ee:01", 80),
		mk("10.5.0.2", "aa:bb:cc:dd:ee:01"),
		mk("10.5.0.3", "aa:bb:cc:dd:ee:01"),
	})
	if len(ghosts) != 2 || len(kept) != 1 || kept[0].IP != "10.5.0.1" {
		t.Fatalf("场景1 应剔 2 留真身: kept=%v ghosts=%v", kept, ghosts)
	}
	// 场景 2: 多 IP 主机(每个 IP 都有端口) → 全留
	kept2, ghosts2 := filterProbeGhostAssets([]*models.Asset{
		mk("10.5.1.1", "aa:bb:cc:dd:ee:02", 443),
		mk("10.5.1.2", "aa:bb:cc:dd:ee:02", 80),
	})
	if len(ghosts2) != 0 || len(kept2) != 2 {
		t.Fatalf("场景2 多 IP 主机不得误删: kept=%v ghosts=%v", kept2, ghosts2)
	}
	// 场景 3: 全组无端口(探针口径下无真身证据) → 不删
	kept3, ghosts3 := filterProbeGhostAssets([]*models.Asset{
		mk("10.5.2.1", "aa:bb:cc:dd:ee:03"),
		mk("10.5.2.2", "aa:bb:cc:dd:ee:03"),
	})
	if len(ghosts3) != 0 || len(kept3) != 2 {
		t.Fatalf("场景3 无真身证据不得删: kept=%v ghosts=%v", kept3, ghosts3)
	}
	// 场景 4: MAC 为空的资产不参与分组(手动录入/仅端口入账的存量行)
	kept4, ghosts4 := filterProbeGhostAssets([]*models.Asset{
		mk("10.5.3.1", "aa:bb:cc:dd:ee:04", 22),
		mk("10.5.3.2", ""),
		mk("10.5.3.3", ""),
	})
	if len(ghosts4) != 0 || len(kept4) != 3 {
		t.Fatalf("场景4 无 MAC 不参与分组: kept=%v ghosts=%v", kept4, ghosts4)
	}
}

// ===== 落点 3: 存量预览 + 清理 API =====

func TestArpGhostPreviewAndCleanup(t *testing.T) {
	h, d := newV2TestEnv(t)
	// 造存量: 代答组(真身 10.9.0.1 有端口 + 幽灵 10.9.0.2/.3 仅 ARP) + 无关主机
	for _, a := range []*models.Asset{
		{IP: "10.9.0.1", MAC: "aa:bb:cc:dd:ee:01", Ports: []int{80}, Alive: true},
		{IP: "10.9.0.2", MAC: "aa:bb:cc:dd:ee:01", Alive: true},
		{IP: "10.9.0.3", MAC: "aa:bb:cc:dd:ee:01", Alive: true},
		{IP: "10.9.1.1", MAC: "cc:dd:ee:ff:00:01", Alive: true},
	} {
		dbA := db.NewAsset(a.IP)
		dbA.MAC, dbA.Ports, dbA.Alive = a.MAC, a.Ports, a.Alive
		if _, err := d.Assets().Upsert(dbA); err != nil {
			t.Fatalf("播种资产: %v", err)
		}
	}

	// 预览: count=2, 组内真身 10.9.0.1
	w := doReq(t, h, "GET", "/api/v2/assets/arp-ghosts", "")
	if w.Code != http.StatusOK {
		t.Fatalf("预览应 200, got %d: %s", w.Code, w.Body.String())
	}
	pv, err := decodeData[struct {
		Enabled bool              `json:"enabled"`
		Count   int               `json:"count"`
		Groups  []json.RawMessage `json:"groups"`
	}](t, w)
	if err != nil {
		t.Fatalf("预览响应解析: %v", err)
	}
	if !pv.Enabled || pv.Count != 2 || len(pv.Groups) != 1 {
		t.Fatalf("预览应 count=2 groups=1 enabled=true: %+v", pv)
	}

	// 清理: 删 2, 剩 2
	w = doReq(t, h, "POST", "/api/v2/assets/arp-ghosts/cleanup", "")
	if w.Code != http.StatusOK {
		t.Fatalf("清理应 200, got %d: %s", w.Code, w.Body.String())
	}
	cl, err := decodeData[struct {
		Deleted int `json:"deleted"`
	}](t, w)
	if err != nil {
		t.Fatalf("清理响应解析: %v", err)
	}
	if cl.Deleted != 2 {
		t.Fatalf("清理应删 2: %+v", cl)
	}
	list, _ := d.Assets().List()
	if len(list) != 2 {
		t.Fatalf("清理后应剩 2 台: %d", len(list))
	}
	for _, a := range list {
		if a.IP == "10.9.0.2" || a.IP == "10.9.0.3" {
			t.Fatalf("幽灵 10.9.0.x 必须被删: %s", a.IP)
		}
	}

	// 审计留痕(删 2 行必须可追溯)
	audits, err := d.Audits().List()
	if err != nil {
		t.Fatalf("读审计: %v", err)
	}
	found := false
	for _, l := range audits {
		if l.Action == "asset.clean_arp_ghost" {
			found = true
			if l.Detail != "deleted=2 groups=1" {
				t.Fatalf("审计 detail 应含删除数: %s", l.Detail)
			}
		}
	}
	if !found {
		t.Fatal("清理必须写 asset.clean_arp_ghost 审计")
	}

	// 幂等: 再清一次 = 0
	w = doReq(t, h, "POST", "/api/v2/assets/arp-ghosts/cleanup", "")
	cl2, _ := decodeData[struct {
		Deleted int `json:"deleted"`
	}](t, w)
	if cl2.Deleted != 0 {
		t.Fatalf("重复清理必须幂等(删 0), got %d", cl2.Deleted)
	}
}

// decodeData 拆 v2 统一响应信封({code,message,data})后解 data 段。
func decodeData[T any](t *testing.T, w *httptest.ResponseRecorder) (T, error) {
	t.Helper()
	var out struct {
		Code int             `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	var zero T
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		return zero, err
	}
	if err := json.Unmarshal(out.Data, &zero); err != nil {
		return zero, err
	}
	return zero, nil
}
