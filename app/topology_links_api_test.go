package main

// topology_links_api_test.go 链路聚合接口契约测试(阶段 B)。
//
// 守的契约(改坏会静默失效):
//  1. 边生成确定性: 探针纳管边 / 同网段星型 / 跨网段链, 各出现一次;
//  2. 链路状态 = 两端最高严重度(一端离线 → 链路 down);
//  3. 非 IP 资产(SCA 工件口径)不进拓扑;
//  4. 接口只读, 数据层不可用 → 500 而非 panic。

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"yugsight/internal/collect"
	"yugsight/internal/db"
	"yugsight/internal/monitor"
)

// injectEmptyTopologySources 注入空的采集/监控单例, 避免测试读开发机
// settings.json 拉起真实采集循环(与 resetMonitorForTest 同口径)。
func injectEmptyTopologySources(t *testing.T) {
	t.Helper()
	resetCollectForTest()
	nodeInst = collect.New(collect.Config{}, func() collect.Config { return collect.Config{} }, nil)
	resetMonitorForTest()
	monInst = monitor.New(monitor.Config{}, func() monitor.Config { return monitor.Config{} }, nil)
	t.Cleanup(func() { resetCollectForTest(); resetMonitorForTest() })
}

type topoLinkRow struct {
	From   string `json:"fromDeviceId"`
	To     string `json:"toDeviceId"`
	Status string `json:"status"`
}

func TestTopologyLinksAPI(t *testing.T) {
	h, d := newV2TestEnv(t)
	injectEmptyTopologySources(t)

	// 两台探针: 一在线(192.168.1 段)一离线(192.168.2 段)
	if _, err := d.Probes().Upsert(&db.Probe{ID: "pb1", Name: "agent-a", Addr: "192.168.1.100:8600", Status: "online"}); err != nil {
		t.Fatalf("upsert probe: %v", err)
	}
	if _, err := d.Probes().Upsert(&db.Probe{ID: "pb2", Name: "agent-b", Addr: "192.168.2.100:8600", Status: "offline"}); err != nil {
		t.Fatalf("upsert probe: %v", err)
	}
	// 三台资产: 1 段两台(其一被 pb1 纳管) + 2 段一台(离线)
	a10 := db.NewAsset("192.168.1.10")
	a10.Alive = true
	a10.ProbeNode = "pb1"
	a11 := db.NewAsset("192.168.1.11")
	a11.Alive = true
	a20 := db.NewAsset("192.168.2.10")
	a20.Alive = false
	for _, a := range []*db.Asset{a10, a11, a20} {
		if _, err := d.Assets().Upsert(a); err != nil {
			t.Fatalf("upsert asset: %v", err)
		}
	}

	// 2026-09-30 自动连通测试: 单测不发真实 ICMP/TCP —— 预置"刚通过"的检查缓存,
	// maybeAutoCheck 见缓存新鲜直接跳过, 不拉起后台探测 goroutine(防跨测试数据竞争)。
	checkedKeys := []string{
		linkCheckKey("A_"+a10.ID, "P_pb1"),
		linkCheckKey("A_"+a10.ID, "A_"+a11.ID),
	}
	topoAutoCheckMu.Lock()
	for _, key := range checkedKeys {
		topoAutoCheck[key] = autoCheckRes{ok: true, rtt: 3, at: time.Now()}
	}
	topoAutoCheckMu.Unlock()
	t.Cleanup(func() {
		topoAutoCheckMu.Lock()
		for _, key := range checkedKeys {
			delete(topoAutoCheck, key)
		}
		topoAutoCheckMu.Unlock()
	})

	w := doReq(t, h, "GET", "/api/v2/topology/links", "")
	if w.Code != 200 {
		t.Fatalf("status=%d body=%.400s", w.Code, w.Body.String())
	}
	var out struct {
		List  []topoLinkRow `json:"list"`
		Count int           `json:"count"`
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v body=%.400s", err, w.Body.String())
	}
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		t.Fatalf("decode data: %v body=%.400s", err, w.Body.String())
	}
	if out.Count != len(out.List) || out.Count == 0 {
		t.Fatalf("count 不一致或为空: count=%d len=%d", out.Count, len(out.List))
	}

	// 资产稳定 ID 不是 IP, 从实体读回构造期望键
	devOf := map[string]string{} // IP -> A_<id>
	for _, a := range []*db.Asset{a10, a11, a20} {
		devOf[a.IP] = "A_" + a.ID
	}
	pair := map[string]bool{}
	statusOf := map[string]string{}
	for _, l := range out.List {
		pair[l.From+"~"+l.To] = true
		statusOf[l.From+"~"+l.To] = l.Status
	}
	has := func(x, y string) bool {
		return pair[x+"~"+y] || pair[y+"~"+x]
	}

	// ① 探针纳管边: 192.168.1.10 ↔ P_pb1
	if !has(devOf["192.168.1.10"], "P_pb1") {
		t.Fatalf("缺探针纳管边: %v", out.List)
	}
	// ② 同 /24 星型: 1.11 挂段代表 1.10(最小 IP)
	if !has(devOf["192.168.1.11"], devOf["192.168.1.10"]) {
		t.Fatalf("缺同网段星型边: %v", out.List)
	}
	// ③ 跨网段链: 两段代表相连(1 段代表=1.10, 2 段代表=2.10)
	if !has(devOf["192.168.1.10"], devOf["192.168.2.10"]) {
		t.Fatalf("缺跨网段边: %v", out.List)
	}
	// ④ 两端最高严重度: 跨网段边的一端 2.10 离线 → down
	st := statusOf[devOf["192.168.1.10"]+"~"+devOf["192.168.2.10"]]
	if st == "" {
		st = statusOf[devOf["192.168.2.10"]+"~"+devOf["192.168.1.10"]]
	}
	if st != "down" {
		t.Fatalf("离线端点所在链路应为 down, got %q: %v", st, out.List)
	}
	// ⑤ 无 SNMP 流量的链路不带 bandwidth 字段(不编造流量)
	if strings.Contains(w.Body.String(), `"bandwidth"`) {
		t.Fatalf("无监控数据时不应输出 bandwidth: %s", w.Body.String())
	}
}

// TestTopologyLinksOnlineUpgradeAndAutoCheck 守 2026-09-30 契约(用户反馈"设备上线
// 检测在线, 线却一直红"):
//  ① SNMP 近期采集成功 = 在线权威证据 —— 存活快照过期(Alive=false)的资产不得卡红,
//     链路状态必须升 normal(改坏时资产端点恒 down, 线恒红且无任何报错);
//  ② 自动连通测试失败 → 链路必须 down —— 绿线必须是实测结果(改坏时设备"在线"即绿线,
//     实际不通的用户看不到红色, 是最危险的静默失效);
//  ③ 有 SNMP 差分数据的链路输出 inMps/outMps/trafficSide(前端上下行定向的数据源)。
func TestTopologyLinksOnlineUpgradeAndAutoCheck(t *testing.T) {
	h, d := newV2TestEnv(t)
	monCfg := monitor.Config{Enabled: true, Targets: []monitor.Target{{ID: "t1", Addr: "192.168.1.50:161"}}}
	resetCollectForTest()
	nodeInst = collect.New(collect.Config{}, func() collect.Config { return collect.Config{} }, nil)
	resetMonitorForTest()
	monInst = monitor.New(monCfg, func() monitor.Config { return monCfg }, nil)
	t.Cleanup(func() { resetCollectForTest(); resetMonitorForTest() })

	restore := SetTopoAutoProbeForTest(func(ip string) (bool, int64, string) { return true, 5, "icmp" })
	t.Cleanup(restore)

	// 资产 A: 存活快照过期(Alive=false)但 SNMP 10s 前刚采集成功 → 应判在线
	a := db.NewAsset("192.168.1.50")
	a.Alive = false
	if _, err := d.Assets().Upsert(a); err != nil {
		t.Fatalf("upsert a: %v", err)
	}
	// 资产 B: 正常存活, 与 A 同 /24 生成星型边
	b := db.NewAsset("192.168.1.51")
	b.Alive = true
	if _, err := d.Assets().Upsert(b); err != nil {
		t.Fatalf("upsert b: %v", err)
	}
	// 新鲜 OK 样本 + 上一轮样本(60s 窗口: dIn=6MB→100KB/s=0.8Mbps, dOut=8.4MB→140KB/s=1.12Mbps)
	// → 链路带 inMps/outMps/trafficSide
	monInst.RecordSample("t1", &monitor.Sample{TargetID: "t1", At: time.Now().Add(-70 * time.Second), OK: true, Ifaces: []monitor.IfaceSample{{Index: "1", Speed: 1e8, Oper: 1, In: 1000000, Out: 2000000}}})
	monInst.RecordSample("t1", &monitor.Sample{TargetID: "t1", At: time.Now().Add(-10 * time.Second), OK: true, Ifaces: []monitor.IfaceSample{{Index: "1", Speed: 1e8, Oper: 1, In: 7000000, Out: 10400000}}})
	t.Cleanup(func() {
		topoAutoCheckMu.Lock()
		delete(topoAutoCheck, linkCheckKey("A_"+a.ID, "A_"+b.ID))
		topoAutoCheckMu.Unlock()
	})

	type linkRow struct {
		From      string  `json:"fromDeviceId"`
		To        string  `json:"toDeviceId"`
		Status    string  `json:"status"`
		Tested    bool    `json:"tested"`
		RttMs     int64   `json:"rttMs"`
		InMps     float64 `json:"inMps"`
		OutMps    float64 `json:"outMps"`
		TrafficSide string `json:"trafficSide"`
	}
	getLink := func() *linkRow {
		w := doReq(t, h, "GET", "/api/v2/topology/links", "")
		if w.Code != 200 {
			t.Fatalf("status=%d body=%.400s", w.Code, w.Body.String())
		}
		var resp struct {
			Data json.RawMessage `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		var out struct {
			List []linkRow `json:"list"`
		}
		if err := json.Unmarshal(resp.Data, &out); err != nil {
			t.Fatalf("decode data: %v", err)
		}
		kA, kB := "A_"+a.ID, "A_"+b.ID
		for i := range out.List {
			l := &out.List[i]
			if (l.From == kA && l.To == kB) || (l.From == kB && l.To == kA) {
				return l
			}
		}
		t.Fatalf("缺 A~B 链路: %+v", out.List)
		return nil
	}

	// ① 无检查缓存时: A 的在线证据(SNMP OK)使其端点不 down → 链路 normal
	l1 := getLink()
	if l1.Status != "normal" {
		t.Fatalf("SNMP 在线证据应使链路 normal(Alive=false 快照不否决), got %q", l1.Status)
	}
	// ③ 速率字段: 50s 窗口 in=5000B out=7000B → in≈0.8M out≈1.12M, 采样端=A
	if l1.InMps < 0.7 || l1.InMps > 0.9 {
		t.Fatalf("inMps 应为 ~0.8, got %v", l1.InMps)
	}
	if l1.OutMps < 1.0 || l1.OutMps > 1.2 {
		t.Fatalf("outMps 应为 ~1.1, got %v", l1.OutMps)
	}
	if l1.TrafficSide != "A_"+a.ID {
		t.Fatalf("trafficSide 应为采样端 A, got %q", l1.TrafficSide)
	}
	// 等后台自动探测完成(假探测瞬时返回; 有界等待, 不裸 sleep)
	deadline := time.Now().Add(2 * time.Second)
	for {
		if r, ok := autoCheckFresh(linkCheckKey("A_"+a.ID, "A_"+b.ID)); ok && r.ok {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("后台自动探测未在 2s 内完成")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// 检查通过 → 链路保持 normal 且带 tested/rttMs
	l2 := getLink()
	if l2.Status != "normal" || !l2.Tested {
		t.Fatalf("检查通过的链路应 normal 且 tested, got status=%q tested=%v", l2.Status, l2.Tested)
	}
	if l2.RttMs != 5 {
		t.Fatalf("rttMs 应为探测值 5, got %d", l2.RttMs)
	}

	// ② 检查失败 → 链路必须 down(绿线必须是实测结果; 改坏时"在线即绿"是最危险静默失效)
	topoAutoCheckMu.Lock()
	topoAutoCheck[linkCheckKey("A_"+a.ID, "A_"+b.ID)] = autoCheckRes{ok: false, at: time.Now()}
	topoAutoCheckMu.Unlock()
	l3 := getLink()
	if l3.Status != "down" {
		t.Fatalf("自动连通测试失败的链路必须 down, got %q", l3.Status)
	}
}

// TestTopologyLinksMonitorTargetEndpoint 2026-10-01 用户契约(真机反馈"设备绑定是节点
// 监控, 不是资产表, 这个逻辑就不对"): 节点监控目标(M_*)必须进拓扑当链路节点 ——
// ① 不在资产表的监控目标(交换机 172.16.199.1) → 跨网段代表链边存在且带真实
//    inMps/outMps(前端交换机线光点/速率的数据源; 改坏时链路又恒无速率且无报错);
// ② 与资产同 IP 的监控目标 → 同 IP 去重不生成 M_ 端点(与前端 S.devices 同口径,
//    防同一 IP 出两个节点)。
func TestTopologyLinksMonitorTargetEndpoint(t *testing.T) {
	h, d := newV2TestEnv(t)
	monCfg := monitor.Config{Enabled: true, Targets: []monitor.Target{
		{ID: "sw1", Addr: "172.16.199.1:161"},
		{ID: "dup1", Addr: "192.168.1.60:161"}, // 与资产同 IP, 应被去重
	}}
	resetCollectForTest()
	nodeInst = collect.New(collect.Config{}, func() collect.Config { return collect.Config{} }, nil)
	resetMonitorForTest()
	monInst = monitor.New(monCfg, func() monitor.Config { return monCfg }, nil)
	t.Cleanup(func() { resetCollectForTest(); resetMonitorForTest() })

	restore := SetTopoAutoProbeForTest(func(ip string) (bool, int64, string) { return true, 5, "icmp" })
	t.Cleanup(restore)

	a60 := db.NewAsset("192.168.1.60")
	a60.Alive = true
	a7 := db.NewAsset("192.168.1.7")
	a7.Alive = true
	for _, a := range []*db.Asset{a60, a7} {
		if _, err := d.Assets().Upsert(a); err != nil {
			t.Fatalf("upsert asset: %v", err)
		}
	}
	// sw1 两帧差分(60s 窗口: dIn=5.4MB → 90KB/s = 0.72Mbps; dOut=0)
	monInst.RecordSample("sw1", &monitor.Sample{TargetID: "sw1", At: time.Now().Add(-60 * time.Second), OK: true, Ifaces: []monitor.IfaceSample{{Index: "1", Speed: 1e8, Oper: 1, In: 1000000, Out: 2000000}}})
	monInst.RecordSample("sw1", &monitor.Sample{TargetID: "sw1", At: time.Now(), OK: true, Ifaces: []monitor.IfaceSample{{Index: "1", Speed: 1e8, Oper: 1, In: 6400000, Out: 2000000}}})

	w := doReq(t, h, "GET", "/api/v2/topology/links", "")
	if w.Code != 200 {
		t.Fatalf("status=%d body=%.400s", w.Code, w.Body.String())
	}
	var resp struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	type linkRow struct {
		From        string  `json:"fromDeviceId"`
		To          string  `json:"toDeviceId"`
		Status      string  `json:"status"`
		InMps       float64 `json:"inMps"`
		OutMps      float64 `json:"outMps"`
		TrafficSide string  `json:"trafficSide"`
	}
	var out struct {
		List []linkRow `json:"list"`
	}
	if err := json.Unmarshal(resp.Data, &out); err != nil {
		t.Fatalf("decode data: %v", err)
	}

	kSw, k60, k7 := "M_sw1", "A_"+a60.ID, "A_"+a7.ID
	// ② 同 IP 去重: 响应里不得出现 M_dup1
	body := w.Body.String()
	if strings.Contains(body, "M_dup1") {
		t.Fatalf("与资产同 IP 的监控目标应去重, 响应却含 M_dup1: %s", body)
	}
	// ① 跨网段代表链: 172.16.199.0/24 代表=M_sw1, 192.168.1.0/24 代表=A_7(数值最小)
	var l *linkRow
	for i := range out.List {
		x := &out.List[i]
		if (x.From == kSw && x.To == k7) || (x.From == k7 && x.To == kSw) {
			l = x
		}
	}
	if l == nil {
		t.Fatalf("缺监控目标跨网段代表边 M_sw1~A_7: %+v", out.List)
	}
	if l.InMps < 0.7 || l.InMps > 0.8 {
		t.Fatalf("inMps 应为 ~0.72, got %v", l.InMps)
	}
	if l.OutMps != 0 {
		t.Fatalf("dOut=0 时 outMps 应为 0, got %v", l.OutMps)
	}
	if l.TrafficSide != kSw {
		t.Fatalf("trafficSide 应为采样端 M_sw1, got %q", l.TrafficSide)
	}
	// 同网段星型边(A_60~A_7)不受监控目标加入影响
	found := false
	for i := range out.List {
		x := &out.List[i]
		if (x.From == k60 && x.To == k7) || (x.From == k7 && x.To == k60) {
			found = true
		}
	}
	if !found {
		t.Fatalf("缺同网段星型边 A_60~A_7: %+v", out.List)
	}

	// 等后台自动连通探测 goroutine 跑完再退出(与 OnlineUpgrade 用合同口径:
	// cleanup 恢复探针函数是写, 后台 goroutine 还在读同一变量, -race 会命中)
	deadline := time.Now().Add(2 * time.Second)
	for _, key := range []string{linkCheckKey(kSw, k7), linkCheckKey(k60, k7)} {
		for {
			if _, ok := autoCheckFresh(key); ok {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("后台自动探测未在 2s 内完成: %s", key)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestTopologyLinksDataLayerDown 数据层不可用 → 500 降级(不 panic 不空列表冒充成功)。
func TestTopologyLinksDataLayerDown(t *testing.T) {
	h, _ := newV2TestEnv(t)
	injectEmptyTopologySources(t)
	prev := v2DBProvider
	v2DBProviderMu.Lock()
	v2DBProvider = func() *db.Database { return nil }
	v2DBProviderMu.Unlock()
	t.Cleanup(func() {
		v2DBProviderMu.Lock()
		v2DBProvider = prev
		v2DBProviderMu.Unlock()
	})

	w := doReq(t, h, "GET", "/api/v2/topology/links", "")
	if w.Code != 500 {
		t.Fatalf("数据层不可用应 500, got %d: %.300s", w.Code, w.Body.String())
	}
}
