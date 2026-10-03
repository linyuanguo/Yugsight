package main

// 守"明明存活却显示未存活"的契约(2026-09-25 用户反馈):
// 主机/Web 单点扫描不跑存活探测(无 ip 事件), 但 TCP 握手成功+拿到服务
// 响应就是"主机活着"的硬证据 —— 原始报告"X 台存活"与资产表 Alive 必须
// 如实反映, 不能恒 0 / 恒 false。
// 同时守反向契约: 严格模式"仅端口开放不计存活"是 ip 事件的权威结论,
// 端口证据不能翻案。

import (
	"testing"
)

func TestScanSinkPortEvidenceAlive(t *testing.T) {
	// 场景 1: 主机扫描(无 ip 事件)发现开放端口 → 该 IP 计存活
	sink := newScanSink(scanReq{Type: "host", IP: "10.0.0.5"}, "10.0.0.5", 0)
	sink.observe("port", map[string]any{"ip": "10.0.0.5", "port": 23, "state": "open", "service": "telnet"})
	sink.observe("finding", map[string]any{"title": "测试漏洞", "host": "10.0.0.5", "port": 23, "severity": "high"})

	pl := sink.rawPayload()
	alive, _ := pl["alive"].(map[string]aliveRecord)
	if len(alive) != 1 {
		t.Fatalf("有开放端口应计 1 台存活, got %d: %v", len(alive), alive)
	}
	rec, ok := alive["10.0.0.5"]
	if !ok || !rec.alive {
		t.Fatalf("10.0.0.5 应判存活(端口证据): %v", alive)
	}

	// 资产表回写: Alive 应为 true
	res := sink.normalize()
	res = sink.applyAliveState(res)
	if res == nil || len(res.Assets) == 0 {
		t.Fatal("应产出资产")
	}
	if !res.Assets[0].Alive {
		t.Fatalf("主机扫描发现开放端口的资产 Alive 应为 true: %+v", res.Assets[0])
	}

	// 场景 2: 严格模式排除的 IP(ip 事件权威) + 端口证据 → 仍不计存活
	sink2 := newScanSink(scanReq{Type: "ip", CIDR: "10.0.0.0/24"}, "", 0)
	sink2.observe("ip", map[string]any{"ip": "10.0.0.6", "alive": true, "excludedByStrict": true})
	sink2.observe("port", map[string]any{"ip": "10.0.0.6", "port": 80, "state": "open", "service": "http"})
	alive2, _ := sink2.rawPayload()["alive"].(map[string]aliveRecord)
	if r, ok := alive2["10.0.0.6"]; !ok || r.alive {
		t.Fatalf("严格模式排除的 IP 不应被端口证据翻案: %v", alive2)
	}

	// 场景 3: 全关的 IP(无端口、无 ip 事件记录) → 不计存活
	sink3 := newScanSink(scanReq{Type: "host", IP: "10.0.0.7"}, "10.0.0.7", 0)
	sink3.observe("port", map[string]any{"ip": "10.0.0.7", "port": 80, "state": "closed"})
	alive3, _ := sink3.rawPayload()["alive"].(map[string]aliveRecord)
	if len(alive3) != 0 {
		t.Fatalf("无开放端口的 IP 不应计存活: %v", alive3)
	}
}
