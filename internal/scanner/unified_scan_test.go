package scanner

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// 本文件覆盖 c7 统一扫描重构的"兼容委托"契约: scanIPsWithMode / ScanPorts /
// probeHost2 三处旧入口改为委托 UnifiedScan / probeHostUnified 后, 对外语义必须
// 与委托前逐字段一致。UnifiedScan 自身的模式判定/取消语义见 unified_test.go,
// 这里只断言"委托链路没有把旧契约改坏"—— 这类问题编译期发现不了, 只会静默缩水。

// TestScanPortsDelegationKeepsClosedResults 旧 ScanPorts 契约: 逐端口回传事件并
// 返回全量结果(开放+关闭)。委托 none 模式后若只收集/转发开放端口, 调用方拿到的
// 结果集会静默缩水 —— 这正是委托最容易改坏的点, 用不可达端口(必 closed)离线验证。
func TestScanPortsDelegationKeepsClosedResults(t *testing.T) {
	const host = "198.51.100.7" // RFC5737 文档保留段: 无真实主机, 拨号必失败
	var mu sync.Mutex
	var events []PortResult
	emit := func(kind string, data any) {
		if kind != "port" {
			return
		}
		if r, ok := data.(PortResult); ok {
			mu.Lock()
			events = append(events, r)
			mu.Unlock()
		}
	}
	results := ScanPorts(context.Background(), host, []int{80, 81, 82}, 300*time.Millisecond, 3, emit)

	if len(results) != 3 {
		t.Fatalf("关闭端口也必须进结果集(旧契约: 返回全量), 期望 3, 实际 %d", len(results))
	}
	for _, r := range results {
		if r.State != "closed" {
			t.Errorf("不可达端口 %d 应为 closed, 实际 %s", r.Port, r.State)
		}
		if r.IP != host {
			t.Errorf("结果 IP 应为 %s, 实际 %s", host, r.IP)
		}
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 3 {
		t.Fatalf("逐端口事件(开放+关闭)也是旧契约, 期望 3 条, 实际 %d", len(events))
	}
}

// TestScanPortsDelegationOpenPortDetails 开放端口的字段口径经委托后不变:
// state= open、服务名/banner/时延齐备。需要真实回环监听, 沙箱不可用时跳过。
func TestScanPortsDelegationOpenPortDetails(t *testing.T) {
	if !loopbackAllowedForAlive() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	ln := listenLoopback(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go acceptAndClose(ln)

	results := ScanPorts(context.Background(), "127.0.0.1", []int{port}, 500*time.Millisecond, 2, func(string, any) {})
	if len(results) != 1 {
		t.Fatalf("期望 1 条结果, 实际 %d", len(results))
	}
	r := results[0]
	if r.State != "open" || r.Port != port || r.IP != "127.0.0.1" {
		t.Errorf("开放端口字段不符: %+v", r)
	}
	if r.LatencyMs < 0 {
		t.Errorf("时延不应为负: %d", r.LatencyMs)
	}
}

// TestScanIPsWithModeDelegationLoose 旧宽松存活入口经委托后判定语义不变:
// 无 ICMP/ARP 应答但端口开放的主机仍计入存活, 且 ip 事件携带 ports。
func TestScanIPsWithModeDelegationLoose(t *testing.T) {
	if !loopbackAllowedForAlive() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	ln := listenLoopback(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go acceptAndClose(ln)

	var mu sync.Mutex
	ipEvents := map[string]map[string]any{}
	emit := func(kind string, data any) {
		if kind != "ip" {
			return
		}
		if m, ok := data.(map[string]any); ok {
			mu.Lock()
			ipEvents[m["ip"].(string)] = m
			mu.Unlock()
		}
	}
	alive, excluded := ScanIPsWithDetail(context.Background(), []string{"127.0.0.1"}, []int{port}, 4, 500*time.Millisecond, false, emit)
	if alive != 1 || excluded != 0 {
		t.Errorf("宽松模式端口开放应存活: alive/excluded = %d/%d", alive, excluded)
	}
	mu.Lock()
	ev := ipEvents["127.0.0.1"]
	mu.Unlock()
	if ev == nil {
		t.Fatal("未收到 ip 事件")
	}
	if v, _ := ev["alive"].(bool); !v {
		t.Error("ip 事件 alive 应为 true")
	}
	if ports, _ := ev["ports"].([]int); len(ports) != 1 || ports[0] != port {
		t.Errorf("ip 事件 ports 应含 %d, 实际 %v", port, ports)
	}
}

// TestScanIPsWithModeCtxCancelReturns 旧存活入口经委托后 ctx 取消语义不变:
// 取消后必须返回(不 hang / 无 goroutine 泄漏)。
func TestScanIPsWithModeCtxCancelReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hosts := make([]string, 0, 8)
	for i := 1; i <= 8; i++ {
		hosts = append(hosts, "198.51.100."+strconv.Itoa(i))
	}
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	done := make(chan struct{})
	go func() {
		ScanIPsWithDetail(ctx, hosts, []int{80}, 4, 300*time.Millisecond, false, func(string, any) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后旧存活入口未返回(委托链路可能丢失 ctx / goroutine 泄漏)")
	}
}

// TestProbeHost2Adapter probeHost2 兼容适配层的映射口径: 无应答主机 alive=false、
// icmp/arp=false、ports 为空 —— 与旧实现(证据合成判定)一致。离线可跑。
func TestProbeHost2Adapter(t *testing.T) {
	res := probeHost2(context.Background(), "198.51.100.7", []int{80}, 300*time.Millisecond, 1, false, false)
	if res.alive {
		t.Error("无任何探测能力的保留段主机不应判活")
	}
	if res.icmp || res.arp {
		t.Errorf("icmpAvail/arpAvail=false 时不应产生应答证据: icmp=%v arp=%v", res.icmp, res.arp)
	}
	if len(res.ports) != 0 {
		t.Errorf("不可达主机不应有开放端口, 实际 %v", res.ports)
	}
}
