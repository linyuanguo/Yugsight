package scanner

import (
	"context"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

// TestParseAliveMode 解析口径: 空值/未知值必须归一到"宽松"(与旧存活扫描默认一致),
// 保证既有 /api/scan(aliveMode 缺省)行为零变化; strict/none 各自精确命中。
func TestParseAliveMode(t *testing.T) {
	cases := []struct {
		in   string
		want AliveMode
	}{
		{"", AliveModeLoose},
		{"loose", AliveModeLoose},
		{"Loose", AliveModeLoose},
		{"宽松", AliveModeLoose},
		{"strict", AliveModeStrict},
		{"STRICT", AliveModeStrict},
		{"严格", AliveModeStrict},
		{"none", AliveModeNone},
		{"NONE", AliveModeNone},
		{"off", AliveModeNone},
		{"跳过", AliveModeNone},
		{"  loose  ", AliveModeLoose}, // 前后空格需 trim
		{"unknown-value", AliveModeLoose}, // 未知 -> 宽松
	}
	for _, c := range cases {
		if got := ParseAliveMode(c.in); got != c.want {
			t.Errorf("ParseAliveMode(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestUnifiedScanEmpty 空目标 / 空端口必须安全返回 0/0/0(不 panic、不除零)。
func TestUnifiedScanEmpty(t *testing.T) {
	for _, mode := range []AliveMode{AliveModeStrict, AliveModeLoose, AliveModeNone} {
		if a, e, o, _ := UnifiedScan(context.Background(), nil, []int{80}, mode, 10, 0, func(string, any) {}); a != 0 || e != 0 || o != 0 {
			t.Errorf("mode=%s 空目标应 0/0/0, 实际 %d/%d/%d", mode, a, e, o)
		}
		if a, e, o, _ := UnifiedScan(context.Background(), []string{"127.0.0.1"}, nil, mode, 10, 0, func(string, any) {}); a != 0 || e != 0 || o != 0 {
			t.Errorf("mode=%s 空端口应 0/0/0, 实际 %d/%d/%d", mode, a, e, o)
		}
	}
}

// TestUnifiedScanNoneModePortOnly none 模式: 跳过存活判定, 只做端口扫描, 回传 port 事件。
// 需要真实回环监听, 沙箱不可用时跳过(交给真机联调覆盖)。
func TestUnifiedScanNoneModePortOnly(t *testing.T) {
	if !loopbackAllowedForAlive() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	ln := listenLoopback(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go acceptAndClose(ln)

	var mu sync.Mutex
	var portEvents []PortResult
	emit := func(kind string, data any) {
		if kind != "port" {
			return
		}
		if r, ok := data.(PortResult); ok {
			mu.Lock()
			portEvents = append(portEvents, r)
			mu.Unlock()
		}
	}
	alive, excluded, open, _ := UnifiedScan(context.Background(), []string{"127.0.0.1"}, []int{port}, AliveModeNone, 10, 500*time.Millisecond, emit)

	if alive != 0 || excluded != 0 {
		t.Errorf("none 模式不做存活判定, 期望 alive/excluded=0, 实际 %d/%d", alive, excluded)
	}
	if open != 1 {
		t.Errorf("none 模式应报告 1 个开放端口, 实际 %d", open)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(portEvents) != 1 {
		t.Fatalf("none 模式应回传 1 条 port 事件, 实际 %d", len(portEvents))
	}
	if portEvents[0].State != "open" || portEvents[0].Port != port {
		t.Errorf("port 事件应为开放且端口=%d, 实际 state=%s port=%d", port, portEvents[0].State, portEvents[0].Port)
	}
}

// TestUnifiedScanLooseCountsOpenPort loose 模式: 端口开放即计入存活(即便无 ICMP/ARP),
// 并额外回传 port 事件(统一扫描相对旧存活扫描的增量信息)。
func TestUnifiedScanLooseCountsOpenPort(t *testing.T) {
	if !loopbackAllowedForAlive() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	ln := listenLoopback(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go acceptAndClose(ln)

	var mu sync.Mutex
	ipEvents := map[string]map[string]any{}
	var portEvents int
	emit := func(kind string, data any) {
		mu.Lock()
		defer mu.Unlock()
		if kind == "ip" {
			if m, ok := data.(map[string]any); ok {
				ipEvents[m["ip"].(string)] = m
			}
		}
		if kind == "port" {
			portEvents++
		}
	}
	alive, _, open, _ := UnifiedScan(context.Background(), []string{"127.0.0.1"}, []int{port}, AliveModeLoose, 10, 500*time.Millisecond, emit)

	if alive != 1 {
		t.Errorf("loose 模式端口开放应计入存活, 实际 alive=%d", alive)
	}
	if open != 1 {
		t.Errorf("loose 模式应报告 1 个开放端口, 实际 %d", open)
	}
	mu.Lock()
	ev, ok := ipEvents["127.0.0.1"]
	mu.Unlock()
	if !ok {
		t.Fatal("未收到 ip 事件(统一扫描每台主机都要回传存活状态)")
	}
	if v, _ := ev["alive"].(bool); !v {
		t.Error("有开放端口时 loose 模式 ip 事件 alive 应为 true")
	}
	if ports, has := ev["ports"]; !has {
		t.Error("ip 事件缺少 ports 字段")
	} else if arr, isArr := ports.([]int); !isArr || len(arr) != 1 || arr[0] != port {
		t.Errorf("ip 事件 ports 应含开放端口 %d, 实际 %v", port, ports)
	}
	mu.Lock()
	pe := portEvents
	mu.Unlock()
	if pe != 1 {
		t.Errorf("loose 模式应回传 1 条 port 事件, 实际 %d", pe)
	}
}

// TestUnifiedScanNoResponseEmitsIPWithPorts 无应答主机(保留段)也必须回传 ip 事件且
// ports 字段为非 nil 切片 —— 与旧存活扫描同一契约, 否则用户无法判断是否漏扫。
// 不依赖真实网络能力, 沙箱里也能稳定执行。
func TestUnifiedScanNoResponseEmitsIPWithPorts(t *testing.T) {
	for _, mode := range []AliveMode{AliveModeLoose, AliveModeStrict} {
		t.Run(string(mode), func(t *testing.T) {
			var mu sync.Mutex
			events := map[string]map[string]any{}
			emit := func(kind string, data any) {
				if kind != "ip" {
					return
				}
				if m, ok := data.(map[string]any); ok {
					mu.Lock()
					events[m["ip"].(string)] = m
					mu.Unlock()
				}
			}
			const host = "198.51.100.7" // RFC5737 文档保留段: 无真实主机, ARP/ICMP 均无应答
			alive, excluded, open, _ := UnifiedScan(context.Background(), []string{host}, []int{80}, mode, 2, 300*time.Millisecond, emit)
			if alive != 0 || excluded != 0 || open != 0 {
				t.Errorf("无应答主机应 0/0/0, 实际 %d/%d/%d", alive, excluded, open)
			}
			mu.Lock()
			ev, ok := events[host]
			mu.Unlock()
			if !ok {
				t.Fatalf("无应答主机也必须回传 ip 事件(否则用户无法判断是否漏扫)")
			}
			if v, _ := ev["alive"].(bool); v {
				t.Error("保留段主机不应被判为存活")
			}
			ports, hasPorts := ev["ports"]
			if !hasPorts {
				t.Fatal("ip 事件缺少 ports 字段")
			}
			if _, isSlice := ports.([]int); !isSlice {
				t.Errorf("ports 应为 []int, 实际 %T", ports)
			}
		})
	}
}

// TestUnifiedScanConcurrent 多主机并发探测(配合 go test -race): 校验并发计数、
// 事件回传、开放端口累加无数据竞争, 且每台主机恰好回传一条 ip 事件。
func TestUnifiedScanConcurrent(t *testing.T) {
	hosts := []string{
		"198.51.100.1", "198.51.100.2", "198.51.100.3", "198.51.100.4",
		"198.51.100.5", "198.51.100.6", "198.51.100.7", "198.51.100.8",
	}
	var mu sync.Mutex
	var ipCount int
	emit := func(kind string, data any) {
		if kind == "ip" {
			mu.Lock()
			ipCount++
			mu.Unlock()
		}
	}
	for _, mode := range []AliveMode{AliveModeLoose, AliveModeStrict} {
		UnifiedScan(context.Background(), hosts, []int{80}, mode, 50, 200*time.Millisecond, emit)
	}
	mu.Lock()
	defer mu.Unlock()
	if ipCount != len(hosts)*2 {
		t.Errorf("每台主机应各回传一条 ip 事件, 期望 %d, 实际 %d", len(hosts)*2, ipCount)
	}
}

// TestUnifiedScanCtxCancelFast none 模式(纯 TCP 拨号, 无 ICMP/ARP): 取消后在途拨号经
// DialContext 立即失败, 必须快速返回 —— 验证 ctx 感知路径的"可快速终止"。
func TestUnifiedScanCtxCancelFast(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hosts := make([]string, 0, 100)
	for i := 1; i <= 100; i++ {
		hosts = append(hosts, "198.51.100."+strconv.Itoa(i%250+1))
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	UnifiedScan(ctx, hosts, []int{80, 81, 82}, AliveModeNone, 100, 5*time.Second, func(string, any) {})
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("ctx 取消后(none 模式, 纯 TCP 拨号)应快速返回, 实际耗时 %v", elapsed)
	}
}

// TestUnifiedScanCtxCancelReturns loose 模式(含 ICMP/ARP): 二者沿用既有 PingICMP /
// ArpProbeOne 实现(不感知 ctx, 与旧 probeHost2 同口径), 取消后在途探测会跑满超时。
// 这里只验证"取消后必然返回、无 goroutine 泄漏(不 hang/死锁)", 不对耗时做过强断言。
func TestUnifiedScanCtxCancelReturns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hosts := []string{"198.51.100.1", "198.51.100.2", "198.51.100.3"}
	go func() {
		time.Sleep(30 * time.Millisecond)
		cancel()
	}()
	done := make(chan struct{})
	go func() {
		UnifiedScan(ctx, hosts, []int{80}, AliveModeLoose, 10, 300*time.Millisecond, func(string, any) {})
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("ctx 取消后 loose 模式扫描未返回(可能 goroutine 泄漏 / 死锁)")
	}
}
