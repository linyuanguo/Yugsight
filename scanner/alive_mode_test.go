// alive_mode_test.go 存活判定口径(宽松/严格)与"证据来源"语义的用例。
//
// 【为什么这些逻辑需要单测】探测本身依赖真实网络(ICMP 需管理员权限、ARP 需
// Windows), 在 CI/沙箱里跑不出稳定结论; 但"三路证据怎么合成存活结论"是纯
// 逻辑, 恰恰是最容易写错、错了也最容易被忽略的部分:
//
//   - 把"端口开放"当成和 ICMP 同等可信 -> 严格模式形同虚设;
//   - 严格模式把端口推断的主机直接丢弃 -> 用户看不到"这台机器其实在", 无法判断是否漏扫;
//   - HasConfirmedResponse 写成 && -> 只看 ICMP 就判不了只回 ARP 的主机;
//   - 存活探测丢掉了顺带探到的开放端口 -> 用户为了拿端口清单再跑一次端口扫描,
//     同一批端口被探测两遍(见 TestIPEventCarriesPorts)。
package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"sync"
	"testing"
	"time"
)

// ===== 回环测试辅助(与 probe/scanner 既有约定保持一致) =====
//
// 沙箱会拦截回环外连(dial 已监听端口会超时而非立即成功/被拒), 此时任何依赖真实
// 端口探测的用例都必然失败且与代码质量无关。故先探测能力, 不可用则 Skip, 把真实
// 网络行为覆盖留给真机联调。

// loopbackAllowedForAlive 探测当前环境是否允许回环 TCP 连接。
func loopbackAllowedForAlive() bool {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return false
	}
	defer ln.Close()
	go acceptAndClose(ln)
	c, err := net.DialTimeout("tcp", ln.Addr().String(), 500*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

// listenLoopback 在回环上监听一个随机端口。
func listenLoopback(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("无法监听回环端口: %v", err)
	}
	return ln
}

// acceptAndClose 持续接受并立即关闭连接, 直到监听器被关闭。
// 端口探测只关心"能否建立连接"(probeHost 用 DialTimeout 后立即 Close),
// 因此不需要回任何数据。
func acceptAndClose(ln net.Listener) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		_ = c.Close()
	}
}

// TestHasConfirmedResponse 确定性证据 = ICMP 或 ARP 任一应答。
func TestHasConfirmedResponse(t *testing.T) {
	cases := []struct {
		icmp, arp bool
		want      bool
	}{
		{true, false, true},   // 只有 ICMP 应答: 确定存活
		{false, true, true},   // 只有 ARP 应答(防火墙丢 ICMP 的常见情形): 同样确定存活
		{true, true, true},    // 都有
		{false, false, false}, // 都没有: 只能靠端口推断
	}
	for _, c := range cases {
		if got := HasConfirmedResponse(c.icmp, c.arp); got != c.want {
			t.Errorf("HasConfirmedResponse(icmp=%v, arp=%v) = %v, 期望 %v", c.icmp, c.arp, got, c.want)
		}
	}
}

// TestClassifyAlive 三路证据 -> 存活结论的穷举(宽松/严格两类口径)。
//
// 这是"存活扫描"最核心的判定口径: 把"端口开放"当成与 ICMP/ARP 同等可信, 严格
// 模式就形同虚设; 反过来把端口推断的主机直接丢弃, 用户就看不到"这台机器其实在",
// 无法判断是否漏扫。因此对 8 种证据组合全部断言。
func TestClassifyAlive(t *testing.T) {
	cases := []struct {
		name             string
		strict, icmp, arp bool
		wantAlive        bool // 是否计入存活
		wantExcluded     bool // 是否被严格模式排除
		wantInferred     bool // 是否仅凭端口推断
	}{
		// 宽松模式: ICMP/ARP 应答或端口开放都算存活
		{"宽松/仅ICMP", false, true, false, true, false, false},
		{"宽松/仅ARP", false, false, true, true, false, false},
		{"宽松/ICMP+ARP", false, true, true, true, false, false},
		{"宽松/仅端口(无确定性证据)", false, false, false, true, false, true},
		// 严格模式: 只认 ICMP/ARP; 仅端口开放者被排除但仍标记 inferred
		{"严格/仅ICMP", true, true, false, true, false, false},
		{"严格/仅ARP", true, false, true, true, false, false},
		{"严格/ICMP+ARP", true, true, true, true, false, false},
		{"严格/仅端口 -> 排除但不算消失", true, false, false, false, true, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			alive, excluded, inferred := classifyAlive(c.strict, c.icmp, c.arp)
			if alive != c.wantAlive || excluded != c.wantExcluded || inferred != c.wantInferred {
				t.Errorf("classifyAlive(strict=%v, icmp=%v, arp=%v) = (alive=%v, excluded=%v, inferred=%v), 期望 (%v, %v, %v)",
					c.strict, c.icmp, c.arp, alive, excluded, inferred,
					c.wantAlive, c.wantExcluded, c.wantInferred)
			}
		})
	}
}

// TestClassifyAliveStrictNeverCountsPortOnly 严格模式的核心不变量:
// "仅端口开放"绝不能计入存活(否则严格模式与宽松模式没有区别)。
//
// 单独再钉一遍的原因: 这是需求里"strict 只用 ARP+ICMP 判定"的硬约束, 一旦被
// 改成宽松口径, 用户做"我只想验证某几台机器在不在线"时会得到一堆误报。
func TestClassifyAliveStrictNeverCountsPortOnly(t *testing.T) {
	for _, icmp := range []bool{false, true} {
		for _, arp := range []bool{false, true} {
			alive, _, _ := classifyAlive(true, icmp, arp)
			want := icmp || arp
			if alive != want {
				t.Errorf("严格模式 icmp=%v arp=%v: 计入存活=%v, 期望 %v(仅 ICMP/ARP 应答算存活)",
					icmp, arp, alive, want)
			}
		}
	}
}

// TestScanIPsEmptyHosts 空目标列表必须安全返回(不能 panic 或除零)。
//
// emit 在 scanIPsWithMode 里是无条件调用的, 传 nil 会空指针 —— 这里用空实现
// 验证"没有任何主机时也不会触碰回调以外的东西"。
func TestScanIPsEmptyHosts(t *testing.T) {
	alive, excluded := scanIPsWithMode(context.Background(), nil, []int{80}, 10, 0, false, func(string, any) {})
	if alive != 0 || excluded != 0 {
		t.Errorf("空目标应返回 0/0, 实际 %d/%d", alive, excluded)
	}
}

// TestBuildIPEventCarriesPorts 三种证据形态下, 事件都必须带上已探到的开放端口。
//
// 这是 c3 的核心契约, 且**不依赖网络**因此能在 CI 稳定执行(回环用例在沙箱里会
// Skip, 不能作为唯一保障)。分别覆盖: 有确定性证据 / 仅端口推断 / 严格模式被排除。
func TestBuildIPEventCarriesPorts(t *testing.T) {
	cases := []struct {
		name             string
		res              hostProbeResult
		inferred         bool
		excludedByStrict bool
	}{
		{
			name:     "ICMP 应答且端口开放",
			res:      hostProbeResult{alive: true, icmp: true, rtt: 3, ports: []int{22, 445}},
			inferred: false,
		},
		{
			name:     "仅端口推断(宽松)",
			res:      hostProbeResult{alive: true, ports: []int{8080}},
			inferred: true,
		},
		{
			name:             "严格模式排除(仅端口开放)",
			res:              hostProbeResult{alive: true, ports: []int{3389, 445}},
			inferred:         true,
			excludedByStrict: true,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := buildIPEvent("10.0.0.9", c.res, c.inferred, c.excludedByStrict)

			ports, ok := ev["ports"]
			if !ok {
				t.Fatal("事件缺少 ports 字段: 用户拿不到顺带探到的开放端口, 会再跑一次端口扫描")
			}
			got, isSlice := ports.([]int)
			if !isSlice {
				t.Fatalf("ports 应为 []int(JSON 数组), 实际 %T", ports)
			}
			if len(got) != len(c.res.ports) {
				t.Fatalf("ports 应为 %v, 实际 %v(端口信息被丢弃/篡改)", c.res.ports, got)
			}
			for i := range got {
				if got[i] != c.res.ports[i] {
					t.Errorf("ports[%d] 应为 %d, 实际 %d", i, c.res.ports[i], got[i])
				}
			}
			if v, _ := ev["inferred"].(bool); v != c.inferred {
				t.Errorf("inferred 应为 %v, 实际 %v", c.inferred, v)
			}
			if v, _ := ev["excludedByStrict"].(bool); v != c.excludedByStrict {
				t.Errorf("excludedByStrict 应为 %v, 实际 %v", c.excludedByStrict, v)
			}
			if v, _ := ev["alive"].(bool); !v {
				t.Error("alive 应为 true(此函数只处理有响应的主机)")
			}
		})
	}
}

// TestBuildIPEventPortsNeverNil 无开放端口时 ports 必须序列化成 [] 而不是 null。
//
// 【必须断言 JSON 输出, 不能断言 `ev["ports"] == nil`】这是踩过的真实坑:
// res.ports 为 []int(nil) 时, 把它存进 any 得到的是"类型 []int、值 nil"的
// **非空接口**, 与 nil 比较恒为 false。于是:
//
//	if ev["ports"] == nil { ev["ports"] = []int{} }   // 死代码, 归一化静默失效
//
// 而基于 `ports == nil` 的断言同样恒为 false, 会给出"测试通过、线上 null"的
// 假绿 —— 本用例曾在真机冒烟里以 `"ports":null` 的形式暴露, 故改为直接断言
// 序列化结果(前端真正看到的东西)。
func TestBuildIPEventPortsNeverNil(t *testing.T) {
	ev := buildIPEvent("10.0.0.9", hostProbeResult{alive: true, icmp: true}, false, false)
	raw, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("序列化失败: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatalf("反序列化失败: %v", err)
	}
	ports, ok := decoded["ports"]
	if !ok {
		t.Fatal("事件缺少 ports 字段")
	}
	if ports == nil {
		t.Fatalf("ports 序列化成了 null(前端统计/展示按数组处理): %s", raw)
	}
	arr, isArr := ports.([]any)
	if !isArr {
		t.Fatalf("ports 应序列化为 JSON 数组, 实际 %T(%s)", ports, raw)
	}
	if len(arr) != 0 {
		t.Errorf("无开放端口时应为空数组, 实际 %v", arr)
	}
	// 顺带钉住: 未探到任何端口时也不能凭空多出 ports 内容
	if bytes.Contains(raw, []byte(`"ports":null`)) {
		t.Errorf("JSON 中不应出现 \"ports\":null: %s", raw)
	}
}

// TestBuildIPEventMACOnlyWhenPresent mac 字段只在真的有 MAC 时出现。
//
// 前端按 `d.mac ? ' '+d.mac : ''` 拼接展示。若恒带空字符串的 mac, 前端会渲染出
// "ARP " 后面跟一个空格再接空的怪异文案; 不带该键则走空串分支, 展示干净。
func TestBuildIPEventMACOnlyWhenPresent(t *testing.T) {
	without := buildIPEvent("10.0.0.9", hostProbeResult{alive: true, icmp: true}, false, false)
	if _, ok := without["mac"]; ok {
		t.Error("没有 MAC 时不应带 mac 字段(前端会渲染出多余空格)")
	}
	with := buildIPEvent("10.0.0.9", hostProbeResult{alive: true, arp: true, mac: "aa:bb:cc:dd:ee:ff"}, false, false)
	if v, _ := with["mac"].(string); v != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("有 MAC 时应原样带回, 实际 %v", with["mac"])
	}
}

// TestIPEventAlwaysCarriesPortsField 存活扫描的 ip 事件必须**始终**带 ports 字段。
//
// 这是本模块的对外契约: 前端把 d.ports 直接渲染成"开放端口"列(index.html
// handleEvent 的 ip 分支), 且用户已被告知"无需再跑端口扫描"。若某条分支漏传
// ports, 前端拿到 undefined 会渲染成空白, 用户会以为"这台主机没开放端口",
// 而真相是"服务端没回传" —— 这类缺陷不报错、只误导。
//
// 用不可能有响应的目标(保留测试网段)保证走"非存活"分支, 覆盖最容易被漏改的
// 那条 emit 路径; 不依赖真实网络能力, 因此在沙箱里也稳定执行。
func TestIPEventAlwaysCarriesPortsField(t *testing.T) {
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
	// 198.51.100.0/24(RFC5737 文档保留段): 真实网络中不会有主机应答,
	// 也不属于本机网段, 因此 ARP 不会有应答 —— 结果稳定为"非存活"
	const host = "198.51.100.7"
	scanIPsWithMode(context.Background(), []string{host}, []int{80}, 2, 300*time.Millisecond, false, emit)

	mu.Lock()
	ev, ok := events[host]
	mu.Unlock()
	if !ok {
		t.Fatalf("未收到 %s 的 ip 事件(每条主机都必须逐条上报, 否则用户无法判断是否漏扫)", host)
	}
	ports, hasPorts := ev["ports"]
	if !hasPorts {
		t.Fatal("ip 事件缺少 ports 字段: 前端会渲染成空白, 用户误以为该主机没有开放端口")
	}
	// 必须是非 nil 的切片(前端用 (d.ports || []).length 判断; 回传 null 也能被
	// || 兜住, 但明确回传空切片语义更清晰, 也让 JSON 序列化成 [] 而非 null)
	if _, isSlice := ports.([]int); !isSlice {
		t.Fatalf("ports 字段应为 []int, 实际 %T", ports)
	}
	// 非存活事件必须显式带 alive=false, 前端据此走"离线"分支
	if alive, _ := ev["alive"].(bool); alive {
		t.Error("198.51.100.7 不该被判为存活(文档保留段无真实主机)")
	}
}

// TestIPEventPortsReportedWhenStrictExcludes 严格模式下"仅端口开放"的主机:
// 不计入存活, 但**端口信息必须照常上报**。
//
// 这正是 c3 要解决的核心诉求 —— 存活探测顺带探到的开放端口是有用信息, 丢弃它
// 会让用户为了拿端口清单再跑一次端口扫描(同一批端口被探两遍)。同时严格模式的
// 存活口径不能因此放宽(排除数要 +1)。需要真实回环监听, 沙箱不可用时跳过。
func TestIPEventPortsReportedWhenStrictExcludes(t *testing.T) {
	if !loopbackAllowedForAlive() {
		t.Skip("沙箱拦截回环 TCP 连接, 跳过(该场景由真机联调覆盖)")
	}
	// 该用例依赖"127.0.0.1 无 ICMP/ARP 应答, 只有端口开放"来构造严格模式的
	// "仅端口"分支。提权环境下回环 ICMP 必答(127.0.0.1 会被正确判为确定存活),
	// 前提不成立 —— 此时跑用例会误报严格模式"放宽了口径", 故按环境跳过。
	if InitICMP() {
		t.Skip("当前环境有 ICMP 权限(提权), 127.0.0.1 会收到 ICMP 应答, 无法构造'仅端口开放'场景; 该场景由非管理员环境覆盖")
	}
	ln := listenLoopback(t)
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port
	go acceptAndClose(ln)

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
	// 只探这一个端口(已确认开放); 127.0.0.1 不会有 ARP 应答, ICMP 在非管理员下
	// 也拿不到 -> 走"仅端口开放"分支
	const host = "127.0.0.1"
	alive, excluded := scanIPsWithMode(context.Background(), []string{host}, []int{port}, 2, 600*time.Millisecond, true, emit)

	if alive != 0 {
		t.Errorf("严格模式下仅端口开放的主机不应计入存活, 实际存活 %d", alive)
	}
	if excluded != 1 {
		t.Errorf("严格模式应排除 1 台(仅端口开放), 实际 %d", excluded)
	}

	mu.Lock()
	ev, ok := events[host]
	mu.Unlock()
	if !ok {
		t.Fatal("未收到 ip 事件")
	}
	if excludedByStrict, _ := ev["excludedByStrict"].(bool); !excludedByStrict {
		t.Error("被严格模式排除的主机应带 excludedByStrict=true(前端据此显示'端口推断'而非'存活')")
	}
	if inferred, _ := ev["inferred"].(bool); !inferred {
		t.Error("仅凭端口开放的主机应带 inferred=true(证据来源标注)")
	}
	got, _ := ev["ports"].([]int)
	found := false
	for _, p := range got {
		if p == port {
			found = true
		}
	}
	if !found {
		t.Errorf("严格模式排除的主机也必须上报已探到的开放端口, 期望含 %d, 实际 %v", port, got)
	}
}

