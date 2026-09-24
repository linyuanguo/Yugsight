// collect_test.go 采集底座契约测试(全部离线, 不发起真实网络)。
//
// 只守"改坏会静默失效"的契约:
//   - 白名单: 空=放行, 非空=只放行命中(CIDR/单IP/坏条目忽略不废全局);
//   - 限速: 令牌桶容量=速率, 取空不阻塞;
//   - 调度: 到期任务被执行, 白名单外不执行, 异常事件边缘触发(离线/恢复);
//   - 解析: NetFlow v5 / IPFIX(模板+数据) 字节级解析, RESTCONF/NETCONF 结构提取,
//     SSH /proc 差分 —— 这些是"协议解析错=指标全错"的硬契约。
package collect

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"strings"
	"testing"
	"time"
)

// ===== 白名单 =====

func TestWhitelistEmptyAllowsAll(t *testing.T) {
	w, _ := NewWhitelist(nil)
	if !w.Empty() || !w.Allow("1.2.3.4") {
		t.Fatal("空白名单应放行一切")
	}
}

func TestWhitelistMatch(t *testing.T) {
	w, bad := NewWhitelist([]string{"10.0.0.1", "192.168.1.0/24", "not-an-ip"})
	if len(bad) != 1 {
		t.Fatalf("坏条目应被忽略, got %v", bad)
	}
	for _, ip := range []string{"10.0.0.1", "192.168.1.55"} {
		if !w.Allow(ip) {
			t.Fatalf("白名单应放行 %s", ip)
		}
	}
	for _, ip := range []string{"10.0.0.2", "172.16.0.1"} {
		if w.Allow(ip) {
			t.Fatalf("白名单不应放行 %s", ip)
		}
	}
	// 无法解析的地址: 有白名单时拒绝
	if w.Allow("garbage") {
		t.Fatal("有白名单时, 不可解析地址必须拒绝")
	}
}

// ===== 限速 =====

func TestLimiterBurstThenStarve(t *testing.T) {
	l := NewLimiter(3)
	// 容量=速率: 连续取 3 个成功, 第 4 个(几乎无补充)必须失败
	for i := 0; i < 3; i++ {
		if !l.TryTake() {
			t.Fatalf("第 %d 个令牌应取到", i+1)
		}
	}
	if l.TryTake() {
		t.Fatal("桶空时 TryTake 必须立即失败(不阻塞)")
	}
}

// ===== 调度 + 事件(用假采集器, 不碰网络) =====

// fakeOK 成功采集器: 返回 cpu 指标。
func fakeOK(cpu float64) Collector {
	return func(ctx context.Context, e *Engine, t Task) *Round {
		r := newRound(t, time.Now())
		r.OK = true
		r.Metrics = append(r.Metrics, Metric{Name: "cpu", Value: cpu, Unit: "%"})
		return r
	}
}

func TestEngineRunTaskRecordsRound(t *testing.T) {
	cfg := Config{Enabled: true, IntervalSec: 60}
	cfg.Tasks = []Task{{ID: "t1", Side: SideHost, Protocol: "icmp", Target: "10.0.0.1", Enabled: true}}
	e := New(cfg, func() Config { return cfg }, nil)
	Register("testok", fakeOK(10))
	// 手动跑一轮
	t1 := cfg.Tasks[0]
	t1.Protocol = "testok"
	r := e.CollectNow(context.Background(), t1)
	if r == nil || !r.OK {
		t.Fatalf("采集应成功, got %+v", r)
	}
	got := e.Store().LatestOf("t1")
	if got == nil || got.OK != true {
		t.Fatal("Store 应记录最新轮次")
	}
	if metricValue(got, "cpu") != 10 {
		t.Fatalf("cpu 指标应为 10, got %v", metricValue(got, "cpu"))
	}
}

func TestEngineWhitelistBlocks(t *testing.T) {
	cfg := Config{Enabled: true, IntervalSec: 60, Whitelist: []string{"10.0.0.0/8"}}
	cfg.Tasks = []Task{{ID: "t1", Side: SideHost, Protocol: "testok", Target: "172.16.1.1", Enabled: true}}
	e := New(cfg, func() Config { return cfg }, nil)
	r := e.CollectNow(context.Background(), cfg.Tasks[0])
	if r == nil || r.OK {
		t.Fatalf("白名单外目标必须被拦截(不执行采集), got %+v", r)
	}
	if !strings.Contains(r.Err, "白名单") {
		t.Fatalf("拦截原因应说明白名单, got %q", r.Err)
	}
}

func TestEngineOfflineAndRecoverEvents(t *testing.T) {
	cfg := Config{Enabled: true, IntervalSec: 60}
	cfg.Alerts.FailStreak = 2
	var events []Event
	e := New(cfg, func() Config { return cfg }, nil)
	e.SetEventHook(func(ev *Event) { events = append(events, *ev) })

	t1 := Task{ID: "t1", Side: SideHost, Protocol: "testok", Target: "10.0.0.1", Enabled: true}
	Register("testok", fakeOK(5))

	// 第 1 轮成功 → 在线
	e.CollectNow(context.Background(), t1)
	// 第 2 轮起失败: 用返回失败的采集器
	Register("testok", func(ctx context.Context, e *Engine, t Task) *Round {
		r := newRound(t, time.Now())
		r.OK = false
		r.Err = "timeout"
		return r
	})
	e.CollectNow(context.Background(), t1) // failStreak=1, 未达阈值
	e.CollectNow(context.Background(), t1) // failStreak=2, 达阈值 → offline

	hasOffline := false
	for _, ev := range events {
		if ev.Type == EvtOffline && ev.Level == EvtCritical {
			hasOffline = true
		}
	}
	if !hasOffline {
		t.Fatalf("连续失败达阈值应产生 offline(critical) 事件, got %+v", events)
	}

	// 恢复 → recover
	Register("testok", fakeOK(5))
	e.CollectNow(context.Background(), t1)
	hasRecover := false
	for _, ev := range events {
		if ev.Type == EvtRecover {
			hasRecover = true
		}
	}
	if !hasRecover {
		t.Fatalf("恢复后应产生 recover 事件, got %+v", events)
	}
}

func TestEngineThresholdEdgeOnly(t *testing.T) {
	cfg := Config{Enabled: true, IntervalSec: 60}
	cfg.Alerts.CPUPct = 90
	cfg.Alerts.FailStreak = 100 // 避免离线事件干扰
	var events []Event
	e := New(cfg, func() Config { return cfg }, nil)
	e.SetEventHook(func(ev *Event) { events = append(events, *ev) })
	t1 := Task{ID: "t1", Side: SideHost, Protocol: "testok", Target: "10.0.0.1", Enabled: true}

	// 从 10% 跨到 95% → 一次 high_cpu
	Register("testok", fakeOK(10))
	e.CollectNow(context.Background(), t1)
	Register("testok", fakeOK(95))
	e.CollectNow(context.Background(), t1)
	// 持续 96% → 不再重复报(边缘触发)
	Register("testok", fakeOK(96))
	e.CollectNow(context.Background(), t1)

	n := 0
	for _, ev := range events {
		if ev.Type == EvtHighCPU {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("CPU 越限应只报一次(边缘触发), 实际 %d 次: %+v", n, events)
	}
}

// ===== NetFlow v5 解析 =====

// buildV5 构造一个 NetFlow v5 包(24 字节头 + count 个 48 字节记录)。
//
// 字段偏移按真实 v5 线格式: 头 24B(含 flowSequence), 记录内
// pkts@17 bytes@21 srcport@33 dstport@35。v5 是累计计数器: 第 i 条记录
// 计数 = 1000*(i+1) 包 / 200000*(i+1) 字节, 差分后每记录贡献 1000 包,
// 与断言(2 条记录 → 总 2000 包)一致。
func buildV5(t *testing.T, records int) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	// 24 字节头
	binary.Write(buf, binary.BigEndian, uint16(5)) // version
	binary.Write(buf, binary.BigEndian, uint16(records))
	binary.Write(buf, binary.BigEndian, uint32(0)) // sysUptime
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	binary.Write(buf, binary.BigEndian, uint32(0)) // unixNsecs
	binary.Write(buf, binary.BigEndian, uint32(0)) // flowSequence
	binary.Write(buf, binary.BigEndian, uint8(0))  // engineType
	binary.Write(buf, binary.BigEndian, uint8(1))  // engineId
	binary.Write(buf, binary.BigEndian, uint16(0)) // reserved
	for i := 0; i < records; i++ {
		rec := make([]byte, 48)
		rec[0] = 6 // protocol: tcp
		copy(rec[1:5], net.IPv4(192, 168, 1, 10).To4()) // srcaddr
		copy(rec[5:9], net.IPv4(192, 168, 1, 20).To4()) // dstaddr
		binary.BigEndian.PutUint32(rec[17:21], 1000*uint32(i+1))   // pkts(累计)
		binary.BigEndian.PutUint32(rec[21:25], 200000*uint32(i+1)) // bytes(累计)
		binary.BigEndian.PutUint16(rec[33:35], 12345) // srcport
		binary.BigEndian.PutUint16(rec[35:37], 80)    // dstport
		buf.Write(rec)
	}
	return buf.Bytes()
}

func TestParseNetFlowV5(t *testing.T) {
	agg := newFlowAgg()
	agg.addV5(buildV5(t, 2))
	active, totalB, totalP, top := agg.takeWindow()
	if active != 1 { // 两条记录同五元组 → 合并为 1 条流
		t.Fatalf("应合并为 1 条流, got %d", active)
	}
	if totalP != 2000 {
		t.Fatalf("总包数应为 2000, got %d", totalP)
	}
	if totalB != 400000 {
		t.Fatalf("总字节应为 400000, got %d", totalB)
	}
	if len(top) != 1 || top[0].proto != "tcp" || top[0].sport != 12345 || top[0].dport != 80 {
		t.Fatalf("TOP 流解析错误: %+v", top)
	}
}

// TestParseNetFlowV5CounterDiff v5 是累计计数器: 同一流两次记录应做差分。
func TestParseNetFlowV5CounterDiff(t *testing.T) {
	agg := newFlowAgg()
	// 第一次: bytes=1000(首条以 0 为基准, 本窗口增量=1000)
	agg.addV5(withV5Bytes(buildV5(t, 1), 1000))
	agg.takeWindow() // 取走, 基准停在 1000
	// 第二次: bytes=3000 → 差分后本窗口增量应为 2000
	agg.addV5(withV5Bytes(buildV5(t, 1), 3000))
	_, totalB, _, _ := agg.takeWindow()
	if totalB != 2000 {
		t.Fatalf("v5 累计计数器应做差分(3000-1000=2000), got %d", totalB)
	}
}

func withV5Bytes(p []byte, b uint32) []byte {
	out := make([]byte, len(p))
	copy(out, p)
	// 首条记录内 bytes 字段: 头 24B + 记录偏移 21, 4 字节
	binary.BigEndian.PutUint32(out[24+21:24+25], b)
	return out
}

// ===== NetFlow IPFIX 解析 =====

// buildIPFIX 构造一个 IPFIX 消息: 模板集(setID=2) + 数据集(setID=100)。
func buildIPFIX(t *testing.T) []byte {
	t.Helper()
	buf := new(bytes.Buffer)
	// 消息头(16 字节)
	binary.Write(buf, binary.BigEndian, uint16(10)) // version
	msgLen := 16 + 4 + 4 + 4*3 + 4 + 4*3 // 占位, 下面按实际算
	// 模板集: setID=2, 字段: byteCount(1,4) packetCount(2,4) srcIP(33,4) dstIP(34,4)
	tmplBody := new(bytes.Buffer)
	binary.Write(tmplBody, binary.BigEndian, uint16(100)) // templateID
	binary.Write(tmplBody, binary.BigEndian, uint16(4))   // fieldCount
	for _, f := range [][2]uint16{{1, 4}, {2, 4}, {33, 4}, {34, 4}} {
		binary.Write(tmplBody, binary.BigEndian, f[0])
		binary.Write(tmplBody, binary.BigEndian, f[1])
	}
	tmplSet := new(bytes.Buffer)
	binary.Write(tmplSet, binary.BigEndian, uint16(2)) // setID
	binary.Write(tmplSet, binary.BigEndian, uint16(4+len(tmplBody.Bytes())))
	tmplSet.Write(tmplBody.Bytes())

	// 数据集: setID=100, 一条记录(16 字节)
	rec := new(bytes.Buffer)
	binary.Write(rec, binary.BigEndian, uint32(5000))   // byteCount
	binary.Write(rec, binary.BigEndian, uint32(50))     // packetCount
	binary.Write(rec, binary.BigEndian, []byte{10, 0, 0, 1}) // srcIP 10.0.0.1
	binary.Write(rec, binary.BigEndian, []byte{10, 0, 0, 2}) // dstIP 10.0.0.2
	dataSet := new(bytes.Buffer)
	binary.Write(dataSet, binary.BigEndian, uint16(100))
	binary.Write(dataSet, binary.BigEndian, uint16(4+len(rec.Bytes())))
	dataSet.Write(rec.Bytes())

	sets := new(bytes.Buffer)
	sets.Write(tmplSet.Bytes())
	sets.Write(dataSet.Bytes())
	msgLen = 16 + sets.Len()

	// 重写消息头
	buf.Reset()
	binary.Write(buf, binary.BigEndian, uint16(10))
	binary.Write(buf, binary.BigEndian, uint16(msgLen))
	binary.Write(buf, binary.BigEndian, uint32(time.Now().Unix()))
	binary.Write(buf, binary.BigEndian, uint32(1)) // seq
	binary.Write(buf, binary.BigEndian, uint32(1)) // domain
	buf.Write(sets.Bytes())
	return buf.Bytes()
}

func TestParseIPFIX(t *testing.T) {
	agg := newFlowAgg()
	agg.addIPFIX(buildIPFIX(t))
	active, totalB, totalP, top := agg.takeWindow()
	if active != 1 {
		t.Fatalf("IPFIX 应解析出 1 条流, got %d", active)
	}
	if totalB != 5000 || totalP != 50 {
		t.Fatalf("IPFIX 字节/包数错误: %d/%d", totalB, totalP)
	}
	if len(top) != 1 || top[0].src != "10.0.0.1" || top[0].dst != "10.0.0.2" {
		t.Fatalf("IPFIX 五元组解析错误: %+v", top)
	}
}

// ===== RESTCONF 解析 =====

func TestFindInterfacesIETF(t *testing.T) {
	data := map[string]any{
		"ietf-interfaces:interfaces": map[string]any{
			"interface": []any{
				map[string]any{
					"name":         "eth0",
					"oper-state":   "up",
					"ifindex":      float64(2),
					"counters": map[string]any{
						"inbound-pkts":  float64(1000),
						"outbound-pkts": float64(2000),
						"inbound-octets": float64(100000),
					},
				},
				map[string]any{"name": "lo0", "oper-state": "up"},
			},
		},
	}
	ifaces, ok := findInterfaces(data)
	if !ok || len(ifaces) != 2 {
		t.Fatalf("应找到 2 个接口, ok=%v len=%d", ok, len(ifaces))
	}
}

func TestFindInterfacesOpenConfig(t *testing.T) {
	data := map[string]any{
		"openconfig-interfaces:interfaces": map[string]any{
			"interface": []any{
				map[string]any{
					"name": "Ethernet1",
					"state": map[string]any{
						"oper-status": "UP",
						"counters": map[string]any{
							"in-pkts": float64(500),
						},
					},
				},
			},
		},
	}
	ifaces, ok := findInterfaces(data)
	if !ok || len(ifaces) != 1 {
		t.Fatalf("openconfig 应找到 1 个接口, ok=%v", ok)
	}
}

// ===== NETCONF 解析 =====

func TestParseXMLTreeAndInterfaces(t *testing.T) {
	xml := `<rpc-reply><data><interfaces>
		<interface><name>eth0</name><oper-state>UP</oper-state>
		  <counters><in-pkts>100</in-pkts><out-pkts>200</out-pkts></counters>
		</interface>
		<interface><name>lo0</name><oper-state>DOWN</oper-state></interface>
	</interfaces></data></rpc-reply>`
	ifaces, ok := netconfInterfaces(xml)
	if !ok || len(ifaces) != 2 {
		t.Fatalf("应解析出 2 个接口, ok=%v", ok)
	}
	if ifaces[0].name != "eth0" || ifaces[0].state != "UP" {
		t.Fatalf("eth0 解析错误: %+v", ifaces[0])
	}
	if v, ok := ifaces[0].leafs["in-pkts"]; !ok || v != "100" {
		t.Fatalf("eth0 in-pkts 应为 100, got %q", v)
	}
}

// ===== WinRM 解码 =====

func TestDecodeWSMAN(t *testing.T) {
	// base64("hello")
	if got := decodeWSMAN("aGVsbG8="); got != "hello" {
		t.Fatalf("应解码为 hello, got %q", got)
	}
	if got := decodeWSMAN(""); got != "" {
		t.Fatalf("空串应保持空, got %q", got)
	}
	// 非法 base64 原样返回
	if got := decodeWSMAN("not-base64!!!"); got != "not-base64!!!" {
		t.Fatalf("非法 base64 应原样返回, got %q", got)
	}
}

// ===== SSH /proc 解析 =====

func TestCPUFromStat(t *testing.T) {
	// 两次采样: total 1000→2000(Δ=1000), idle 1000→1500(Δ=500) → CPU = 1 - 500/1000 = 50%
	stat := "cpu  0 0 0 1000 0 0 0 0\ncpu  500 0 0 1500 0 0 0 0\n"
	cpu, ok := cpuFromStat(stat)
	if !ok {
		t.Fatal("应成功解析")
	}
	if cpu < 49 || cpu > 51 {
		t.Fatalf("CPU 应约 50%%, got %.1f", cpu)
	}
}

func TestParseSSHOutput(t *testing.T) {
	out := "MARK-STAT\ncpu  0 0 0 1000 0 0 0 0\ncpu  500 0 0 1500 0 0 0 0\n" +
		"MARK-MEM\nMemTotal:       8000000 kB\nMemAvailable:   4000000 kB\n" +
		"MARK-LOAD\n0.50 0.40 0.30 2/100 1234\n" +
		"MARK-UPTIME\n3600\n" +
		"MARK-DISK\n/dev/sda1  1000000000 500000000 500000000  50% /\n" +
		"MARK-PROC\nPID COMM %CPU %MEM\n  1 systemd 0.1 0.5\n 100 nginx 5.0 1.2\n" +
		"MARK-EVENTS\nJan 1 00:00:00 host kernel: warning msg\n"
	r := &Round{}
	parseSSHOutput(r, out)
	m := map[string]Metric{}
	for _, x := range r.Metrics {
		m[x.Name] = x
	}
	if m["cpu"].Value < 49 || m["cpu"].Value > 51 {
		t.Fatalf("CPU 应约 50%%, got %v", m["cpu"].Value)
	}
	if m["mem_total"].Value <= 0 {
		t.Fatal("mem_total 应 >0")
	}
	if m["load1"].Value != 0.5 {
		t.Fatalf("load1 应为 0.5, got %v", m["load1"].Value)
	}
	if m["uptime"].Value != 3600 {
		t.Fatalf("uptime 应为 3600, got %v", m["uptime"].Value)
	}
	if len(m) == 0 {
		t.Fatal("应解析出指标")
	}
}

// ===== 配置默认值 =====

func TestConfigWithDefaults(t *testing.T) {
	c := Config{}.WithDefaults()
	if c.IntervalSec != 60 || c.Concurrent != 4 || c.GlobalRate != 10 {
		t.Fatalf("默认值错误: %+v", c)
	}
	if c.NetFlow.Listen != "0.0.0.0:2000" {
		t.Fatalf("NetFlow 默认监听错误: %s", c.NetFlow.Listen)
	}
	// 任务间隔钳制: 1s < 5s 下限 → 提到 5s
	if iv := c.TaskInterval(Task{IntervalSec: 1}); iv != 5*time.Second {
		t.Fatalf("任务间隔应钳制到 5s, got %v", iv)
	}
}
