package scanner

import (
	"encoding/binary"
	"testing"
	"time"
)

// ===== 环路检测测试 =====
//
// 【本文件的重点是"必须不误报"】旧实现的两处误报都被实测复现过:
//   - 一条普通 TCP 流的第 80 个包触发"疑似二层环路"(帧指纹不覆盖端口/载荷)
//   - TTL 64/63/62 这种正常三跳路径触发"疑似三层环路"(只看种类数不看差值)
//
// 误报的代价远高于漏报: 一条假的环路告警会让运维去拔网线排查。所以下面的
// 反向用例(TestLoop_NoFalsePositive_*) 比正向用例更重要。

// mkIPFrame 构造一个以太网 + IPv4 + (可选)TCP 帧。
//
// id/ttl/proto 可调; port 与 payload 用来制造"同连接不同包"的干扰流量。
func mkIPFrame(id uint16, ttl, proto byte, sport, dport uint16, payload []byte) []byte {
	ihl := 20
	p := make([]byte, 14+ihl+8+len(payload))
	// 以太头: dst/src MAC
	copy(p[0:6], []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x01})
	copy(p[6:12], []byte{0xaa, 0xbb, 0xcc, 0x00, 0x00, 0x02})
	binary.BigEndian.PutUint16(p[12:14], ethTypeIPv4)
	// IPv4 头
	p[14] = 0x45 // version 4, ihl 5
	total := uint16(ihl + 8 + len(payload))
	binary.BigEndian.PutUint16(p[16:18], total)
	binary.BigEndian.PutUint16(p[18:20], id)
	p[22] = ttl
	p[23] = proto
	// 首部校验和: 用固定值填充, 保证同参数帧的校验和一致(测试不校验真实性)
	binary.BigEndian.PutUint16(p[24:26], 0x1234)
	copy(p[26:30], []byte{192, 168, 1, 143})
	copy(p[30:34], []byte{192, 168, 1, 1})
	// TCP/UDP 端口
	if proto == 6 || proto == 17 {
		binary.BigEndian.PutUint16(p[34:36], sport)
		binary.BigEndian.PutUint16(p[36:38], dport)
	}
	copy(p[14+ihl+8:], payload)
	return p
}

// ===== 必须不误报(反向用例) =====

// TestLoop_NoFalsePositive_TCPStream 一条正常 TCP 连接的大量数据包不得报环路。
//
// 【这是旧实现最主要的误报】旧帧指纹只哈希到 IP 头的 ihl(20 字节, 正好在 TTL
// 处截断), 既不含端口也不含载荷 → 同连接所有包指纹相同 → 80 个包必报
// "疑似二层环路"。实测: 100 个包触发 1 条告警。
func TestLoop_NoFalsePositive_TCPStream(t *testing.T) {
	d := NewLoopDetector(true)
	base := time.Now()
	for i := 0; i < 300; i++ {
		// 同一连接(端口固定), 内容逐包不同, id 恒为 0(Windows 已连接 TCP 的常见行为)
		pkt := mkIPFrame(0, 64, 6, 51000, 443, []byte{byte(i), byte(i >> 8), 0xaa})
		alarms := d.ObserveIPv4(pkt, base.Add(time.Duration(i)*time.Millisecond))
		for _, a := range alarms {
			t.Errorf("正常 TCP 流量误报 %q: %s", a.Title, a.Detail)
		}
	}
}

// TestLoop_NoFalsePositive_TTLKinds 只看"TTL 种类数"是不够的: 三个互不相邻的
// TTL 值(如 64/128/255, 或 64/62)不代表环路, 因为环路特征是"逐跳减 1"。
//
// 【旧实现会报】判据是 len(ttlSet) >= 3, 所以 {64,128,255} 和 {64,63,62} 一样
// 都会被判为环路。而 64/63/62 恰恰是完全正常的三跳路径。
func TestLoop_NoFalsePositive_TTLKinds(t *testing.T) {
	cases := []struct {
		name string
		ttls []byte
	}{
		// 旧实现会误报的典型: 连续递减但只观测了 3 种值? -> 这是真环路特征, 见正向用例
		// 这里放的是"看起来像但差值≠1"的序列
		{"跨度大(正常多跳)", []byte{255, 128, 64}},
		{"差值 2 的跳变", []byte{64, 62, 60}},
		{"乱序", []byte{62, 64, 63}},
		{"先降后升", []byte{64, 63, 65}},
		{"同值重复", []byte{64, 64, 64, 64, 64}},
		{"两段各两步不连续", []byte{64, 63, 128, 127}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d := NewLoopDetector(true)
			base := time.Now()
			// 同一个"逻辑报文"(id 固定、内容固定)反复出现, 但 TTL 序列如上
			pkt := mkIPFrame(7, 64, 6, 1234, 80, []byte("same"))
			for i, ttl := range c.ttls {
				pkt[22] = ttl
				alarms := d.ObserveIPv4(pkt, base.Add(time.Duration(i)*10*time.Millisecond))
				for _, a := range alarms {
					t.Errorf("TTL 序列 %v 误报 %q: %s", c.ttls, a.Title, a.Detail)
				}
			}
		})
	}
}

// TestLoop_NoFalsePositive_IDZeroCrossHost id=0 的包来自多台主机时必须区分开。
//
// 【旧实现会报】key 是 src->dst#0, 但这不会把不同主机混在一起(源 IP 不同)。
// 真正的问题在于: **同一对主机的不同 TCP 连接** id 也常为 0, 且源端口不同 ——
// 旧 key 不含端口, 于是这些完全无关的流量被并进一个桶。本用例覆盖"同 src/dst、
// id=0、不同端口"的正常流量。
func TestLoop_NoFalsePositive_IDZeroCrossHost(t *testing.T) {
	d := NewLoopDetector(true)
	base := time.Now()
	// 同一对主机的 50 条不同连接(源端口不同), 每条各发 3 个包, TTL 各不相同
	for c := 0; c < 50; c++ {
		for k := 0; k < 3; k++ {
			ttl := byte(60 + k*2) // 差值 2, 不是环路
			pkt := mkIPFrame(0, ttl, 6, uint16(40000+c), 443, []byte{byte(c)})
			alarms := d.ObserveIPv4(pkt, base.Add(time.Duration(c*10+k)*time.Millisecond))
			for _, a := range alarms {
				t.Errorf("多连接 id=0 流量误报 %q: %s", a.Title, a.Detail)
			}
		}
	}
}

// TestLoop_NoFalsePositive_WindowExpiry 跨时间窗的相同帧不应累计。
//
// 同一个报文在 5 秒窗口外再次出现(如 TCP 重传、或只是周期任务发了同样的包),
// 不构成环路。旧实现完全没有时间窗, 只在处理满 20000 包时清表, 于是"两小时内
// 的 3 个包"也会被算成一次环路。
func TestLoop_NoFalsePositive_WindowExpiry(t *testing.T) {
	d := NewLoopDetector(true)
	base := time.Now()
	pkt := mkIPFrame(9, 64, 6, 4321, 80, []byte("tick"))
	// 每秒发 1 个, 连发 30 个(总跨度 30s, 每个都在上一个的窗口之外)
	for i := 0; i < 30; i++ {
		alarms := d.ObserveIPv4(pkt, base.Add(time.Duration(i)*time.Second))
		for _, a := range alarms {
			t.Errorf("跨窗口重发误报 %q: %s", a.Title, a.Detail)
		}
	}
}

// TestLoop_NoFalsePositive_TCPRetransmit TCP 重传(间隔递增)不应被当作环路。
//
// 这是"二层重复帧"最贴近现实的干扰源: 重传的帧内容与新发完全一致(含校验和),
// 所以会被哈希撞上。区分点在于**间隔**: 环路是密集复制(RTO 之外的固定小间隔),
// 重传间隔按 RTO 指数递增(200ms→400ms→800ms→1.6s→3.2s)。
// 时间窗设为 5 秒, 因此首尾间隔超过 5s 的重传不会被累计到阈值。
func TestLoop_NoFalsePositive_TCPRetransmit(t *testing.T) {
	d := NewLoopDetector(true)
	base := time.Now()
	// RTO 序列缩短到窗口内可观察的范围: 用 20 次重传但总跨度 > 窗口
	gaps := []time.Duration{0, 200, 400, 800, 1600, 3200, 6400}
	at := base
	pkt := mkIPFrame(11, 64, 6, 5555, 80, []byte("retrans"))
	for _, g := range gaps {
		at = at.Add(g * time.Millisecond)
		for _, a := range d.ObserveIPv4(pkt, at) {
			t.Errorf("TCP 重传误报 %q: %s", a.Title, a.Detail)
		}
	}
}

// TestLoop_DisabledNoOverhead 默认关闭时不得产生任何告警。
func TestLoop_DisabledNoOverhead(t *testing.T) {
	d := NewLoopDetector(false)
	base := time.Now()
	pkt := mkIPFrame(1, 64, 6, 1000, 80, []byte("x"))
	for i := 0; i < 100; i++ {
		pkt[22] = byte(64 - i) // 制造完美的逐跳递减
		if a := d.ObserveIPv4(pkt, base.Add(time.Duration(i)*time.Millisecond)); len(a) > 0 {
			t.Fatalf("关闭状态下仍报 %q", a[0].Title)
		}
	}
}

// ===== 必须命中(正向用例) =====

// TestLoop_DetectsThreeLayerLoop 真环路: 同一报文被反复转发, TTL 逐跳减 1。
func TestLoop_DetectsThreeLayerLoop(t *testing.T) {
	d := NewLoopDetector(true)
	base := time.Now()
	// 同一报文(id/端口/载荷全同), TTL 64->63->62->61(每跳减 1)
	got := false
	for i, ttl := range []byte{64, 63, 62, 61} {
		pkt := mkIPFrame(100, ttl, 6, 8080, 80, []byte("loop-payload"))
		for _, a := range d.ObserveIPv4(pkt, base.Add(time.Duration(i)*20*time.Millisecond)) {
			if a.Title == "疑似三层环路" {
				got = true
				t.Logf("命中: %s", a.Detail)
			}
		}
	}
	if !got {
		t.Fatal("TTL 逐跳递减(64->63->62->61) 必须被识别为三层环路")
	}
}

// TestLoop_DetectsTwoLayerLoop 真二层环路: 完全相同的帧在窗口内密集重复。
func TestLoop_DetectsTwoLayerLoop(t *testing.T) {
	d := NewLoopDetector(true)
	base := time.Now()
	pkt := mkIPFrame(200, 64, 6, 9090, 80, []byte("dup-frame"))
	got := false
	for i := 0; i < loopFrameRepeat+5; i++ {
		for _, a := range d.ObserveIPv4(pkt, base.Add(time.Duration(i)*5*time.Millisecond)) {
			if a.Title == "疑似二层环路(重复帧)" {
				got = true
				t.Logf("命中: %s", a.Detail)
			}
		}
	}
	if !got {
		t.Fatalf("同帧密集重复 %d 次必须被识别为二层环路", loopFrameRepeat+5)
	}
}

// TestLoop_AlarmOncePerBucket 同一次环路只告警一次(不刷屏)。
func TestLoop_AlarmOncePerBucket(t *testing.T) {
	d := NewLoopDetector(true)
	base := time.Now()
	n := 0
	// 连续 20 次递减(远超阈值), 但只应产生 1 条告警
	for i := 0; i < 20; i++ {
		pkt := mkIPFrame(300, byte(80-i), 6, 777, 80, []byte("once"))
		for _, a := range d.ObserveIPv4(pkt, base.Add(time.Duration(i)*10*time.Millisecond)) {
			if a.Title == "疑似三层环路" {
				n++
			}
		}
	}
	if n != 1 {
		t.Errorf("同一次环路应只告警 1 次, 实得 %d 次", n)
	}
}

// ===== maxTTLDescend 单元 =====

func TestMaxTTLDescend(t *testing.T) {
	cases := []struct {
		in   []byte
		want int
	}{
		{nil, 0},
		{[]byte{64}, 0},
		{[]byte{64, 63, 62, 61}, 3},
		{[]byte{64, 62}, 0},         // 差值 2
		{[]byte{64, 64, 63}, 1},     // 重复值不打断链条
		{[]byte{64, 63, 128, 127}, 1}, // 跳变后重置, 后段只有 1 步
		{[]byte{63, 64}, 0},         // 递增不算
		{[]byte{10, 9, 8, 7, 6}, 4},
	}
	for _, c := range cases {
		if got := maxTTLDescend(c.in); got != c.want {
			t.Errorf("maxTTLDescend(%v) = %d, 期望 %d", c.in, got, c.want)
		}
	}
}

// TestCaptureLoopDetectDefaultOff Capture 默认不得开启环路检测(项目规则 5)。
func TestCaptureLoopDetectDefaultOff(t *testing.T) {
	c := NewCapture()
	if c.LoopDetectEnabled() {
		t.Fatal("环路检测必须默认关闭(规则 5: 新增功能默认关闭)")
	}
	c.SetLoopDetect(true)
	if !c.LoopDetectEnabled() {
		t.Fatal("SetLoopDetect(true) 后应开启")
	}
	// Start 不得把用户的开关重置掉
	c.Start()
	defer c.Stop()
	if !c.LoopDetectEnabled() {
		t.Fatal("Start() 不应重置环路检测开关")
	}
}

// TestCaptureLoopDetectOffNoAlarms Capture 关闭环路检测时, 即便喂真环路帧也不告警。
func TestCaptureLoopDetectOffNoAlarms(t *testing.T) {
	c := NewCapture()
	c.Start()
	defer c.Stop()
	for i := 0; i < loopFrameRepeat+10; i++ {
		c.OnPacket(mkIPFrame(400, byte(80-i), 6, 1111, 80, []byte("loop")))
	}
	for _, e := range c.events {
		if e.Title == "疑似三层环路" || e.Title == "疑似二层环路(重复帧)" {
			t.Fatalf("关闭状态下不应产生环路告警, 实得 %q", e.Title)
		}
	}
}
