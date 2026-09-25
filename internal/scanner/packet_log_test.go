package scanner

import (
	"encoding/binary"
	"fmt"
	"strings"
	"testing"
	"time"
)

// ===== 报文解码测试 =====
//
// 报文列是抓包页面最核心的价值(用户要看"谁在跟谁通信"), 解码错了比不解码更糟:
// 会让人得出错误结论。这里的用例全部用**字节级构造的真实帧结构**。

// mkEth 拼一个以太网帧
func mkEth(dst, src []byte, ether uint16, payload []byte) []byte {
	p := make([]byte, 14+len(payload))
	copy(p[0:6], dst)
	copy(p[6:12], src)
	binary.BigEndian.PutUint16(p[12:14], ether)
	copy(p[14:], payload)
	return p
}

// mkIPv4 拼一个 IPv4 头 + 载荷
func mkIPv4(proto, ttl byte, src, dst [4]byte, payload []byte) []byte {
	h := make([]byte, 20)
	h[0] = 0x45
	binary.BigEndian.PutUint16(h[2:4], uint16(20+len(payload)))
	h[8] = ttl
	h[9] = proto
	copy(h[12:16], src[:])
	copy(h[16:20], dst[:])
	return append(h, payload...)
}

func TestDecodeTCP(t *testing.T) {
	// TCP 头 20 字节: 源端口 51234, 目的 443, 标志 PSH+ACK
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 51234)
	binary.BigEndian.PutUint16(tcp[2:4], 443)
	tcp[12] = 0x50 // data offset 5
	tcp[13] = 0x18 // PSH + ACK
	frame := mkEth(
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		ethTypeIPv4,
		mkIPv4(6, 64, [4]byte{192, 168, 1, 10}, [4]byte{10, 0, 0, 5}, tcp),
	)

	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("合法 TCP 帧应解码成功")
	}
	if rec.Protocol != "TCP" {
		t.Errorf("协议应为 TCP, 实得 %q", rec.Protocol)
	}
	if rec.SrcIP != "192.168.1.10" || rec.DstIP != "10.0.0.5" {
		t.Errorf("IP 解析错误: %s -> %s", rec.SrcIP, rec.DstIP)
	}
	if rec.SrcPort != 51234 || rec.DstPort != 443 {
		t.Errorf("端口解析错误: %d -> %d", rec.SrcPort, rec.DstPort)
	}
	if rec.TTL != 64 {
		t.Errorf("TTL 应为 64, 实得 %d", rec.TTL)
	}
	// 443 应被识别为 HTTPS/TLS
	if !strings.Contains(rec.Info, "HTTPS") {
		t.Errorf("443 端口应识别为 HTTPS, Info=%q", rec.Info)
	}
	if !strings.Contains(rec.Info, "PSH") || !strings.Contains(rec.Info, "ACK") {
		t.Errorf("TCP 标志应包含 PSH/ACK, Info=%q", rec.Info)
	}
	if rec.SrcMAC == "" || rec.DstMAC == "" {
		t.Error("MAC 不应为空")
	}
}

func TestDecodeUDPDNS(t *testing.T) {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	frame := mkEth(
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		ethTypeIPv4,
		mkIPv4(17, 128, [4]byte{192, 168, 1, 10}, [4]byte{8, 8, 8, 8}, udp),
	)
	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("合法 UDP 帧应解码成功")
	}
	if rec.Protocol != "UDP" {
		t.Errorf("协议应为 UDP, 实得 %q", rec.Protocol)
	}
	if rec.DstPort != 53 {
		t.Errorf("目的端口应为 53, 实得 %d", rec.DstPort)
	}
	if rec.Info != "DNS" {
		t.Errorf("53 端口应识别为 DNS, Info=%q", rec.Info)
	}
}

func TestDecodeICMPPing(t *testing.T) {
	icmp := []byte{8, 0, 0, 0, 0, 1, 0, 1} // type 8 = echo request
	frame := mkEth(
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		ethTypeIPv4,
		mkIPv4(1, 64, [4]byte{192, 168, 1, 10}, [4]byte{192, 168, 1, 1}, icmp),
	)
	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("合法 ICMP 帧应解码成功")
	}
	if rec.Protocol != "ICMP" {
		t.Errorf("协议应为 ICMP, 实得 %q", rec.Protocol)
	}
	if !strings.Contains(rec.Info, "Echo") {
		t.Errorf("ICMP type 8 应识别为 Echo request, Info=%q", rec.Info)
	}
}

// TestDecodeLoopbackICMP Npcap 回环适配器(NPF_Loopback)帧解码。
//
// 回环帧没有以太网头: [02 00 00 00](小端 AF_INET)+ 裸 IPv4 包。
// 用户"抓包选了 ICMP 却抓不到自己的 ping"的根因就是这类帧(本机回环流量
// 只出现在回环适配器上)此前被解成"其它"。
func TestDecodeLoopbackICMP(t *testing.T) {
	icmp := []byte{8, 0, 0, 0, 0, 1, 0, 1} // type 8 = echo request
	frame := append([]byte{2, 0, 0, 0},
		mkIPv4(1, 128, [4]byte{127, 0, 0, 1}, [4]byte{127, 0, 0, 1}, icmp)...)
	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("回环 ICMP 帧应解码成功")
	}
	if rec.Protocol != "ICMP" {
		t.Errorf("协议应为 ICMP, 实得 %q", rec.Protocol)
	}
	if rec.SrcIP != "127.0.0.1" || rec.DstIP != "127.0.0.1" {
		t.Errorf("回环 IP 解析错误: %s -> %s", rec.SrcIP, rec.DstIP)
	}
	if !strings.Contains(rec.Info, "Echo") {
		t.Errorf("ICMP type 8 应识别为 Echo request, Info=%q", rec.Info)
	}
	if rec.SrcMAC != "" || rec.DstMAC != "" {
		t.Errorf("回环帧无 MAC, 不应有 MAC 值: %s / %s", rec.SrcMAC, rec.DstMAC)
	}
}

// TestDecodeLoopbackIPv6 回环帧的 IPv6 变体: [17 00 00 00](AF_INET6)+ 裸 IPv6 包。
func TestDecodeLoopbackIPv6(t *testing.T) {
	v6 := make([]byte, 40)
	v6[0] = 0x60
	v6[6] = 58 // next header = ICMPv6
	v6[7] = 64
	copy(v6[8:24], []byte{0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(v6[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	// ICMPv6 echo: 8 字节头 + 32 字节载荷(与真实 ping 一致, 保证帧长够解出 IP)
	icmp6 := make([]byte, 40)
	icmp6[0], icmp6[1] = 128, 0 // type 128 = echo request
	copy(icmp6[4:6], []byte{1, 2})
	frame := append([]byte{23, 0, 0, 0}, v6...)
	frame = append(frame, icmp6...)
	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("回环 IPv6 帧应解码成功")
	}
	if rec.Protocol != "ICMPv6" {
		t.Errorf("协议应为 ICMPv6, 实得 %q", rec.Protocol)
	}
	if rec.SrcIP == "" || rec.DstIP == "" {
		t.Errorf("IPv6 源/目的不应为空: %q / %q", rec.SrcIP, rec.DstIP)
	}
	if !strings.Contains(rec.Info, "Echo") {
		t.Errorf("ICMPv6 type 128 应识别为 Echo request, Info=%q", rec.Info)
	}
}

// TestDecodeEthernetNotMistakenForLoopback 普通以太网帧不得被误判成回环帧:
// 目标 MAC 以 02:00:00:00 开头(随机 MAC 常见前缀)时, 只要 ethertype 是合法的
// 就仍按以太网解析。
func TestDecodeEthernetNotMistakenForLoopback(t *testing.T) {
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp[0:2], 54321)
	binary.BigEndian.PutUint16(udp[2:4], 53)
	frame := mkEth(
		[]byte{0x02, 0x00, 0x00, 0x00, 0x4a, 0x01}, // dst MAC 撞回环前缀
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		ethTypeIPv4,
		mkIPv4(17, 128, [4]byte{192, 168, 1, 10}, [4]byte{8, 8, 8, 8}, udp),
	)
	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("合法以太网帧应解码成功")
	}
	if rec.Protocol != "UDP" {
		t.Errorf("应按以太网解析为 UDP, 实得 %q", rec.Protocol)
	}
	if rec.SrcMAC != "66:77:88:99:aa:bb" {
		t.Errorf("MAC 解析错误: %q", rec.SrcMAC)
	}
}

func TestDecodeARP(t *testing.T) {
	// ARP: htype=1, ptype=0x0800, hlen=6, plen=4, op=1(request)
	arp := make([]byte, 28)
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4] = 6
	arp[5] = 4
	binary.BigEndian.PutUint16(arp[6:8], 1)
	copy(arp[8:14], []byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb})
	copy(arp[14:18], []byte{192, 168, 1, 10})
	copy(arp[24:28], []byte{192, 168, 1, 1})

	frame := mkEth(
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		ethTypeARP,
		arp,
	)
	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("合法 ARP 帧应解码成功")
	}
	if rec.Protocol != "ARP" {
		t.Errorf("协议应为 ARP, 实得 %q", rec.Protocol)
	}
	if rec.SrcIP != "192.168.1.10" || rec.DstIP != "192.168.1.1" {
		t.Errorf("ARP 地址解析错误: %s -> %s", rec.SrcIP, rec.DstIP)
	}
	if !strings.Contains(rec.Info, "Who has") {
		t.Errorf("ARP 请求应显示 Who has, Info=%q", rec.Info)
	}
}

func TestDecodeIPv6TCP(t *testing.T) {
	// IPv6 头 40 字节 + TCP 头 20 字节
	v6 := make([]byte, 40)
	v6[0] = 0x60
	v6[6] = 6 // next header = TCP
	v6[7] = 64
	copy(v6[8:24], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})
	copy(v6[24:40], []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2})
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[0:2], 12345)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	tcp[12] = 0x50
	tcp[13] = 0x02 // SYN

	frame := mkEth(
		[]byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55},
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		0x86dd,
		append(v6, tcp...),
	)
	rec, ok := DecodePacket(frame, time.Now())
	if !ok {
		t.Fatal("合法 IPv6 帧应解码成功")
	}
	if !strings.Contains(rec.Protocol, "TCP") {
		t.Errorf("IPv6+TCP 应识别为 TCPv6, 实得 %q", rec.Protocol)
	}
	if rec.SrcPort != 12345 || rec.DstPort != 80 {
		t.Errorf("IPv6 端口解析错误: %d -> %d", rec.SrcPort, rec.DstPort)
	}
}

func TestDecodeL2Protocols(t *testing.T) {
	// 非 IP 的二层协议也要能显示名字(排障时同样重要)
	cases := []struct {
		ether uint16
		want  string
	}{
		{0x88cc, "LLDP"},
		{0x8100, "VLAN(802.1Q)"},
		{0x888e, "EAPOL(802.1X)"},
		{0x8809, "LACP"},
		{0x9999, "其它"},
	}
	for _, c := range cases {
		frame := mkEth(
			[]byte{0x01, 0x80, 0xc2, 0x00, 0x00, 0x0e},
			[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			c.ether,
			[]byte{1, 2, 3, 4, 5, 6},
		)
		rec, ok := DecodePacket(frame, time.Now())
		if !ok {
			t.Fatalf("ether=0x%04x 应解码成功", c.ether)
		}
		if rec.Protocol != c.want {
			t.Errorf("ether=0x%04x 协议应为 %q, 实得 %q", c.ether, c.want, rec.Protocol)
		}
	}
}

// TestDecodeMalformedNoPanic 畸形帧不得 panic(网络数据完全不受控)。
func TestDecodeMalformedNoPanic(t *testing.T) {
	cases := [][]byte{
		nil,
		{},
		{1, 2, 3},
		make([]byte, 13),
		make([]byte, 14),
		// ihl 声明 15(60 字节)但帧只有 14+20
		func() []byte {
			p := make([]byte, 34)
			p[12], p[13] = 0x08, 0x00
			p[14] = 0x4f
			return p
		}(),
		// ARP 声明 hlen=200
		func() []byte {
			p := make([]byte, 14+28)
			p[12], p[13] = 0x08, 0x06
			p[18] = 200
			p[19] = 4
			return p
		}(),
	}
	for i, data := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("用例 %d 触发 panic: %v", i, r)
				}
			}()
			_, _ = DecodePacket(data, time.Now())
		}()
	}
}

// ===== PacketLog 环形缓冲 =====

// TestPacketLogRingBuffer 缓冲满后必须覆盖最老的, 且保持时间顺序。
func TestPacketLogRingBuffer(t *testing.T) {
	p := NewPacketLog()
	base := time.Now()
	total := pktLogCap + 300
	for i := 0; i < total; i++ {
		// 用 TCP 帧, 端口随 i 变化以便区分
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[0:2], uint16(1000+i%60000))
		binary.BigEndian.PutUint16(tcp[2:4], 80)
		frame := mkEth(
			[]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55},
			[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			ethTypeIPv4,
			mkIPv4(6, 64, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, tcp),
		)
		p.Append(frame, base.Add(time.Duration(i)*time.Millisecond))
	}
	if p.Count() != int64(total) {
		t.Errorf("总数应为 %d, 实得 %d", total, p.Count())
	}
	if p.Len() != pktLogCap {
		t.Errorf("缓冲应满(%d), 实得 %d", pktLogCap, p.Len())
	}
	// 顺序性: Tail 返回的 seq 必须递增
	tail := p.Tail(10)
	if len(tail) != 10 {
		t.Fatalf("Tail(10) 应返回 10 条, 实得 %d", len(tail))
	}
	for i := 1; i < len(tail); i++ {
		if tail[i].Seq <= tail[i-1].Seq {
			t.Fatalf("Tail 结果 seq 必须递增, 但 %d <= %d", tail[i].Seq, tail[i-1].Seq)
		}
	}
	// 最新的那条应是最后写入的
	if tail[len(tail)-1].Seq != int64(total) {
		t.Errorf("最新 seq 应为 %d, 实得 %d", total, tail[len(tail)-1].Seq)
	}
}

// TestPacketLogSince 增量拉取: 只返回比 since 新的记录。
func TestPacketLogSince(t *testing.T) {
	p := NewPacketLog()
	base := time.Now()
	for i := 0; i < 50; i++ {
		tcp := make([]byte, 20)
		binary.BigEndian.PutUint16(tcp[2:4], 80)
		p.Append(mkEth(
			[]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55},
			[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			ethTypeIPv4,
			mkIPv4(6, 64, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, tcp),
		), base)
	}
	got := p.Since(40, 0)
	if len(got) != 10 {
		t.Fatalf("since=40 应返回 10 条, 实得 %d", len(got))
	}
	if got[0].Seq != 41 {
		t.Errorf("首条 seq 应为 41, 实得 %d", got[0].Seq)
	}
	// limit 应保留最新的若干条
	limited := p.Since(0, 5)
	if len(limited) != 5 {
		t.Fatalf("limit=5 应返回 5 条, 实得 %d", len(limited))
	}
	if limited[4].Seq != 50 {
		t.Errorf("limit 应保留最新(seq=50), 实得 %d", limited[4].Seq)
	}
}

// TestPacketLogUndecodableCounted 无法解码的帧要计数(供页面解释"为什么少几条")
func TestPacketLogUndecodableCounted(t *testing.T) {
	p := NewPacketLog()
	p.Append([]byte{1, 2, 3}, time.Now()) // 不足 14 字节
	if p.Filtered() != 1 {
		t.Errorf("应记 1 条无法解码, 实得 %d", p.Filtered())
	}
	if p.Len() != 0 {
		t.Errorf("无法解码的帧不应进列表, 实得 %d", p.Len())
	}
	// ARP 帧即使不足 28 字节也应进列表(结构可识别), 只是 Info 提示截断
	short := make([]byte, 16)
	short[12], short[13] = 0x08, 0x06
	p.Append(short, time.Now())
	if p.Len() != 1 {
		t.Errorf("截断的 ARP 应仍进列表, 实得 %d", p.Len())
	}
}

// TestPacketLogReset 会话重置必须清空(否则上一次的数据会串到新会话)
func TestPacketLogReset(t *testing.T) {
	p := NewPacketLog()
	p.Append(mkEth(
		[]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55},
		[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
		ethTypeARP, make([]byte, 28),
	), time.Now())
	if p.Len() == 0 {
		t.Fatal("追加后应有记录")
	}
	p.Reset()
	if p.Len() != 0 || p.Count() != 0 || p.Filtered() != 0 {
		t.Error("Reset 后应全部清零")
	}
}

// TestCaptureOnPacketFeedsLog Capture 收到的帧必须同时进统计与报文列表。
func TestCaptureOnPacketFeedsLog(t *testing.T) {
	c := NewCapture()
	c.Start()
	defer c.Stop()
	tcp := make([]byte, 20)
	binary.BigEndian.PutUint16(tcp[2:4], 80)
	for i := 0; i < 5; i++ {
		c.OnPacket(mkEth(
			[]byte{0, 0x11, 0x22, 0x33, 0x44, 0x55},
			[]byte{0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb},
			ethTypeIPv4,
			mkIPv4(6, 64, [4]byte{10, 0, 0, 1}, [4]byte{10, 0, 0, 2}, tcp),
		))
	}
	if c.Packets().Count() != 5 {
		t.Errorf("报文列表应收到 5 条, 实得 %d", c.Packets().Count())
	}
	stats := c.Stats()
	if stats["pktTotal"].(int64) != 5 {
		t.Errorf("Stats 的 pktTotal 应为 5, 实得 %v", stats["pktTotal"])
	}
}

// TestCaptureStatsHasPacketFields 统计字段必须齐全(前端依赖这些键名)。
func TestCaptureStatsHasPacketFields(t *testing.T) {
	c := NewCapture()
	c.Start()
	defer c.Stop()
	s := c.Stats()
	for _, k := range []string{"pktBuffered", "pktCapacity", "pktTotal", "pktUndecodable", "loopDetect"} {
		if _, ok := s[k]; !ok {
			t.Errorf("Stats 缺少字段 %q", k)
		}
	}
}

var _ = fmt.Sprintf
