package scanner

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

// syn_test.go SYN 扫描的离线用例。
//
// 覆盖范围刻意限定为三块(沙箱无真实网络与管理员权限, 端到端靠真机联调):
//  1. 报文构造: IP/TCP 头字段值 + 标志位 + 校验和(手算向量, 不是"换个参数再算一遍");
//  2. 状态判定: 用构造的字节流喂 classifySynReply;
//  3. 降级路径: 平台/权限不支持时仍返回全连接结果(State=closed, 而非 SYN 的 filtered)。

var (
	synTestSrc = netip.MustParseAddr("10.0.0.1")
	synTestDst = netip.MustParseAddr("10.0.0.2")
)

// TestBuildSynPacketIPHeader IPv4 头字段与校验和(手算向量)。
//
// 向量: 45 00 | 总长 40 | ID 0 | 分片 0 | TTL 64 | 协议 6 | 校验和 | 10.0.0.1 -> 10.0.0.2
// 逐字累加 = 0x9931 -> 取反 = 0x66CE。
func TestBuildSynPacketIPHeader(t *testing.T) {
	pkt, err := buildSynPacket(synTestSrc, synTestDst, 40000, 80, 1, true)
	if err != nil {
		t.Fatalf("构造报文失败: %v", err)
	}
	if len(pkt) != 40 {
		t.Fatalf("自带 IP 头时报文应为 40 字节, 实际 %d", len(pkt))
	}
	if got := pkt[0]; got != 0x45 {
		t.Fatalf("version/IHL 应为 0x45, 实际 %#x", got)
	}
	if got := binary.BigEndian.Uint16(pkt[2:4]); got != 40 {
		t.Fatalf("总长度应为 40, 实际 %d", got)
	}
	if got := pkt[8]; got != synTTL {
		t.Fatalf("TTL 应为 %d, 实际 %d", synTTL, got)
	}
	if got := pkt[9]; got != 6 {
		t.Fatalf("协议应为 6(TCP), 实际 %d", got)
	}
	if !netip.AddrFrom4([4]byte(pkt[12:16])) .IsValid() {
		t.Fatal("源 IP 字段非法")
	}
	if got, _ := netip.AddrFromSlice(pkt[12:16]); got != synTestSrc {
		t.Fatalf("源 IP 应为 %v, 实际 %v", synTestSrc, got)
	}
	if got, _ := netip.AddrFromSlice(pkt[16:20]); got != synTestDst {
		t.Fatalf("目的 IP 应为 %v, 实际 %v", synTestDst, got)
	}
	if got := binary.BigEndian.Uint16(pkt[10:12]); got != 0x66CE {
		t.Fatalf("IP 校验和应为 0x66CE, 实际 %#x", got)
	}
	// 自校验: 校验和正确的头, 整体累加取反应为 0
	if got := checksum16(0, pkt[:20]); got != 0 {
		t.Fatalf("IP 头自校验应为 0, 实际 %#x", got)
	}
}

// TestBuildSynPacketTCPHeader TCP 头字段、标志位与校验和(手算向量)。
//
// 向量: 10.0.0.1:40000 -> 10.0.0.2:80, seq=1, ack=0, 窗口 1024, 仅 SYN。
// 伪首部 0x141D + TCP 段 0xF093 = 0x104B0 -> 回卷 0x04B1 -> 取反 = 0xFB4E。
func TestBuildSynPacketTCPHeader(t *testing.T) {
	pkt, err := buildSynPacket(synTestSrc, synTestDst, 40000, 80, 1, true)
	if err != nil {
		t.Fatalf("构造报文失败: %v", err)
	}
	tcp := pkt[20:]
	if got := binary.BigEndian.Uint16(tcp[0:2]); got != 40000 {
		t.Fatalf("源端口应为 40000, 实际 %d", got)
	}
	if got := binary.BigEndian.Uint16(tcp[2:4]); got != 80 {
		t.Fatalf("目的端口应为 80, 实际 %d", got)
	}
	if got := binary.BigEndian.Uint32(tcp[4:8]); got != 1 {
		t.Fatalf("seq 应为 1, 实际 %d", got)
	}
	if got := tcp[12]; got != 0x50 {
		t.Fatalf("data offset 应为 0x50(20 字节), 实际 %#x", got)
	}
	if got := tcp[13]; got != synFlagSYN {
		t.Fatalf("标志位应恰为 SYN, 实际 %#x", got)
	}
	if got := binary.BigEndian.Uint16(tcp[14:16]); got != synWindow {
		t.Fatalf("窗口应为 %d, 实际 %d", synWindow, got)
	}
	if got := binary.BigEndian.Uint16(tcp[16:18]); got != 0xFB4E {
		t.Fatalf("TCP 校验和应为 0xFB4E, 实际 %#x", got)
	}
}

// TestBuildSynPacketKernelHeader 由内核填 IP 头时只发 TCP 段, 校验和口径不变。
func TestBuildSynPacketKernelHeader(t *testing.T) {
	pkt, err := buildSynPacket(synTestSrc, synTestDst, 40000, 80, 1, false)
	if err != nil {
		t.Fatalf("构造报文失败: %v", err)
	}
	if len(pkt) != synTCPHeaderLen {
		t.Fatalf("内核填头模式应只返回 20 字节 TCP 段, 实际 %d", len(pkt))
	}
	if got := binary.BigEndian.Uint16(pkt[16:18]); got != 0xFB4E {
		t.Fatalf("TCP 校验和应与自带 IP 头时一致(0xFB4E), 实际 %#x", got)
	}
}

// TestTCPChecksumDetectsMutation 校验和必须能反映载荷变化
// (否则"改了端口/标志位但校验和不变"会让目标直接丢包, 表现为莫名其妙的全 filtered)。
func TestTCPChecksumDetectsMutation(t *testing.T) {
	base := buildTCPHeader(synTestSrc, synTestDst, 40000, 80, 1)
	// 目的端口 80 -> 81 重新构造: 载荷变化必须体现在校验和上
	// (否则"改了端口/标志位但校验和不变"会让目标直接丢包, 表现为莫名其妙的全 filtered)
	mutated := buildTCPHeader(synTestSrc, synTestDst, 40000, 81, 1)
	if binary.BigEndian.Uint16(base[16:18]) == binary.BigEndian.Uint16(mutated[16:18]) {
		t.Fatal("载荷变了但校验和未变")
	}
	// 未改动的段自校验必须为 0
	var pseudo [12]byte
	copy(pseudo[0:4], synTestSrc.AsSlice())
	copy(pseudo[4:8], synTestDst.AsSlice())
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(base)))
	if got := checksum16(checksumWords(pseudo[:]), base); got != 0 {
		t.Fatalf("TCP 段(含伪首部)自校验应为 0, 实际 %#x", got)
	}
}

// synReplyForTest 构造一个回包(IPv4 头 + TCP 头), 供判定函数使用。
func synReplyForTest(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, flags byte) []byte {
	pkt := make([]byte, 40)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], 40)
	pkt[8] = 64
	pkt[9] = 6
	copy(pkt[12:16], srcIP.AsSlice())
	copy(pkt[16:20], dstIP.AsSlice())
	tcp := pkt[20:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	tcp[12] = 0x50
	tcp[13] = flags
	return pkt
}

func TestClassifySynReply(t *testing.T) {
	cases := []struct {
		name      string
		pkt       func() []byte
		wantState string
		wantMatch bool
	}{
		{"SYN+ACK 判开放", func() []byte {
			return synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagSYN|synFlagACK)
		}, synStateOpen, true},
		{"RST 判关闭", func() []byte {
			return synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagRST)
		}, synStateClosed, true},
		{"RST+ACK 判关闭", func() []byte {
			return synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagRST|synFlagACK)
		}, synStateClosed, true},
		{"仅 SYN(自己发出的探测)不算回包", func() []byte {
			return synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagSYN)
		}, "", false},
		{"无标志位不判定", func() []byte {
			return synReplyForTest(synTestDst, synTestSrc, 80, 40000, 0)
		}, "", false},
		{"源 IP 不符不判定", func() []byte {
			return synReplyForTest(netip.MustParseAddr("10.9.9.9"), synTestSrc, 80, 40000, synFlagSYN|synFlagACK)
		}, "", false},
		{"非 IPv4 不判定", func() []byte {
			p := synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagSYN|synFlagACK)
			p[0] = 0x65
			return p
		}, "", false},
		{"非 TCP 协议不判定", func() []byte {
			p := synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagSYN|synFlagACK)
			p[9] = 1
			return p
		}, "", false},
		{"分片后续片不判定(无 TCP 头)", func() []byte {
			p := synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagSYN|synFlagACK)
			binary.BigEndian.PutUint16(p[6:8], 0x0025) // 片偏移非 0
			return p
		}, "", false},
		{"短包不判定", func() []byte {
			return synReplyForTest(synTestDst, synTestSrc, 80, 40000, synFlagSYN|synFlagACK)[:30]
		}, "", false},
	}
	for _, c := range cases {
		_, state, matched := classifySynReply(synTestDst, c.pkt())
		if matched != c.wantMatch {
			t.Fatalf("%s: matched=%v, want %v", c.name, matched, c.wantMatch)
		}
		if matched && state != c.wantState {
			t.Fatalf("%s: state=%q, want %q", c.name, state, c.wantState)
		}
	}
}

// TestClassifySynReplyReturnsProbePort 回包必须能反查到"是哪个端口的探测"
// (靠目的端口 = 探测时用的本地源端口)。
func TestClassifySynReplyReturnsProbePort(t *testing.T) {
	pkt := synReplyForTest(synTestDst, synTestSrc, 443, synSrcPort(7), synFlagSYN|synFlagACK)
	port, state, matched := classifySynReply(synTestDst, pkt)
	if !matched || state != synStateOpen {
		t.Fatalf("应判为 open, 实际 matched=%v state=%q", matched, state)
	}
	if port != synSrcPort(7) {
		t.Fatalf("应回带探测用的本地源端口 %d, 实际 %d", synSrcPort(7), port)
	}
}

// TestSynSrcPortUnique 同批探测的本地源端口必须互不相同(否则回包会张冠李戴)。
func TestSynSrcPortUnique(t *testing.T) {
	seen := map[uint16]bool{}
	for i := 0; i < synSrcPortSpan; i++ {
		p := synSrcPort(i)
		if p < 1024 {
			t.Fatalf("源端口 %d 落在特权端口区间", p)
		}
		if seen[p] {
			t.Fatalf("第 %d 个探测的源端口 %d 重复", i, p)
		}
		seen[p] = true
	}
}

// TestScanPortsRawDegradesWhenSynUnsupported 平台/权限不支持时必须回落到全连接扫描:
// 结果仍是"closed"(全连接失败口径), 不能是 SYN 特有的 "filtered"。
func TestScanPortsRawDegradesWhenSynUnsupported(t *testing.T) {
	if SynScanSupported() {
		t.Skip("本机具备 SYN 扫描条件(Windows 管理员), 降级路径不适用")
	}
	task := NewTask("port", "192.0.2.1", Config{
		EnableSynScan: true,
		Ports:         []int{80},
		Timeout:       Timeouts{Dial: 150 * time.Millisecond},
	})
	res := task.scanPortsRaw(context.Background(), "192.0.2.1", []int{80}, false)
	if len(res) != 1 {
		t.Fatalf("应返回 1 条结果(降级后仍要出结果), 实际 %d", len(res))
	}
	if res[0].State != synStateClosed {
		t.Fatalf("降级后应走全连接(closed), 实际 %q", res[0].State)
	}
	if res[0].IP != "192.0.2.1" || res[0].Port != 80 {
		t.Fatalf("结果字段口径不符: %+v", res[0])
	}
}

// TestOptionsSynScanDefault SYN 扫描必须默认关闭(项目规则 5: 显式下发才启用)。
func TestOptionsSynScanDefault(t *testing.T) {
	if OptionsFromArgs(nil, Config{}).EnableSynScan {
		t.Fatal("无参数时 SYN 扫描应关闭")
	}
	if !OptionsFromArgs(map[string]any{"synscan": true}, Config{}).EnableSynScan {
		t.Fatal("显式 synscan=true 应启用")
	}
	if OptionsFromArgs(map[string]any{"synscan": false}, Config{}).EnableSynScan {
		t.Fatal("显式 synscan=false 应关闭")
	}
	// 类型不符一律忽略(中心端参数错误不应改变扫描方式)
	if OptionsFromArgs(map[string]any{"synscan": "true"}, Config{}).EnableSynScan {
		t.Fatal("字符串 \"true\" 不应被当作启用")
	}
}
