package scanner

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

// ===== SYN 半开扫描(仅 Windows + 管理员权限, 默认关闭) =====
//
// 背景: 探针能力上报里一直有 synscan(见 probe_api.go 的能力推导), 但探针端从未实现 ——
// 中心端下发带 syn 语义的任务时没有任何对应路径。这里补上实现。
//
// 与全连接扫描的区别:
//
//	全连接  完成三次握手, 目标会记一条完整连接记录, 且要等握手超时才判关闭(慢);
//	SYN     只发 SYN 并按回包判定(open/closed/filtered), 不建立连接(半开), 快且不留下完整连接。
//
// 平台约束(关键, 决定了本实现的形状):
//
//	Windows 自 XP SP2 起限制原始套接字 —— 发送 TCP 报文、伪造源地址都可能被拒
//	(WSAEACCES=10013), 且内核 TCP 栈会抢先应答, raw socket 可能一个回包都收不到。
//	因此三条降级线必须都存在:
//	  1. 非 Windows            -> 不支持(空桩 syn_other.go, 项目规则 2 全平台编译);
//	  2. Windows 非管理员      -> 不支持;
//	  3. 管理员但发送被拒 / 一个回包都收不到 -> 运行时降级为既有全连接扫描(记日志, 不报错)。
//	宁可慢, 不能"扫了但全空" —— 后者会被中心端读成"目标没有开放端口", 是危险结论。
//
// 启用方式: 中心端下发 Args{"synscan": true}(默认 false, 项目规则 5)。

// SYN 扫描端口状态(与既有 PortResult.State 同口径: open/closed; filtered 为 SYN 特有)。
const (
	synStateOpen     = "open"
	synStateClosed   = "closed"
	synStateFiltered = "filtered"
)

const (
	synIPHeaderLen  = 20 // 无选项的 IPv4 头
	synTCPHeaderLen = 20 // 无选项的 TCP 头
	synTTL          = 64
	synWindow       = 1024

	// synSrcPortBase/Span: 每个探测用一个独立本地源端口, 回包靠"目的端口"反查是哪个端口的探测。
	// 必须独立于并发之外(同一批端口不能撞号), 否则"A 端口的 SYN-ACK 被算到 B 端口头上"。
	synSrcPortBase = 40000
	synSrcPortSpan = 20000
)

// TCP 标志位(只用到判定相关的三个)。
const (
	synFlagFIN = 0x01
	synFlagSYN = 0x02
	synFlagRST = 0x04
	synFlagACK = 0x10
)

var (
	// errSynUnsupported 平台/权限不支持(调用方据此静默降级, 不视为扫描失败)。
	errSynUnsupported = errors.New("SYN 扫描不受支持(需 Windows 且以管理员权限运行)")
	// errSynNoReply 一个回包都没收到: Windows 上内核 TCP 栈抢答是常态, 此时 SYN 判定不可信。
	errSynNoReply = errors.New("SYN 扫描未收到任何回包(可能被系统策略或内核 TCP 栈拦截)")
	// errSynTimeout 单次 recvfrom 超时(内部使用, 表示"本次等待窗口内没有更多回包")。
	errSynTimeout = errors.New("等待回包超时")
)

// SynScanSupported 本机是否具备 SYN 扫描条件(Windows + 管理员权限)。
//
// 非 Windows 恒为 false(见 syn_other.go 空桩), 中心端据此不会把该节点当"有 SYN 能力"来调度。
func SynScanSupported() bool { return synPlatformSupported() }

// synSrcPort 第 i 个探测使用的本地源端口(同批内不重复)。
func synSrcPort(i int) uint16 {
	if i < 0 {
		i = 0
	}
	return uint16(synSrcPortBase + i%synSrcPortSpan)
}

// ===== 报文构造(纯函数, 全平台可测) =====

// buildSynPacket 构造一个 SYN 报文。
//
// hdrIncl=true 时报文自带 IPv4 头(发送端需开启 IP_HDRINCL); false 时只返回 TCP 头,
// 由内核填 IP 头 —— Windows 上两种模式都可能生效也可能被拒, 由调用方按实际结果选择。
//
// seq 参与 TCP 校验和, 因此每个探测的 seq 必须不同(同 seq 会让不同端口的报文字节全等,
// 回包与探测无法一一对应)。
func buildSynPacket(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq uint32, hdrIncl bool) ([]byte, error) {
	if !srcIP.Is4() || !dstIP.Is4() {
		return nil, errors.New("SYN 扫描仅支持 IPv4")
	}
	tcp := buildTCPHeader(srcIP, dstIP, srcPort, dstPort, seq)
	if !hdrIncl {
		return tcp, nil
	}
	ip := buildIPv4Header(srcIP, dstIP, synIPHeaderLen+len(tcp))
	out := make([]byte, 0, len(ip)+len(tcp))
	out = append(out, ip...)
	out = append(out, tcp...)
	return out, nil
}

// buildIPv4Header 构造无选项 IPv4 头(20 字节, 校验和已填入)。
//
// IP-ID 与分片字段置 0: 单包 40 字节不会分片, 也无需重传标识。
func buildIPv4Header(srcIP, dstIP netip.Addr, totalLen int) []byte {
	b := make([]byte, synIPHeaderLen)
	b[0] = 0x45 // version=4, IHL=5(20 字节)
	b[1] = 0x00 // DSCP/ECN = 0
	binary.BigEndian.PutUint16(b[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(b[4:6], 0)  // identification
	binary.BigEndian.PutUint16(b[6:8], 0)  // flags + fragment offset
	b[8] = synTTL                          // TTL
	b[9] = 6                               // protocol = TCP
	binary.BigEndian.PutUint16(b[10:12], 0) // checksum 占位, 下面填
	copy(b[12:16], srcIP.AsSlice())
	copy(b[16:20], dstIP.AsSlice())
	binary.BigEndian.PutUint16(b[10:12], checksum16(0, b))
	return b
}

// buildTCPHeader 构造 SYN 段(20 字节, 无选项, 校验和已填入)。
func buildTCPHeader(srcIP, dstIP netip.Addr, srcPort, dstPort uint16, seq uint32) []byte {
	b := make([]byte, synTCPHeaderLen)
	binary.BigEndian.PutUint16(b[0:2], srcPort)
	binary.BigEndian.PutUint16(b[2:4], dstPort)
	binary.BigEndian.PutUint32(b[4:8], seq)
	binary.BigEndian.PutUint32(b[8:12], 0) // ack number(纯 SYN 不带 ACK)
	b[12] = 0x50                           // data offset = 5(20 字节)
	b[13] = synFlagSYN                     // 仅 SYN
	binary.BigEndian.PutUint16(b[14:16], synWindow)
	binary.BigEndian.PutUint16(b[16:18], 0) // checksum 占位
	binary.BigEndian.PutUint16(b[18:20], 0) // urgent pointer
	binary.BigEndian.PutUint16(b[16:18], tcpChecksum(srcIP, dstIP, b))
	return b
}

// tcpChecksum TCP 校验和(含 12 字节伪首部)。
//
// 伪首部必须参与: 只算 TCP 段自身会让"源/目的 IP 被改"的报文校验和仍然通过。
func tcpChecksum(srcIP, dstIP netip.Addr, tcp []byte) uint16 {
	var pseudo [12]byte
	copy(pseudo[0:4], srcIP.AsSlice())
	copy(pseudo[4:8], dstIP.AsSlice())
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcp)))
	return checksum16(checksumWords(pseudo[:]), tcp)
}

// checksum16 计算 16 位反码和校验和: 累加 → 回卷进位 → 取反。
func checksum16(seed uint32, b []byte) uint16 {
	sum := seed + checksumWords(b)
	for sum > 0xFFFF {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// checksumWords 按网络序(大端)逐 16 位累加; 奇数字节时末尾补零字节(标准做法)。
func checksumWords(b []byte) uint32 {
	var sum uint32
	for len(b) >= 2 {
		sum += uint32(b[0])<<8 | uint32(b[1])
		b = b[2:]
	}
	if len(b) == 1 {
		sum += uint32(b[0]) << 8
	}
	return sum
}

// ===== 回包判定(纯函数, 用构造的字节流即可测) =====

// classifySynReply 解析一个回包, 判定它属于哪次探测、端口是什么状态。
//
// wantSrc 是目标 IP(回包源必须是它, 否则是别的会话的报文);
// 返回的 localPort 是回包的目的端口, 也就是我们发 SYN 时用的本地源端口 —— 靠它反查端口。
//
// matched=false 表示与本次探测无关(短包 / 非 IPv4 / 非 TCP / 分片 / 源不符 / 标志位都不是),
// 调用方应忽略。判定口径与 nmap 一致: SYN+ACK=open, RST=closed, 无响应=filtered(由调用方兜底)。
func classifySynReply(wantSrc netip.Addr, pkt []byte) (localPort uint16, state string, matched bool) {
	if !wantSrc.Is4() || len(pkt) < synIPHeaderLen+synTCPHeaderLen {
		return 0, "", false
	}
	if pkt[0]>>4 != 4 { // 仅 IPv4
		return 0, "", false
	}
	if pkt[9] != 6 { // 协议非 TCP
		return 0, "", false
	}
	// 非首片分片没有 TCP 头, 不能判定(继续收后续片, 不猜)
	if binary.BigEndian.Uint16(pkt[6:8])&0x1FFF != 0 {
		return 0, "", false
	}
	src, ok := netip.AddrFromSlice(pkt[12:16])
	if !ok || src != wantSrc {
		return 0, "", false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < synIPHeaderLen || len(pkt) < ihl+synTCPHeaderLen {
		return 0, "", false
	}
	tcp := pkt[ihl:]
	localPort = binary.BigEndian.Uint16(tcp[2:4])
	flags := tcp[13]
	switch {
	case flags&synFlagSYN != 0 && flags&synFlagACK != 0:
		return localPort, synStateOpen, true
	case flags&synFlagRST != 0:
		return localPort, synStateClosed, true
	}
	return 0, "", false
}
