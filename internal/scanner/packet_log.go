package scanner

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ===== 报文留存与解码 =====
//
// 【为什么需要】原实现只把帧喂给 OnPacket 做计数/ARP 绑定/告警, **不留存报文本身**,
// 页面上只有统计数字, 看不到"具体是哪些包" —— 而这恰恰是抓包工具最核心的价值:
// 用户要看的是"谁在跟谁通信、发了什么"。
//
// 本文件负责把每个帧解码成结构化记录压入环形缓冲, 供页面分页拉取。
//
// 【为什么是环形缓冲而不是全存】抓包速率可达数十万 pps, 一分钟就是几百兆字节。
// 全存必然撑爆内存(且本项目单机部署, 没有外部存储可落)。环形缓冲保留最近 N 条
// (默认 2000), 既够排障时"回看刚才发生了什么", 又有确定的内存上界。
// 需要长期留存请用页面上的"导出 PCAP"功能。
const (
	// pktLogCap 报文环形缓冲容量。2000 条约等于几秒到几分钟的现场(视流量而定),
	// 每条记录含摘要字符串, 总占用在几百 KB 量级。
	pktLogCap = 2000
	// pktPayloadKeep 每条记录保留的原始字节上限(供"详情/十六进制"查看)。
	// 完整帧通常 < 1500 字节, 这里限 256 是为了让 2000 条记录经 JSON 传前端的
	// 体积可控(每条 base64 约 +33%); 需要完整帧时用 PCAP 导出。
	pktPayloadKeep = 256
	// pktRawCap 每条记录留存的完整帧字节上限(仅供 PCAP 导出, 不经 JSON 传输)。
	// 以太网帧最大 1514(巨型帧 9018), 65535 只是防御性上限; 按 2000 条满配
	// 计最坏约 128MB, 实际流量(≤1514/帧)约 3MB, 内存上界可接受。
	pktRawCap = 65535
)

// PacketRecord 一条解码后的报文记录(前端"报文列表"的一行)
type PacketRecord struct {
	Seq     int64  `json:"seq"`
	Time    string `json:"time"`
	TimeMS  int64  `json:"timeMs"`
	Length  int    `json:"length"`
	SrcMAC  string `json:"srcMac,omitempty"`
	DstMAC  string `json:"dstMac,omitempty"`
	EtherTy string `json:"etherType"`
	// Protocol 人读的协议名: ARP / TCP / UDP / ICMP / IPv6 / 其它
	Protocol string `json:"protocol"`
	SrcIP    string `json:"srcIp,omitempty"`
	DstIP    string `json:"dstIp,omitempty"`
	SrcPort  int    `json:"srcPort,omitempty"`
	DstPort  int    `json:"dstPort,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	// Info 一行摘要(TCP 标志/ICMP 类型/ARP 操作), 与 Wireshark 的 Info 列对齐
	Info string `json:"info,omitempty"`
	// Payload 原始帧前若干字节, 供十六进制详情(限 pktPayloadKeep)
	Payload []byte `json:"payload,omitempty"`
	// Raw 完整原始帧(限 pktRawCap), 仅供 PCAP 导出; json:"-" 不随报文列表
	// 传输, 否则 2000 条 × 1500 字节的 base64 会把每次轮询的 JSON 撑到数 MB。
	Raw []byte `json:"-"`
}

// PacketLog 报文环形缓冲(并发安全)
type PacketLog struct {
	mu    sync.Mutex
	buf   []PacketRecord
	next  int // 下一个写入位置
	total int64
	seq   int64
	// filtered 因解码失败(畸形帧)被跳过的报文数: 与 badFrames 口径一致,
	// 页面可见, 否则"列表比统计少几条"没法解释
	filtered int64
}

// NewPacketLog 创建报文缓冲
func NewPacketLog() *PacketLog {
	return &PacketLog{buf: make([]PacketRecord, 0, pktLogCap)}
}

// Reset 会话开始时清空
func (p *PacketLog) Reset() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.buf = p.buf[:0]
	p.next = 0
	p.total = 0
	p.seq = 0
	p.filtered = 0
	p.mu.Unlock()
}

// Count 已记录报文总数(含被环形缓冲覆盖掉的)
func (p *PacketLog) Count() int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.total
}

// Len 当前缓冲内条数
func (p *PacketLog) Len() int {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.buf)
}

// Append 解码并压入一个帧。
//
// 解码失败不 panic(畸形帧来自网络, 内容完全不受控), 只计数。
func (p *PacketLog) Append(data []byte, now time.Time) {
	if p == nil {
		return
	}
	rec, ok := DecodePacket(data, now)
	if !ok {
		p.mu.Lock()
		p.filtered++
		p.mu.Unlock()
		return
	}
	// 留存完整帧供 PCAP 导出: 必须拷贝 —— data 是 readCaptureStream 里的栈上
	// 切片, 下一轮读取就复用该内存, 直接引用会变成"每条报文都是最后一个包"。
	if len(data) > pktRawCap {
		rec.Raw = append([]byte(nil), data[:pktRawCap]...)
	} else {
		rec.Raw = append([]byte(nil), data...)
	}
	p.mu.Lock()
	p.seq++
	rec.Seq = p.seq
	p.total++
	if len(p.buf) < pktLogCap {
		p.buf = append(p.buf, rec)
	} else {
		p.buf[p.next] = rec
	}
	p.next = (p.next + 1) % pktLogCap
	p.mu.Unlock()
}

// Since 返回 seq > since 的记录(最多 limit 条, limit<=0 表示不额外限制)。
//
// 供前端增量轮询: 记住上次看到的最后一个 seq, 每次只取新的, 避免重复传输。
func (p *PacketLog) Since(since int64, limit int) []PacketRecord {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]PacketRecord, 0, 64)
	// 缓冲是环形: 按时间顺序遍历需要从最老的位置开始
	n := len(p.buf)
	for i := 0; i < n; i++ {
		idx := i
		if n == pktLogCap {
			idx = (p.next + i) % n
		}
		r := p.buf[idx]
		if r.Seq > since {
			out = append(out, r)
		}
	}
	if limit > 0 && len(out) > limit {
		// 取最新的 limit 条(排障时更关心最近发生的事)
		out = out[len(out)-limit:]
	}
	return out
}

// Tail 返回最近 limit 条(供"看看现在有什么"的初始加载)
func (p *PacketLog) Tail(limit int) []PacketRecord {
	if p == nil || limit <= 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	n := len(p.buf)
	if n <= limit {
		out := make([]PacketRecord, n)
		copy(out, p.buf)
		return out
	}
	out := make([]PacketRecord, 0, limit)
	for i := n - limit; i < n; i++ {
		idx := i
		if n == pktLogCap {
			idx = (p.next + i) % n
		}
		out = append(out, p.buf[idx])
	}
	return out
}

// Filtered 解码失败被跳过的条数
func (p *PacketLog) Filtered() int64 {
	if p == nil {
		return 0
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.filtered
}

// ===== 解码 =====

// DecodePacket 把一个以太网帧解码成记录。
//
// 【为什么不用 gopacket】项目硬约束是纯标准库、零第三方依赖(单二进制跨平台)。
// 而我们只需要"够用的摘要 + 端口 + 标志", 手写解析即可, 逻辑量可控且有测试守护。
func DecodePacket(data []byte, now time.Time) (PacketRecord, bool) {
	rec := PacketRecord{
		Time:   now.Format("15:04:05.000"),
		TimeMS: now.UnixMilli(),
		Length: len(data),
	}
	if len(data) < 14 {
		return rec, false
	}
	rec.DstMAC = net.HardwareAddr(data[0:6]).String()
	rec.SrcMAC = net.HardwareAddr(data[6:12]).String()
	ether := binary.BigEndian.Uint16(data[12:14])

	// 保留前若干字节供十六进制详情
	if len(data) > pktPayloadKeep {
		rec.Payload = append([]byte(nil), data[:pktPayloadKeep]...)
	} else {
		rec.Payload = append([]byte(nil), data...)
	}

	switch ether {
	case ethTypeARP:
		rec.EtherTy = "ARP"
		rec.Protocol = "ARP"
		decodeARPInfo(&rec, data[14:])
	case ethTypeIPv4:
		rec.EtherTy = "IPv4"
		if len(data) < 34 {
			rec.Protocol = "IPv4"
			rec.Info = "报文截断"
			return rec, true
		}
		decodeIPv4(&rec, data, 14)
	case 0x86dd:
		decodeIPv6(&rec, data, 14)
	default:
		// Npcap 回环适配器(NPF_Loopback, "Adapter for loopback traffic capture")
		// 的帧**没有以太网头**: 帧首是 4 字节地址族(小端: 2=AF_INET, 23=AF_INET6),
		// 之后直接跟裸 IP 包。本机回环流量(如 ping 127.0.0.1 / ::1)只出现在回环
		// 适配器上 —— 不识别这个格式, 用户"选了 ICMP 却抓不到自己的 ping"。
		// 已知 ethertype 的帧已在上面分支消化, 走到这里才试探回环格式, 且要求
		// 前缀精确匹配 + IP 版本号验证, 普通帧误判空间可忽略。
		if off, ok := loopbackIPOffset(data); ok {
			rec.SrcMAC, rec.DstMAC = "", "" // 回环帧无 MAC, 清掉上面从"假 MAC"解出的垃圾值
			if data[off]&0xf0 == 0x40 {
				rec.EtherTy = "IPv4"
				decodeIPv4(&rec, data, off)
			} else {
				decodeIPv6(&rec, data, off)
			}
			return rec, true
		}
		rec.EtherTy = fmt.Sprintf("0x%04x", ether)
		rec.Protocol = "其它"
		// LLDP / STP / EAPOL 等二层协议: 给出常见名字, 否则显示类型号
		if name := l2ProtoName(ether); name != "" {
			rec.Protocol = name
		}
	}
	return rec, true
}

// loopbackIPOffset 识别 Npcap 回环适配器帧, 返回裸 IP 包在帧内的偏移。
//
// 回环帧格式(实测): [02 00 00 00][IPv4 包] 或 [17 00 00 00][IPv6 包] ——
// 前 4 字节是小端地址族(AFI 语义: 2=IPv4, 23=IPv6)。
func loopbackIPOffset(data []byte) (int, bool) {
	if len(data) < 24 {
		return 0, false
	}
	if data[0] == 2 && data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4]&0xf0 == 0x40 {
		return 4, true
	}
	if data[0] == 23 && data[1] == 0 && data[2] == 0 && data[3] == 0 && data[4]&0xf0 == 0x60 {
		return 4, true
	}
	return 0, false
}

// decodeIPv6 解析 IPv6 首部并取第一层的 TCP/UDP/ICMPv6 信息。
// off = IPv6 头在帧内的偏移(以太网帧 14, Npcap 回环帧 4)。
// 只取第一层: 带扩展头的包仍给出源/目的 IP, 协议显示 IPv6。
func decodeIPv6(rec *PacketRecord, data []byte, off int) {
	rec.EtherTy = "IPv6"
	rec.Protocol = "IPv6"
	// IPv6 头 40 字节: 相对偏移 next header=+6, 源 IP=+8..+24, 目的 IP=+24..+40
	if len(data) >= off+40 {
		rec.SrcIP = net.IP(data[off+8 : off+24]).String()
		rec.DstIP = net.IP(data[off+24 : off+40]).String()
		// IPv6 下一头部: 6=TCP 17=UDP 58=ICMPv6
		switch data[off+6] {
		case 6:
			rec.Protocol = "TCPv6"
			if len(data) >= off+44 {
				rec.SrcPort = int(binary.BigEndian.Uint16(data[off+40 : off+42]))
				rec.DstPort = int(binary.BigEndian.Uint16(data[off+42 : off+44]))
			}
		case 17:
			rec.Protocol = "UDPv6"
			if len(data) >= off+44 {
				rec.SrcPort = int(binary.BigEndian.Uint16(data[off+40 : off+42]))
				rec.DstPort = int(binary.BigEndian.Uint16(data[off+42 : off+44]))
			}
		case 58:
			rec.Protocol = "ICMPv6"
			if len(data) >= off+41 {
				rec.Info = icmp6Name(data[off+40])
			}
		}
	}
}

func decodeARPInfo(rec *PacketRecord, a []byte) {
	if len(a) < 8 {
		return
	}
	hlen, plen := int(a[4]), int(a[5])
	if hlen == 0 || plen == 0 || hlen > 16 || plen > 16 || len(a) < 8+2*hlen+2*plen {
		rec.Info = "ARP(报文截断)"
		return
	}
	op := binary.BigEndian.Uint16(a[6:8])
	spa := net.IP(a[8+hlen : 8+hlen+plen]).String()
	tpa := net.IP(a[8+2*hlen+plen : 8+2*hlen+2*plen]).String()
	rec.SrcIP, rec.DstIP = spa, tpa
	switch op {
	case 1:
		rec.Info = fmt.Sprintf("Who has %s? Tell %s", tpa, spa)
	case 2:
		rec.Info = fmt.Sprintf("%s is at %s", spa, rec.SrcMAC)
	default:
		rec.Info = fmt.Sprintf("ARP op=%d %s -> %s", op, spa, tpa)
	}
}

// decodeIPv4 解析 IPv4 首部及第一层 TCP/UDP/ICMP 信息。
// off = IPv4 头在帧内的偏移(以太网帧 14, Npcap 回环帧 4)。
func decodeIPv4(rec *PacketRecord, data []byte, off int) {
	ihl := int(data[off]&0x0f) * 4
	if ihl < 20 || len(data) < off+ihl {
		rec.Protocol = "IPv4"
		rec.Info = "首部长度非法"
		return
	}
	rec.TTL = int(data[off+8])
	proto := data[off+9]
	rec.SrcIP = net.IP(data[off+12 : off+16]).String()
	rec.DstIP = net.IP(data[off+16 : off+20]).String()
	// 总长度用于识别"抓包截断"(snaplen 小于实际帧长时尾巴会被丢掉)
	totalLen := int(binary.BigEndian.Uint16(data[off+2 : off+4]))

	switch proto {
	case 6:
		rec.Protocol = "TCP"
		if len(data) >= off+ihl+14 {
			t := data[off+ihl:]
			rec.SrcPort = int(binary.BigEndian.Uint16(t[0:2]))
			rec.DstPort = int(binary.BigEndian.Uint16(t[2:4]))
			rec.Info = tcpFlags(t[13])
		}
	case 17:
		rec.Protocol = "UDP"
		if len(data) >= off+ihl+4 {
			u := data[off+ihl:]
			rec.SrcPort = int(binary.BigEndian.Uint16(u[0:2]))
			rec.DstPort = int(binary.BigEndian.Uint16(u[2:4]))
			// 常见端口给出应用层名字, 排障时一眼能看出是什么流量
			if name := udpAppName(rec.SrcPort, rec.DstPort); name != "" {
				rec.Info = name
			}
		}
	case 1:
		rec.Protocol = "ICMP"
		if len(data) >= off+ihl+2 {
			rec.Info = icmpName(data[off+ihl], data[off+ihl+1])
		}
	case 2:
		rec.Protocol = "IGMP"
	case 47:
		rec.Protocol = "GRE"
	case 50:
		rec.Protocol = "ESP"
	case 51:
		rec.Protocol = "AH"
	case 89:
		rec.Protocol = "OSPF"
	default:
		rec.Protocol = "IP/" + strconv.Itoa(int(proto))
	}
	// TCP/UDP 的常用端口也补一个应用名(仅当 Info 还是空或只是标志位时)
	if rec.Protocol == "TCP" {
		if name := tcpAppName(rec.SrcPort, rec.DstPort); name != "" {
			if rec.Info == "" {
				rec.Info = name
			} else {
				rec.Info = name + " " + rec.Info
			}
		}
	}
	// 截断提示: 抓到的比 IP 头声明的短
	if totalLen > 0 && off+totalLen > len(data) {
		rec.Info = strings.TrimSpace(rec.Info + " [截断]")
	}
}

// tcpFlags 把 TCP 标志位渲染成 "SYN, ACK" 这样的可读串
func tcpFlags(f byte) string {
	var names []string
	if f&0x01 != 0 {
		names = append(names, "FIN")
	}
	if f&0x02 != 0 {
		names = append(names, "SYN")
	}
	if f&0x04 != 0 {
		names = append(names, "RST")
	}
	if f&0x08 != 0 {
		names = append(names, "PSH")
	}
	if f&0x10 != 0 {
		names = append(names, "ACK")
	}
	if f&0x20 != 0 {
		names = append(names, "URG")
	}
	if len(names) == 0 {
		return ""
	}
	return strings.Join(names, ", ")
}

func icmpName(typ, code byte) string {
	switch typ {
	case 0:
		return "Echo (ping) reply"
	case 3:
		switch code {
		case 0:
			return "Destination unreachable (net)"
		case 1:
			return "Destination unreachable (host)"
		case 3:
			return "Destination unreachable (port)"
		}
		return "Destination unreachable"
	case 5:
		return "Redirect"
	case 8:
		return "Echo (ping) request"
	case 11:
		return "Time-to-live exceeded"
	case 13:
		return "Timestamp request"
	case 14:
		return "Timestamp reply"
	}
	return fmt.Sprintf("ICMP type=%d code=%d", typ, code)
}

func icmp6Name(typ byte) string {
	switch typ {
	case 128:
		return "Echo (ping) request"
	case 129:
		return "Echo (ping) reply"
	case 133:
		return "Router solicitation"
	case 134:
		return "Router advertisement"
	case 135:
		return "Neighbor solicitation"
	case 136:
		return "Neighbor advertisement"
	}
	return fmt.Sprintf("ICMPv6 type=%d", typ)
}

// appPortName 常见端口 -> 应用名(排障时比端口号直观得多)
func appPortName(p int) string {
	switch p {
	case 20, 21:
		return "FTP"
	case 22:
		return "SSH"
	case 23:
		return "Telnet"
	case 25:
		return "SMTP"
	case 53:
		return "DNS"
	case 67, 68:
		return "DHCP"
	case 69:
		return "TFTP"
	case 80, 8080, 8000:
		return "HTTP"
	case 110:
		return "POP3"
	case 123:
		return "NTP"
	case 135:
		return "MSRPC"
	case 137, 138, 139:
		return "NetBIOS"
	case 143:
		return "IMAP"
	case 161, 162:
		return "SNMP"
	case 389:
		return "LDAP"
	case 443, 8443:
		return "HTTPS/TLS"
	case 445:
		return "SMB"
	case 514:
		return "Syslog"
	case 1433:
		return "MSSQL"
	case 1900:
		return "SSDP"
	case 3306:
		return "MySQL"
	case 3389:
		return "RDP"
	case 5353:
		return "mDNS"
	case 5432:
		return "PostgreSQL"
	case 6379:
		return "Redis"
	case 27017:
		return "MongoDB"
	}
	return ""
}

func tcpAppName(sport, dport int) string {
	if n := appPortName(sport); n != "" {
		return n
	}
	return appPortName(dport)
}

func udpAppName(sport, dport int) string {
	if n := appPortName(sport); n != "" {
		return n
	}
	return appPortName(dport)
}

// l2ProtoName 常见二层协议名(非 IP 流量在排障时也需要能看懂)
func l2ProtoName(ether uint16) string {
	switch ether {
	case 0x88cc:
		return "LLDP"
	case 0x8100:
		return "VLAN(802.1Q)"
	case 0x888e:
		return "EAPOL(802.1X)"
	case 0x8809:
		return "LACP"
	case 0x88f7:
		return "PTP"
	case 0x88a8:
		return "VLAN(QinQ)"
	}
	// STP/RSTP/MSTP 的 LLC 帧: 长度字段 <= 1500 且以 0x42 0x42 0x03 开头
	// (这里只能看 ether 字段, 已在长度区间内则提示可能是 STP)
	if ether <= 1500 {
		return "LLC"
	}
	return ""
}
