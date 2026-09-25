package scanner

// pcap_export.go 把留存的报文拼成标准 pcap 文件(纯标准库, 可离线单测)。
//
// 【为什么在 scanner 包而不是 main】pcap 拼装是纯函数, 与 HTTP/会话解耦后
// 可以逐字节断言(魔数/版本/时间戳/帧长), 主包只做端点接线。
//
// 【pcap 格式要点】全局头 24 字节 + 每条记录 16 字节头 + 原始帧。
// 魔数 0xa1b2c3d4 本身是端序标记: 读端(如 Wireshark)按魔数判断整文件的
// 字节序, 故这里统一小端写出, 所有字段同序即可互通。
import "encoding/binary"

const (
	pcapMagic      = 0xa1b2c3d4
	pcapSnapLen    = 65535 // 单记录最大长度, 与 pktRawCap 同口径
	pcapLinkEther  = 1     // 链路层类型: 以太网(LINKTYPE_ETHERNET)
	pcapGlobalLen  = 24
	pcapRecordLen  = 16
)

// BuildPcap 把留存报文拼成标准 pcap 文件内容。
//
// 只写带原始帧(Raw)的记录: 仅有 256 字节摘要(Payload)的记录写出来是截断帧,
// 在 Wireshark 里既看不懂也没用, 反而会误导排障 —— 直接跳过。
// 回环适配器的帧带 4 字节地址族前缀、无以太网头, 按以太网(linktype 1)写出
// 在 Wireshark 里会解析错位, 属已知限制; 物理网卡流量(绝大多数场景)正常。
func BuildPcap(recs []PacketRecord) []byte {
	out := make([]byte, 0, pcapGlobalLen+len(recs)*(pcapRecordLen+1514))

	// 全局头: 魔数 / 版本 2.4 / thiszone 0 / sigfigs 0 / snaplen / 链路类型
	var gh [pcapGlobalLen]byte
	binary.LittleEndian.PutUint32(gh[0:4], pcapMagic)
	binary.LittleEndian.PutUint16(gh[4:6], 2) // 版本主
	binary.LittleEndian.PutUint16(gh[6:8], 4) // 版本次
	binary.LittleEndian.PutUint32(gh[8:12], 0)
	binary.LittleEndian.PutUint32(gh[12:16], 0)
	binary.LittleEndian.PutUint32(gh[16:20], pcapSnapLen)
	binary.LittleEndian.PutUint32(gh[20:24], pcapLinkEther)
	out = append(out, gh[:]...)

	for _, r := range recs {
		if len(r.Raw) == 0 {
			continue
		}
		ms := r.TimeMS
		incl := len(r.Raw)
		orig := r.Length
		if orig == 0 {
			orig = incl
		}
		var rh [pcapRecordLen]byte
		binary.LittleEndian.PutUint32(rh[0:4], uint32(ms/1000))
		binary.LittleEndian.PutUint32(rh[4:8], uint32((ms%1000)*1000))
		binary.LittleEndian.PutUint32(rh[8:12], uint32(incl))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(orig))
		out = append(out, rh[:]...)
		out = append(out, r.Raw...)
	}
	return out
}
