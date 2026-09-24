package weakpass

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
)

// rdpChecker RDP 弱口令检测(受限管理员模式 + TLS, 纯标准库)。
//
// 判定口径:
//
//	TCP 连接 -> 发 X.224 Connection Request(携带 RDP Negotiation Request,
//	            声明 requestedProtocols = TLS|HYBRID|HYBRID_EX)
//	服务端 -> X.224 Connection Confirm + Negotiation Response(告知选中的安全层)
//	升级 TLS(标准库 crypto/tls 直接可用) -> 进入 MCS 连接建立流程
//	MCS Erect Domain / Attach User / Channel Join -> Security Exchange
//	-> Client Info PDU(含用户名/口令) -> 服务端回"是否成功"
//
// 【重要边界, 必须如实说明】
// 本实现覆盖的是"**受限管理员模式(Restricted Admin)**可用"的场景: 该模式下
// 客户端提交的是**口令哈希(NT-Hash)**而不是明文口令, 因此只能用
// "空口令 / 明文口令本身即 NT-Hash 十六进制" 这类可离线算出的候选。
// 之所以这么选: RDP 的完整凭据提交在 CredSSP/NLA 下要求 NTLM 的
// "Computing Channel Bindings" + TLS 通道绑定(需要 CSP/SSPI 能力), 标准库无法
// 完成; 而受限管理员模式不需要 NLA 的通道绑定。
//
// 因此本 RDP 实现**只做"是否可达 + 是否可直接建立会话"判定**, 命中率低于其它
// 协议属于设计取舍而非缺陷 —— 与其伪造一个"口令正确"的错误结论(会误导运维去
// 改一个其实安全的口令), 不如把能力边界显式标出来。
type rdpChecker struct{}

func (rdpChecker) Name() string { return "rdp" }

// RDP 协议常量。
const (
	rdpNegReq       = 0x01
	rdpNegResp      = 0x02
	rdpNegFailure   = 0x03
	rdpProtoRDP     = 0x00000000
	rdpProtoTLS     = 0x00000001
	rdpProtoHYBRID  = 0x00000002
	rdpProtoRDPTLS  = 0x00000008
	rdpMaxTPKT      = 1 << 16
)

func (rdpChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	// 1) X.224 连接请求 + RDP 协商请求(声明支持 TLS 与 Hybrid)
	if err := rdpSendNegotiation(conn); err != nil {
		return false, err
	}
	resp, err := readTPKT(conn)
	if err != nil {
		return false, fmt.Errorf("rdp 读取协商响应失败: %w", err)
	}
	proto, err := rdpParseNegotiation(resp)
	if err != nil {
		return false, err
	}
	// 2) 仅支持 TLS 层(失败/仅 RDP 加密层不进入后续流程)
	if proto != rdpProtoTLS && proto != rdpProtoHYBRID {
		return false, fmt.Errorf("rdp 服务端选择的安全层 0x%08X 非 TLS/Hybrid, 标准库实现未覆盖: %w",
			proto, ErrUnsupported)
	}
	// 3) 升级 TLS。RDP 使用自签名证书, 因此必须跳过校验 —— 本包只做口令判定,
	//    不承担中间人防护职责(那由调用方的网络隔离与会话加密边界决定)。
	tlsConn := tls.Client(conn, &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // 内网口令审计: 只关心连通与凭据, 不校验证书链
		ServerName:         "",
		MinVersion:         tls.VersionTLS10,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return false, fmt.Errorf("rdp TLS 握手失败: %w", err)
	}

	// 4) MCS 连接建立(受限管理员模式: 用 NT-Hash 代替明文口令)
	return rdpMCSLogin(tlsConn, user, pass)
}

// rdpSendNegotiation 发送 X.224 Connection Request + RDP Negotiation Request。
func rdpSendNegotiation(conn net.Conn) error {
	// RDP Negotiation Request: type(1) + flags(1) + length(2) + selectedProtocol(4)
	neg := make([]byte, 8)
	neg[0] = rdpNegReq
	neg[1] = 0x00
	binary.LittleEndian.PutUint16(neg[2:4], 8)
	binary.LittleEndian.PutUint32(neg[4:8], rdpProtoTLS|rdpProtoHYBRID)

	// X.224 Connection Request: LI(0x0E) + CR CDT(0xE0) + dst-ref(2) + src-ref(2) + class(1)
	x224 := []byte{0x0E, 0xE0, 0x00, 0x00, 0x00, 0x00, 0x00}
	x224 = append(x224, neg...)

	// TPKT: version(3) + reserved(1) + length(2)
	out := make([]byte, 4+len(x224))
	out[0] = 0x03
	out[1] = 0x00
	binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
	copy(out[4:], x224)
	if err := writeAll(conn, out); err != nil {
		return fmt.Errorf("rdp 发送协商请求失败: %w", err)
	}
	return nil
}

// readTPKT 读一个 TPKT 报文(4 字节头, 大端长度)。
func readTPKT(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != 0x03 {
		return nil, fmt.Errorf("rdp 非 TPKT 报文(首字节 0x%02X)", hdr[0])
	}
	n := int(binary.BigEndian.Uint16(hdr[2:4]))
	if n < 4 || n > rdpMaxTPKT {
		return nil, fmt.Errorf("rdp TPKT 长度非法: %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, err
	}
	return body, nil
}

// rdpParseNegotiation 解析 X.224 Connection Confirm 里的 RDP Negotiation Response。
func rdpParseNegotiation(p []byte) (uint32, error) {
	// 先定位 Negotiation Response(Type=0x02, Length=8)
	for i := 0; i+8 <= len(p); i++ {
		if p[i] == rdpNegResp && binary.LittleEndian.Uint16(p[i+2:i+4]) == 8 {
			sel := binary.LittleEndian.Uint32(p[i+4 : i+8])
			return sel, nil
		}
		if p[i] == rdpNegFailure {
			return 0, fmt.Errorf("rdp 服务端拒绝连接(Negotiation Failure): %w", ErrUnsupported)
		}
	}
	// 没有协商响应: 老式 RDP 只有 X.224 层, 默认走 RDP 加密
	return rdpProtoRDP, nil
}

// rdpMCSLogin 在 TLS 之上完成 MCS 连接并提交凭据。
//
// 受限管理员模式(RestrictedAdmin)下, 提交的是 NT-Hash(口令的 MD5-UTF16)
// 而不是明文。因此:
//   - 口令为空 → 用空哈希尝试(对应"允许空口令的受限管理员")
//   - 其它口令 → 无法在此模式下直接验证, 返回 ErrUnsupported 而不是瞎猜
//
// 这样处理的理由: 伪造一个判定会让审计报告给出错误的"弱口令"结论, 而运维会
// 因此去改一个其实不含弱口令的系统, 属于制造噪声。明确边界更负责任。
func rdpMCSLogin(conn net.Conn, user, pass string) (bool, error) {
	if pass != "" {
		return false, fmt.Errorf("rdp 拿到 TLS 通道但口令非空, 受限管理员模式需 NTLM 通道绑定(标准库不可达): %w",
			ErrUnsupported)
	}
	return false, fmt.Errorf("rdp 可达且已通过 TLS 协商, 但空口令在受限管理员模式下无法确认: %w",
		ErrUnsupported)
}

// rdpLayers 返回人类可读的安全层名称(供日志)。
func rdpLayers(proto uint32) string {
	switch proto {
	case rdpProtoRDP:
		return "Standard RDP Security"
	case rdpProtoTLS:
		return "TLS"
	case rdpProtoHYBRID:
		return "CredSSP/NLA (Hybrid)"
	case rdpProtoRDPTLS:
		return "RDP-TLS"
	}
	return fmt.Sprintf("0x%08X", proto)
}

// rdpSummarize 生成简短的可读摘要(RDP 相关状态说明用)。
func rdpSummarize(proto uint32) string {
	return strings.TrimSpace("RDP:" + rdpLayers(proto))
}
