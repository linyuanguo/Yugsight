package weakpass

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// mysqlChecker MySQL / MariaDB 弱口令检测(协议握手 + 口令认证)。
//
// 流程(与 MySQL 4.1+ 客户端协议一致):
//
//	服务端 -> 客户端: Initial Handshake Packet(seq 0, protocol 10)
//	客户端 -> 服务端: Handshake Response 41(seq 1, 含加密后的口令)
//	服务端 -> 客户端: OK(0x00) / ERR(0xFF)
//
// 口令加密(mysql_native_password):
//
//	h1 = SHA1(pass)
//	h2 = SHA1(h1)
//	h3 = SHA1(nonce + h2)
//	scramble = h1 XOR h3        // 20 字节
//
// 空口令: 认证响应长度字段写 0(不发送 scramble), 服务端按"该用户无口令"校验
// —— 这正是"空口令"这一高危配置的标准检测方式。
//
// 能力边界: MySQL 8 默认改用 caching_sha2_password, 完整实现需要 TLS 或 RSA
// 公钥加密(标准库可做但代码量与出错面都大)。遇到时**明确返回错误**, 不做
// "猜一个判定"的伪实现。
type mysqlChecker struct{}

func (mysqlChecker) Name() string { return "mysql" }

// MySQL 客户端能力位(只挑必需的, 不多声明用不到的能力)。
const (
	mysqlCapProtocol41     = 0x00000200 // 4.1+ 协议
	mysqlCapSecureConn     = 0x00008000 // 支持 20 字节加密口令
	mysqlCapPluginAuth     = 0x00080000 // 支持认证插件名
	mysqlNativePasswordPh  = "mysql_native_password"
	mysqlPktHeaderLen      = 4
	mysqlHandshakeMinLen   = 20
	mysqlProtocolVersion10 = 10
)

func (mysqlChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	payload, err := readMySQLPacket(conn)
	if err != nil {
		return false, fmt.Errorf("mysql 读取握手包失败: %w", err)
	}
	nonce, caps, err := parseHandshake(payload)
	if err != nil {
		return false, err
	}
	if caps&mysqlCapSecureConn == 0 {
		return false, fmt.Errorf("mysql 服务端不支持安全连接认证(旧协议), 未支持: %w", ErrUnsupported)
	}
	resp, err := buildAuthResponse(user, pass, nonce)
	if err != nil {
		return false, err
	}
	if err := writeMySQLPacket(conn, resp, 1); err != nil {
		return false, fmt.Errorf("mysql 发送认证包失败: %w", err)
	}
	reply, err := readMySQLPacket(conn)
	if err != nil {
		return false, fmt.Errorf("mysql 读取认证应答失败: %w", err)
	}
	if len(reply) == 0 {
		return false, fmt.Errorf("mysql 认证应答为空")
	}
	switch reply[0] {
	case 0x00:
		return true, nil // OK: 口令正确(或该用户无口令)
	case 0xFF:
		return false, nil // ERR: 口令错误 / 账号被拒
	case 0xFE:
		// 认证切换: 服务端要求换插件。caching_sha2_password 需要 TLS 或 RSA,
		// 明确报不支持, 而不是回 false 让用户以为"口令没问题"。
		plugin := string(trimZero(reply[1:]))
		if plugin == "" {
			plugin = "未知插件"
		}
		return false, fmt.Errorf("mysql 服务端要求认证插件 %s, 标准库实现仅覆盖 %s: %w",
			plugin, mysqlNativePasswordPh, ErrUnsupported)
	default:
		return false, fmt.Errorf("mysql 未识别的应答类型: 0x%02X", reply[0])
	}
}

// parseHandshake 解析 Initial Handshake Packet, 返回 20 字节 nonce 与服务端能力位。
func parseHandshake(p []byte) (nonce []byte, caps uint32, err error) {
	if len(p) < mysqlHandshakeMinLen {
		return nil, 0, fmt.Errorf("mysql 握手包过短(%d 字节)", len(p))
	}
	if p[0] != mysqlProtocolVersion10 {
		return nil, 0, fmt.Errorf("mysql 协议版本 %d 未支持(仅支持 10)", p[0])
	}
	rest := p[1:]
	i := indexZero(rest)
	if i < 0 {
		return nil, 0, fmt.Errorf("mysql 握手包缺少版本字符串结束符")
	}
	rest = rest[i+1:] // 跳过 server version + 结束符
	// connection id(4) + auth-plugin-data-part-1(8) + filler(1)
	if len(rest) < 13 {
		return nil, 0, fmt.Errorf("mysql 握手包字段不足")
	}
	rest = rest[4:]
	var part1 [8]byte
	copy(part1[:], rest[:8])
	rest = rest[9:] // 8 字节 data + 1 字节 filler
	// 能力位低 16 位 + 字符集(1) + 状态位(2) + 能力位高 16 位 + auth data len(1) + 保留(10)
	if len(rest) < 18 {
		return nil, 0, fmt.Errorf("mysql 握手包能力字段不足")
	}
	capLow := binary.LittleEndian.Uint16(rest[0:2])
	rest = rest[5:] // 2 能力 + 1 字符集 + 2 状态
	capHigh := binary.LittleEndian.Uint16(rest[0:2])
	authDataLen := int(rest[2])
	rest = rest[13:] // 2 能力 + 1 长度 + 10 保留
	caps = uint32(capLow) | uint32(capHigh)<<16

	n := authDataLen - 8
	if n < 0 {
		n = 0
	}
	if n > len(rest) {
		n = len(rest)
	}
	nonce = make([]byte, 0, 20)
	nonce = append(nonce, part1[:]...)
	nonce = append(nonce, rest[:n]...)
	if len(nonce) < 20 {
		nonce = append(nonce, make([]byte, 20-len(nonce))...)
	}
	nonce = nonce[:20]
	return nonce, caps, nil
}

// buildAuthResponse 构造 Handshake Response 41 的负载。
func buildAuthResponse(user, pass string, nonce []byte) ([]byte, error) {
	caps := uint32(mysqlCapProtocol41 | mysqlCapSecureConn | mysqlCapPluginAuth)
	out := make([]byte, 0, 64+len(user)+32)
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], caps)
	out = append(out, b[:]...)
	binary.LittleEndian.PutUint32(b[:], 0x01000000) // max packet size
	out = append(out, b[:]...)
	out = append(out, 33) // utf8_general_ci
	out = append(out, make([]byte, 23)...)
	out = append(out, []byte(user)...)
	out = append(out, 0)
	if pass == "" {
		// 空口令: 认证数据长度为 0
		out = append(out, 0)
	} else {
		sc, err := mysqlScramble(pass, nonce)
		if err != nil {
			return nil, err
		}
		out = append(out, byte(len(sc)))
		out = append(out, sc...)
	}
	out = append(out, []byte(mysqlNativePasswordPh)...)
	out = append(out, 0)
	return out, nil
}

// mysqlScramble 计算 mysql_native_password 的 20 字节认证串。
func mysqlScramble(pass string, nonce []byte) ([]byte, error) {
	if len(nonce) < 20 {
		return nil, fmt.Errorf("mysql nonce 长度不足(%d)", len(nonce))
	}
	h1 := sha1.Sum([]byte(pass))
	h2 := sha1.Sum(h1[:])
	h := sha1.New()
	h.Write(nonce[:20])
	h.Write(h2[:])
	h3 := h.Sum(nil)
	out := make([]byte, 20)
	for i := 0; i < 20; i++ {
		out[i] = h1[i] ^ h3[i]
	}
	return out, nil
}

// readMySQLPacket 读一个 MySQL 协议包(4 字节头 + 负载)。
func readMySQLPacket(r io.Reader) ([]byte, error) {
	hdr := make([]byte, mysqlPktHeaderLen)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	n := int(hdr[0]) | int(hdr[1])<<8 | int(hdr[2])<<16
	if n <= 0 || n > 1<<24 {
		return nil, fmt.Errorf("mysql 包长度非法: %d", n)
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

// writeMySQLPacket 写一个 MySQL 协议包。
func writeMySQLPacket(w io.Writer, payload []byte, seq byte) error {
	n := len(payload)
	hdr := []byte{byte(n), byte(n >> 8), byte(n >> 16), seq}
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// indexZero 找第一个 0x00 的位置(找不到返回 -1)。
func indexZero(b []byte) int {
	for i, c := range b {
		if c == 0 {
			return i
		}
	}
	return -1
}

// trimZero 截断到第一个 0x00(用于取 C 风格字符串)。
func trimZero(b []byte) []byte {
	if i := indexZero(b); i >= 0 {
		return b[:i]
	}
	return b
}
