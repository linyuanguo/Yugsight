package weakpass

import (
	"context"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strings"
)

// postgresChecker PostgreSQL 弱口令检测(消息协议 v3, 纯标准库)。
//
// 判定口径:
//
//	客户端 -> 服务端: StartupMessage(含 user 参数)
//	服务端 -> 客户端: 认证请求 'R'(AuthenticationRequest)
//	  - 0  = AuthenticationOk          → 免认证(trust 认证方式)
//	  - 3  = CleartextPassword         → 发明文口令
//	  - 5  = MD5Password(带 4 字节盐)  → 发 "md5" + md5(md5(pass+user)+salt)
//	客户端 -> 服务端: PasswordMessage 'p'
//	服务端 -> 客户端: AuthenticationOk(认证通过) / ErrorResponse 'E'(认证失败)
//
// 为什么能覆盖绝大多数场景: 内网 PostgreSQL 的 pg_hba.conf 默认对同网段用
// md5/trust, 而 scram-sha-256 需要 PBKDF2 + 完整 SASL 协商。遇到 10(scram)时
// 明确返回 ErrUnsupported, 不做"猜一个判定"的伪实现 —— 误报会让人去改一个
// 其实很强的口令, 漏报只是少一条提示。
type postgresChecker struct{}

func (postgresChecker) Name() string { return "postgresql" }

// PostgreSQL 认证请求子类型。
const (
	pgAuthOk              = 0
	pgAuthCleartext       = 3
	pgAuthMD5             = 5
	pgAuthSASL            = 10
	pgAuthSASLContinue    = 11
	pgAuthSASLFinal       = 12
	pgProtocolVersion3    = 196608 // 3 << 16
	pgMaxMsgLen           = 1 << 20
	pgSSLRequestCode      = 80877103 // 8.2+ SSLRequest 魔数, 用 1 字节应答
)

func (postgresChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	if err := writeStartup(conn, user); err != nil {
		return false, err
	}
	// 读第一条消息: 正常是 'R'(认证请求); 若服务端要求 SSL, 会先回 1 字节
	// 'S'/'N'(SSLRequest 应答)。这里**不发 SSLRequest**, 因此不会走到那个分支;
	// 若真收到非 'R' 的开头, 说明协议不符, 明确报错而不是继续瞎读。
	typ, payload, err := readPGMessage(conn)
	if err != nil {
		return false, fmt.Errorf("postgres 读取认证请求失败: %w", err)
	}
	if typ != 'R' {
		return false, fmt.Errorf("postgres 未收到认证请求(收到消息类型 %q): %w", string(typ), ErrUnsupported)
	}
	if len(payload) < 4 {
		return false, fmt.Errorf("postgres 认证请求过短")
	}
	sub := binary.BigEndian.Uint32(payload[:4])
	switch sub {
	case pgAuthOk:
		return true, nil // trust 认证: 无需口令即通过
	case pgAuthCleartext:
		if err := writePGPassword(conn, pass); err != nil {
			return false, err
		}
	case pgAuthMD5:
		if len(payload) < 8 {
			return false, fmt.Errorf("postgres MD5 认证请求缺少盐值")
		}
		if err := writePGPassword(conn, pgMD5Pass(pass, user, payload[4:8])); err != nil {
			return false, err
		}
	default:
		// scram-sha-256(10) / GSS / SSPI 等: 明确报不支持
		return false, fmt.Errorf("postgres 服务端要求认证方式 %d(scram/gss 等), 标准库实现仅覆盖 md5/明文: %w",
			sub, ErrUnsupported)
	}
	return readPGAuthResult(conn)
}

// writeStartup 发送不含口令的 StartupMessage。
//
// 长度字段含自身(4 字节), 所以总长 = 4 + 4 + len(payload)。
func writeStartup(conn net.Conn, user string) error {
	var body []byte
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], pgProtocolVersion3)
	body = append(body, b[:]...)
	// 参数区: key\0value\0..., 以额外的 \0 结束
	body = append(body, []byte("user")...)
	body = append(body, 0)
	body = append(body, []byte(user)...)
	body = append(body, 0)
	body = append(body, []byte("database")...)
	body = append(body, 0)
	body = append(body, []byte(user)...)
	body = append(body, 0)
	body = append(body, 0)

	out := make([]byte, 4, 4+len(body))
	binary.BigEndian.PutUint32(out, uint32(4+len(body)))
	out = append(out, body...)
	if err := writeAll(conn, out); err != nil {
		return fmt.Errorf("postgres 发送 StartupMessage 失败: %w", err)
	}
	return nil
}

// writePGPassword 发送 PasswordMessage 'p'(明文或 md5 串)。
func writePGPassword(conn net.Conn, secret string) error {
	payload := append([]byte(secret), 0)
	out := make([]byte, 0, 5+len(payload))
	out = append(out, 'p')
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(4+len(payload)))
	out = append(out, b[:]...)
	out = append(out, payload...)
	if err := writeAll(conn, out); err != nil {
		return fmt.Errorf("postgres 发送口令失败: %w", err)
	}
	return nil
}

// pgMD5Pass 计算 PostgreSQL md5 认证串: "md5" + hex(md5(hex(md5(pass+user)) + salt))。
func pgMD5Pass(pass, user string, salt []byte) string {
	h1 := md5.Sum([]byte(pass + user))
	inner := hex.EncodeToString(h1[:])
	h2 := md5.Sum(append([]byte(inner), salt...))
	return "md5" + hex.EncodeToString(h2[:])
}

// readPGAuthResult 读认证结果: 'R'+0 = 成功, 'E' = 失败(口令错/账号被拒)。
func readPGAuthResult(conn net.Conn) (bool, error) {
	typ, payload, err := readPGMessage(conn)
	if err != nil {
		return false, fmt.Errorf("postgres 读取认证结果失败: %w", err)
	}
	switch typ {
	case 'R':
		if len(payload) >= 4 && binary.BigEndian.Uint32(payload[:4]) == pgAuthOk {
			return true, nil
		}
		return false, fmt.Errorf("postgres 认证请求未完结(未收到 AuthenticationOk)")
	case 'E':
		return false, nil // ErrorResponse: 口令错误
	}
	return false, fmt.Errorf("postgres 未识别的认证结果类型: %q", string(typ))
}

// readPGMessage 读一条 PostgreSQL 消息: 1 字节类型 + 4 字节长度(含自身) + 负载。
func readPGMessage(r io.Reader) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[1:5]))
	if n < 4 || n > pgMaxMsgLen {
		return 0, nil, fmt.Errorf("postgres 消息长度非法: %d", n)
	}
	payload := make([]byte, n-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, err
	}
	return hdr[0], payload, nil
}

// pgErrDetail 从 ErrorResponse 里提取最关键的一行(供错误信息回显)。
func pgErrDetail(payload []byte) string {
	var parts []string
	for i := 0; i < len(payload); {
		field := payload[i]
		i++
		j := indexZero(payload[i:])
		if j < 0 {
			break
		}
		if field == 'M' { // M = 主要消息
			parts = append(parts, string(payload[i:i+j]))
		}
		i += j + 1
	}
	return strings.Join(parts, "; ")
}
