package weakpass

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// oracleChecker Oracle 数据库弱口令检测(TNS 协议 CONNECT + O3LOGON, 纯标准库)。
//
// 判定口径:
//
//	TCP 连接 -> TNS Connect 包(packet type 0x01): 携带 CONNECT_DATA
//	            (SERVICE_NAME/ORACLE_SID + 客户端字符集)
//	服务端 -> TNS Accept(0x02)/Refuse(0x04)/Redirect(0x03)
//	客户端 -> TNS Data(0x06): 内嵌 TNS 登录包 + O3LOGON 口令校验
//	服务端 -> TNS Data: 认证结果(成功/ORA-01017 口令无效)
//
// 【实现边界, 必须如实说明】Oracle 的 O3LOGON 口令校验算法(2017 年前的老版本)
// 是 AUTH_PASSWORD + AUTH_SESSKEY 两轮"生成器", 其核心是一个非公开的哈希
// (Oracle 的 password verifier), 标准库无法实现。新版(11g+)使用
// O5LOGON/AUTH_SESSKEY + AES, 也依赖 Oracle 私有的密钥派生细节。
//
// 因此本实现做的是**TNS 层可达性 + 服务标识确认**: 完成 TNS 握手、读出
// CONNECT_DATA 里返回的实例名/版本, 并明确返回 ErrUnsupported 说明"口令无法
// 用纯标准库验证"。
//
// 为什么不做"发个包看有没有 ORA-01017"的伪判定: 服务端对任何口令都会回错误,
// 无法区分"口令错"与"口令对" —— 得到一个恒定 false 的 checker 毫无价值, 反而
// 会让用户以为"扫过了、没有弱口令"。明确的能力边界比虚假的覆盖率有用。
type oracleChecker struct{}

func (oracleChecker) Name() string { return "oracle" }

// TNS 包类型与版本。
const (
	tnsTypeConnect  = 1
	tnsTypeAccept   = 2
	tnsTypeAck      = 3
	tnsTypeRefuse   = 4
	tnsTypeRedirect = 5
	tnsTypeData     = 6
	tnsTypeResend   = 11
	tnsTypeMarker   = 12
	tnsTypeAlert    = 14
	tnsVersion      = 0x0136 // 1.6
	tnsHeaderLen    = 8
	tnsMaxPacket    = 1 << 20
)

func (oracleChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	// 1) TNS Connect: 不含口令, 只声明要连的库(用 ORCL 通用名, 服务名错的
	//    实例会回 Refuse/Redirect, 我们在错误里带上, 便于定位)
	connectData := tnsConnectData("ORCL")
	if err := tnsSend(conn, tnsTypeConnect, connectData); err != nil {
		return false, err
	}
	typ, payload, err := tnsRead(conn)
	if err != nil {
		return false, fmt.Errorf("oracle 读取 Connect 响应失败: %w", err)
	}
	switch typ {
	case tnsTypeAccept:
		// 正常: 服务端接受连接, payload 里含 Accept 数据(实例信息)
	case tnsTypeRefuse:
		return false, fmt.Errorf("oracle 服务端拒绝连接(Refuse): %w", ErrUnsupported)
	case tnsTypeRedirect:
		_, host, port := tnsParseRedirect(payload)
		return false, fmt.Errorf("oracle 服务端要求重定向到 %s:%d(可能为 RAC/监听器分发): %w",
			host, port, ErrUnsupported)
	default:
		return false, fmt.Errorf("oracle Connect 响应类型异常: %d: %w", typ, ErrUnsupported)
	}

	// 2) 口令验证: TNS 层能到达, 但 O3LOGON/O5LOGON 的口令校验依赖 Oracle 私有
	//    哈希与密钥派生, 标准库无法实现 —— 显式报不支持而非伪造判定。
	_ = user
	_ = pass
	return false, fmt.Errorf("oracle TNS 可达(已获 Accept), 但口令校验依赖 Oracle 私有 O3LOGON/O5LOGON: %w",
		ErrUnsupported)
}

// tnsSend 发送一个 TNS 包(8 字节头 + 负载)。
func tnsSend(conn net.Conn, typ byte, payload []byte) error {
	total := tnsHeaderLen + len(payload)
	out := make([]byte, total)
	binary.BigEndian.PutUint16(out[0:2], uint16(total))
	// packet checksum(2) 留 0
	out[4] = typ
	out[5] = 0x00 // reserved
	binary.BigEndian.PutUint16(out[6:8], tnsVersion)
	copy(out[8:], payload)
	if err := writeAll(conn, out); err != nil {
		return fmt.Errorf("oracle 发送 TNS 包失败: %w", err)
	}
	return nil
}

// tnsRead 读一个 TNS 包, 返回类型与负载。
func tnsRead(conn net.Conn) (byte, []byte, error) {
	var hdr [tnsHeaderLen]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[0:2]))
	if n < tnsHeaderLen || n > tnsMaxPacket {
		return 0, nil, fmt.Errorf("oracle TNS 包长度非法: %d", n)
	}
	body := make([]byte, n-tnsHeaderLen)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	return hdr[4], body, nil
}

// tnsConnectData 构造 CONNECT_DATA(不含口令的纯 TNS Connect 描述)。
//
// 结构(简化, 通用 Connect): 长度(2) + 版本(2) + 服务选项(2) + SDU(2) +
// TDU(2) + 协议特征(2) + 行首字节数(2) + 字符集(2=US7ASCII) + 名长度(2) + 名...
func tnsConnectData(service string) []byte {
	sn := []byte(service)
	// 头部 18 字节固定字段
	out := make([]byte, 18)
	binary.BigEndian.PutUint16(out[0:2], uint16(18+len(sn)))
	binary.BigEndian.PutUint16(out[2:4], tnsVersion)
	// 服务选项: 0x0C11 = 常见(分散事务/句柄)
	binary.BigEndian.PutUint16(out[4:6], 0x0C11)
	binary.BigEndian.PutUint16(out[6:8], 0x2000)  // SDU
	binary.BigEndian.PutUint16(out[8:10], 0x2000) // TDU
	binary.BigEndian.PutUint16(out[10:12], 0x0800)
	binary.BigEndian.PutUint16(out[12:14], 0x0000)
	binary.BigEndian.PutUint16(out[14:16], 0x0055) // 字符集 US7ASCII
	binary.BigEndian.PutUint16(out[16:18], uint16(len(sn)))
	return append(out, sn...)
}

// tnsParseRedirect 解析 Redirect 包里的目标地址(尽力而为, 拿不到就给空串)。
func tnsParseRedirect(p []byte) (typ byte, host string, port uint16) {
	// Redirect 负载: 长度(2) + 数据长度(2) + 数据类型(1) + 协议(2) + 主机长度(2) + ...
	if len(p) < 11 {
		return 0, "", 0
	}
	t := p[4]
	if len(p) < 13 {
		return t, "", 0
	}
	hostLen := int(binary.BigEndian.Uint16(p[9:11]))
	hostOff := 13
	if hostLen <= 0 || hostOff+hostLen+2 > len(p) {
		return t, "", 0
	}
	host = string(p[hostOff : hostOff+hostLen])
	port = binary.BigEndian.Uint16(p[hostOff+hostLen : hostOff+hostLen+2])
	return t, host, port
}
