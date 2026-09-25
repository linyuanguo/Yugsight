package weakpass

import (
	"context"
	"crypto/des" //nolint:staticcheck // VNC 认证协议规定用 DES, 标准库是唯一可用实现
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// vncChecker VNC 弱口令检测(RFB 3.3/3.7/3.8 认证, 纯标准库)。
//
// 判定口径:
//
//	服务端 -> 客户端: 版本横幅 "RFB 003.008\n"
//	客户端 -> 服务端: 回同版本号(取服务端支持的较低版本, 保证双方一致)
//	服务端 -> 客户端: 安全类型列表(3.7+)/ 单个类型(3.3)
//	客户端 -> 服务端: 选定安全类型 2 = VNC Authentication
//	服务端 -> 客户端: 16 字节挑战
//	客户端 -> 服务端: 16 字节响应 = DES-ECB(按位反转的口令, 挑战)
//	服务端 -> 客户端: 4 字节安全结果(0 = 通过)
//
// DES 密钥: VNC 把口令的每个字节**位序反转**(bit-reverse)后取前 8 字节作为 DES
// 密钥。这是 RFB 协议的怪癖(历史实现沿用至今), 不是任意选择 —— 不做这步反转
// 会导致**所有口令都判失败**(包括正确口令), 是这一实现最容易写错的地方。
//
// 安全类型 1(None)是"无需认证": 直接进入会话, 属未授权访问, 一次尝试即定性。
type vncChecker struct{}

func (vncChecker) Name() string { return "vnc" }

// VNC 安全类型。
const (
	vncSecNone     = 1
	vncSecVNC      = 2
	vncAuthMsgLen  = 16
	vncSecResult   = 4
	vncMaxSecTypes = 64
)

func (vncChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	banner, err := readLine(conn, 64)
	if err != nil {
		return false, fmt.Errorf("vnc 读取版本横幅失败: %w", err)
	}
	ver, err := vncVersion(banner)
	if err != nil {
		return false, err
	}
	// 回同版本号: 用服务端给的版本号原样回, 避免"客户端要高版本但服务端不认"。
	if err := writeAll(conn, []byte(ver+"\n")); err != nil {
		return false, fmt.Errorf("vnc 发送版本号失败: %w", err)
	}
	sec, err := vncSelectAuth(conn, ver)
	if err != nil {
		return false, err
	}
	if sec == vncSecNone {
		return true, nil // 无需认证: 未授权访问
	}
	if sec != vncSecVNC {
		return false, fmt.Errorf("vnc 服务端要求安全类型 %d(非 VNC 认证), 标准库实现未覆盖: %w",
			sec, ErrUnsupported)
	}
	challenge := make([]byte, vncAuthMsgLen)
	if _, err := io.ReadFull(conn, challenge); err != nil {
		return false, fmt.Errorf("vnc 读取认证挑战失败: %w", err)
	}
	resp, err := vncResponse(pass, challenge)
	if err != nil {
		return false, err
	}
	if err := writeAll(conn, resp); err != nil {
		return false, fmt.Errorf("vnc 发送认证响应失败: %w", err)
	}
	// 安全结果: 大端 uint32, 0 = 通过, 1 = 失败, 2 = 太多尝试
	var res [vncSecResult]byte
	if _, err := io.ReadFull(conn, res[:]); err != nil {
		return false, fmt.Errorf("vnc 读取认证结果失败: %w", err)
	}
	return binary.BigEndian.Uint32(res[:]) == 0, nil
}

// vncVersion 解析横幅里的版本号(返回 "RFB 003.008" 这类规范化形式)。
//
// readLine 会剥掉结尾 \n, 所以这里的横幅是 11 字节("RFB 003.008") ——
// 不能按协议原文的 12 字节校验, 否则对任何真实服务端都报"横幅非法"。
func vncVersion(banner string) (string, error) {
	b := []byte(banner)
	if len(b) < 11 || string(b[:4]) != "RFB " {
		return "", fmt.Errorf("vnc 版本横幅非法: %q", truncate(banner, 40))
	}
	// 只认到第三个数字段结束, 去掉可能的 \r
	ver := string(b[:11])
	for _, c := range ver[8:] {
		if c < '0' || c > '9' {
			return "", fmt.Errorf("vnc 版本号非法: %q", ver)
		}
	}
	return ver, nil
}

// vncSelectAuth 协商并选定安全类型, 返回服务端最终采用的安全类型。
func vncSelectAuth(conn net.Conn, ver string) (uint32, error) {
	// 3.3 与 3.7+ 的安全类型协商格式不同: 3.3 只有 4 字节单个类型。
	major, minor := vncParse(ver)
	if major == 3 && minor < 7 {
		var one [4]byte
		if _, err := io.ReadFull(conn, one[:]); err != nil {
			return 0, fmt.Errorf("vnc 读取安全类型失败: %w", err)
		}
		sec := binary.BigEndian.Uint32(one[:])
		if err := writeAll(conn, one[:]); err != nil {
			return 0, fmt.Errorf("vnc 发送安全类型选择失败: %w", err)
		}
		return sec, nil
	}
	// 3.7+: 1 字节类型个数 + N 个字节类型
	var cnt [1]byte
	if _, err := io.ReadFull(conn, cnt[:]); err != nil {
		return 0, fmt.Errorf("vnc 读取安全类型数量失败: %w", err)
	}
	n := int(cnt[0])
	if n <= 0 || n > vncMaxSecTypes {
		return 0, fmt.Errorf("vnc 安全类型数量非法: %d", n)
	}
	types := make([]byte, n)
	if _, err := io.ReadFull(conn, types); err != nil {
		return 0, fmt.Errorf("vnc 读取安全类型列表失败: %w", err)
	}
	// 优先选 VNC 认证(2), 其次 None(1): 未授权访问比弱口令更严重, 优先暴露。
	pick := byte(0)
	for _, t := range types {
		if t == vncSecVNC {
			pick = vncSecVNC
			break
		}
		if t == vncSecNone {
			pick = vncSecNone
		}
	}
	if pick == 0 {
		return 0, fmt.Errorf("vnc 服务端未提供 VNC 认证/None 安全类型(仅 %v): %w", types, ErrUnsupported)
	}
	if err := writeAll(conn, []byte{pick}); err != nil {
		return 0, fmt.Errorf("vnc 发送安全类型选择失败: %w", err)
	}
	return uint32(pick), nil
}

// vncParse 解析版本号 "RFB 003.008" 的 major/minor。
func vncParse(ver string) (int, int) {
	if len(ver) < 11 {
		return 0, 0
	}
	major := int(ver[4]-'0')*100 + int(ver[5]-'0')*10 + int(ver[6]-'0')
	minor := int(ver[8]-'0')*100 + int(ver[9]-'0')*10 + int(ver[10]-'0')
	return major, minor
}

// vncResponse 计算 16 字节认证响应。
//
// 口令须先做**位序反转**(每字节 bit-reverse)再取前 8 字节作 DES 密钥, 不足 8 字节
// 补 0。不做这步反转会导致正确口令也判失败 —— RFB 协议的历史怪癖。
func vncResponse(pass string, challenge []byte) ([]byte, error) {
	if len(challenge) != vncAuthMsgLen {
		return nil, fmt.Errorf("vnc 挑战长度非法: %d", len(challenge))
	}
	var key [8]byte
	for i := 0; i < 8 && i < len(pass); i++ {
		key[i] = vncReverseBits(pass[i])
	}
	block, err := des.NewCipher(key[:]) //nolint:staticcheck // 协议规定
	if err != nil {
		return nil, fmt.Errorf("vnc DES 初始化失败: %w", err)
	}
	out := make([]byte, vncAuthMsgLen)
	block.Encrypt(out[0:8], challenge[0:8])
	block.Encrypt(out[8:16], challenge[8:16])
	return out, nil
}

// vncReverseBits 反转一个字节的位序(0b11000000 -> 0b00000011)。
func vncReverseBits(b byte) byte {
	b = (b&0xF0)>>4 | (b&0x0F)<<4
	b = (b&0xCC)>>2 | (b&0x33)<<2
	b = (b&0xAA)>>1 | (b&0x55)<<1
	return b
}
