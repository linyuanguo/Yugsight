package weakpass

import (
	"context"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4" //nolint:staticcheck // SMB1/NTLMv2 协议规定 RC4
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"unicode/utf16"
)

// smbChecker SMB/Windows 共享弱口令检测(SMB1 + NTLMSSP, 纯标准库)。
//
// 判定口径:
//
//	TCP 握手 -> SMB1 Negotiate Protocol(声明支持 NTLMSSP)
//	服务端 -> SESSION_SETUP_ANDX (扩展安全). 挑战为 SPNEGO 包裹的 NTLMSSP
//	客户端 -> 解析出 8 字节 server challenge, 计算 NTLMv2 响应回发
//	服务端 -> 状态码: STATUS_SUCCESS(0) = 口令正确
//	                     STATUS_LOGON_FAILURE(0xC000006D) = 口令错
//	                     STATUS_MORE_PROCESSING(0xC0000016) = 需要继续(不支持)
//
// 为什么选 SMB1 而不是 SMB2/3: SMB1 的 NTLMSSP 交换报文结构简单且被
// Windows/Linux(Samba)/NAS 全兼容(降低 SMB2 后默认仍接受 SMB1 协商报文)。
// SMB2 的 SPNEGO/SESSION_SETUP 状态机复杂得多, 而"验证口令"这一步用 SMB1
// 就能完成。
//
// NTLMv2 计算: ResponseKeyNT = HMAC-MD5(NT-Hash, UTF16(user) + UTF16(domain)),
// 响应 = HMAC-MD5(ResponseKeyNT, challenge + blob)。NT-Hash = MD5(UTF16(pass))。
// 【关键】SMB 弱口令检测里 "NTLMv1" 需要 DES 与 LM 哈希, 且很多现代系统已禁用
// NTLMv1(禁用后只会回 STATUS_LOGON_FAILURE), 因此本实现直接用 NTLMv2 —— 它是
// 现代默认, 判错的概率最低。
type smbChecker struct{}

func (smbChecker) Name() string { return "smb" }

// NTLMSSP 消息类型与 SMB 状态码。
const (
	ntlmNegotiate = 1
	ntlmChallenge = 2
	ntlmAuth      = 3

	smbStatusSuccess          = 0x00000000
	smbStatusMoreProcessing   = 0xC0000016
	smbStatusLogonFailure     = 0xC000006D
	smbStatusAccountRestricted = 0xC000006E
	smbStatusAccountDisabled  = 0xC0000072
	smbStatusPasswordExpired  = 0xC0000071
	smbStatusBadPassword      = 0xC000006A
)

func (smbChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	if err := smbNegotiate(conn); err != nil {
		return false, err
	}
	neg, err := smbSessionSetup1(conn, user)
	if err != nil {
		return false, err
	}
	// 服务端可能直接回成功(匿名/免认证)或失败
	switch neg.status {
	case smbStatusMoreProcessing:
		// 正常流程: 拿到 challenge 继续
	case smbStatusSuccess:
		return true, nil
	case smbStatusLogonFailure, smbStatusBadPassword, smbStatusAccountRestricted,
		smbStatusAccountDisabled, smbStatusPasswordExpired:
		return false, nil
	default:
		return false, fmt.Errorf("smb 首次会话建立返回状态 0x%08X: %w", neg.status, ErrUnsupported)
	}
	if len(neg.challenge) < 8 {
		return false, fmt.Errorf("smb 未在响应中找到 NTLM 挑战")
	}
	return smbSessionSetup2(conn, user, pass, neg)
}

// smbNegInfo 会话建立第一阶段的结果。
type smbNegInfo struct {
	status    uint32
	challenge []byte // 8 字节 server challenge
	flags     uint32
	target    []byte // target name(用于 NTLMv2 计算)
	sessionID uint16
}

// smbNegotiate 发送 SMB1 Negotiate Protocol 并校验响应。
func smbNegotiate(conn net.Conn) error {
	// SMB1 Negotiate: dialect 列表里含 "NT LM 0.12"(0x0C) 与 "SMB 2.002"(0x0202)
	dialects := []byte{
		0x02, 'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
		0x02, 'S', 'M', 'B', ' ', '2', '.', '0', '0', '2', 0x00,
	}
	payload := make([]byte, 0, 64)
	payload = append(payload, 0xFF, 'S', 'M', 'B') // protocol
	payload = append(payload, 0x72)                // Negotiate Protocol
	payload = append(payload, make([]byte, 4)...)  // status (0)
	payload = append(payload, 0x00)                // flags
	payload = append(payload, 0x00, 0x00)          // flags2
	payload = append(payload, make([]byte, 12)...) // PID high/security features/signature
	payload = append(payload, make([]byte, 2)...)  // reserved
	payload = append(payload, make([]byte, 2)...)  // TID
	payload = append(payload, 0xFE, 0xFF)          // PID
	payload = append(payload, make([]byte, 2)...)  // UID
	payload = append(payload, make([]byte, 2)...)  // MID
	payload = append(payload, byte(len(dialects))) // WordCount
	payload = append(payload, dialects...)         // dialect list

	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf, uint32(len(payload))) // NetBIOS session header
	copy(buf[4:], payload)
	if err := writeAll(conn, buf); err != nil {
		return fmt.Errorf("smb 发送 Negotiate 失败: %w", err)
	}
	resp, err := smbReadResponse(conn)
	if err != nil {
		return err
	}
	if len(resp) < 32 {
		return fmt.Errorf("smb Negotiate 响应过短: %d", len(resp))
	}
	if binary.BigEndian.Uint32(resp[4:8]) != 0xFF534D42 { // 0xFF 'S' 'M' 'B'
		return fmt.Errorf("smb 非 SMB1 响应(可能是 SMB2 端口/SMB 被禁用): %w", ErrUnsupported)
	}
	// SMB2 回退: 服务端可能回 0xFE 'S' 'M' 'B' 表示只支持 SMB2
	if st := binary.LittleEndian.Uint32(resp[8:12]); st != smbStatusSuccess {
		return fmt.Errorf("smb Negotiate 被拒: 0x%08X: %w", st, ErrUnsupported)
	}
	return nil
}

// smbReadResponse 读一条 NetBIOS 会话报文(4 字节长度前缀)。
func smbReadResponse(conn net.Conn) ([]byte, error) {
	var hdr [4]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return nil, fmt.Errorf("smb 读取响应头失败: %w", err)
	}
	n := int(hdr[1])<<16 | int(hdr[2])<<8 | int(hdr[3])
	if n <= 0 || n > 1<<20 {
		return nil, fmt.Errorf("smb 响应长度非法: %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("smb 读取响应体失败: %w", err)
	}
	return body, nil
}

// smbSessionSetup1 发第一次 SessionSetup(含 NTLM Type1), 取回挑战。
func smbSessionSetup1(conn net.Conn, user string) (*smbNegInfo, error) {
	type1 := ntlmBuildType1()
	// SPNEGO: 直接用 NTLMSSP 裸消息也常被接受(扩展安全协商后)。
	if err := writeAll(conn, smbSessionSetupPacket(type1)); err != nil {
		return nil, fmt.Errorf("smb 发送 SessionSetup 失败: %w", err)
	}
	resp, err := smbReadResponse(conn)
	if err != nil {
		return nil, err
	}
	return smbParseSessionSetup(resp)
}

// smbParseSessionSetup 解析 SESSION_SETUP 响应, 抽出状态码与 NTLM 挑战。
func smbParseSessionSetup(resp []byte) (*smbNegInfo, error) {
	if len(resp) < 36 {
		return nil, fmt.Errorf("smb SessionSetup 响应过短: %d", len(resp))
	}
	info := &smbNegInfo{}
	info.status = binary.LittleEndian.Uint32(resp[8:12])
	info.flags = uint32(binary.LittleEndian.Uint16(resp[12:14]))
	wc := int(resp[32])
	// WordCount 8 字节 word + 2 字节 ByteCount, 之后是数据
	dataOff := 33 + wc*2
	if dataOff+2 > len(resp) {
		return nil, fmt.Errorf("smb SessionSetup 字段越界")
	}
	n := int(binary.LittleEndian.Uint16(resp[dataOff : dataOff+2]))
	data := resp[dataOff+2:]
	if n > 0 && n <= len(data) {
		data = data[:n]
	}
	// securityBlob 里搜 NTLMSSP 挑战(可能有 SPNEGO 外层包装)
	if ch, ok := ntlmFindChallenge(data); ok {
		info.challenge = ch.challenge
		info.target = ch.target
	}
	return info, nil
}

// ntlmChallengeInfo 从 NTLMSSP Type2 里抽出的关键字段。
type ntlmChallengeInfo struct {
	challenge []byte
	target    []byte
}

// ntlmFindChallenge 在 blob 中定位 NTLMSSP Type2 消息并解析挑战。
func ntlmFindChallenge(blob []byte) (*ntlmChallengeInfo, bool) {
	sig := []byte("NTLMSSP\x00")
	idx := indexBytes(blob, sig)
	if idx < 0 {
		return nil, false
	}
	m := blob[idx:]
	if len(m) < 48 {
		return nil, false
	}
	if binary.LittleEndian.Uint32(m[8:12]) != ntlmChallenge {
		return nil, false
	}
	ch := make([]byte, 8)
	copy(ch, m[24:32])
	info := &ntlmChallengeInfo{challenge: ch}
	// TargetName 的 Len(2)/MaxLen(2)/Offset(4) 在 12 字节处
	if len(m) >= 20 {
		tl := int(binary.LittleEndian.Uint16(m[12:14]))
		to := int(binary.LittleEndian.Uint32(m[16:20]))
		if tl > 0 && to+tl <= len(m) {
			info.target = m[to : to+tl]
		}
	}
	return info, true
}

// smbSessionSetup2 发第二次 SessionSetup(含 NTLMv2 响应)并判定结果。
func smbSessionSetup2(conn net.Conn, user, pass string, neg *smbNegInfo) (bool, error) {
	type3, err := ntlmBuildType3(user, pass, neg.challenge, neg.target)
	if err != nil {
		return false, err
	}
	if err := writeAll(conn, smbSessionSetupPacket(type3)); err != nil {
		return false, fmt.Errorf("smb 发送认证包失败: %w", err)
	}
	resp, err := smbReadResponse(conn)
	if err != nil {
		return false, err
	}
	if len(resp) < 12 {
		return false, fmt.Errorf("smb 认证响应过短: %d", len(resp))
	}
	switch st := binary.LittleEndian.Uint32(resp[8:12]); st {
	case smbStatusSuccess:
		return true, nil
	case smbStatusLogonFailure, smbStatusBadPassword, smbStatusAccountRestricted,
		smbStatusAccountDisabled, smbStatusPasswordExpired:
		return false, nil
	case smbStatusMoreProcessing:
		return false, fmt.Errorf("smb 服务端仍要求继续认证(NTLMv2 未被接受): %w", ErrUnsupported)
	default:
		return false, fmt.Errorf("smb 认证状态 0x%08X: %w", st, ErrUnsupported)
	}
}

// smbSessionSetupPacket 构造 SESSION_SETUP_ANDX 报文。
func smbSessionSetupPacket(secBlob []byte) []byte {
	payload := make([]byte, 0, 128+len(secBlob))
	payload = append(payload, 0xFF, 'S', 'M', 'B')
	payload = append(payload, 0x73)               // SESSION_SETUP_ANDX
	payload = append(payload, make([]byte, 4)...) // status
	payload = append(payload, 0x00)               // flags
	payload = append(payload, 0x00, 0x00)         // flags2
	payload = append(payload, make([]byte, 12)...)
	payload = append(payload, make([]byte, 2)...) // reserved
	payload = append(payload, make([]byte, 2)...) // TID
	payload = append(payload, 0xFE, 0xFF)         // PID
	payload = append(payload, make([]byte, 2)...) // UID
	payload = append(payload, make([]byte, 2)...) // MID

	// WordCount = 12: AndXCommand..SecurityBlobLength
	payload = append(payload, 0x0C)
	payload = append(payload, 0xFF)               // AndXCommand = 0xFF (none)
	payload = append(payload, 0x00)               // AndXReserved
	payload = append(payload, make([]byte, 2)...) // AndXOffset
	payload = append(payload, make([]byte, 2)...) // MaxBufferSize
	payload = append(payload, make([]byte, 2)...) // MaxMpxCount
	payload = append(payload, 0x01, 0x00)         // VCNumber
	payload = append(payload, make([]byte, 4)...) // SessionKey
	payload = append(payload, 0x00, 0x00)         // SecurityBlobLength(占位)
	payload = append(payload, make([]byte, 4)...) // Reserved
	payload = append(payload, make([]byte, 4)...) // Capabilities
	// ByteCount + 安全 blob
	bc := make([]byte, 2)
	binary.LittleEndian.PutUint16(bc, uint16(len(secBlob)))
	payload = append(payload, bc...)
	payload = append(payload, secBlob...)
	return payload
}

// ntlmBuildType1 构造 NTLMSSP Type1(Negotiate)消息。
func ntlmBuildType1() []byte {
	flags := uint32(0x00008201 | // UNICODE | NEGOTIATE_NTLM
		0x00000004 | // REQUEST_TARGET
		0x00080000 | // NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
		0x00002000 | // NEGOTIATE_SIGN
		0x00001000 | // NEGOTIATE_SEAL
		0x00000400 | // NEGOTIATE_NTLM2_KEY
		0x00008000)  // NEGOTIATE_ALWAYS_SIGN
	out := make([]byte, 32)
	copy(out, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(out[8:12], ntlmNegotiate)
	binary.LittleEndian.PutUint32(out[12:16], flags)
	// Domain/Workstation 字段留空(Len=0, MaxLen=0, Offset=32)
	binary.LittleEndian.PutUint32(out[16:20], 0)
	binary.LittleEndian.PutUint32(out[20:24], 0)
	binary.LittleEndian.PutUint32(out[24:28], 0)
	binary.LittleEndian.PutUint32(out[28:32], 0)
	if len(out) < 32 {
		out = append(out, 0)
	}
	return out[:32]
}

// ntlmBuildType3 构造 NTLMv2 认证消息。
func ntlmBuildType3(user, pass string, challenge, target []byte) ([]byte, error) {
	if len(challenge) < 8 {
		return nil, fmt.Errorf("smb NTLM 挑战长度非法: %d", len(challenge))
	}
	domain := "" // 空域: 本地账号/域账号都由服务端兜底(LM 兼容域由服务端补)
	ntHash := ntlmNTHash(pass)
	respKeyNT := hmacMD5(ntHash, utf16LE(unicodeUpper(user)+domain))

	// 客户端挑战(blob 的一部分)
	blob := ntlmV2Blob(challenge[:8])
	ntProof := hmacMD5(respKeyNT, append(append([]byte{}, challenge[:8]...), blob...))
	ntResp := append(append([]byte{}, ntProof...), blob...)

	// 空 LM 响应(现代服务端接受)
	lmResp := make([]byte, 24)

	domainB := utf16LE(domain)
	userB := utf16LE(user)
	workstation := utf16LE("YUGSIGHT")

	// 布局: 固定 64 字节头 + domain + user + workstation + lm(24) + nt + sessionKey(16)
	header := 64
	domainOff := header
	userOff := domainOff + len(domainB)
	wsOff := userOff + len(userB)
	lmOff := wsOff + len(workstation)
	ntOff := lmOff + len(lmResp)
	skOff := ntOff + len(ntResp)

	out := make([]byte, header)
	copy(out, []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(out[8:12], ntlmAuth)

	// LM 响应: Len/MaxLen/Offset(8..20)
	putSecBuf(out[12:20], len(lmResp), lmOff)
	// NT 响应(20..32)
	putSecBuf(out[20:28], len(ntResp), ntOff)
	// Domain(28..36)
	putSecBuf(out[28:36], len(domainB), domainOff)
	// User(36..44)
	putSecBuf(out[36:44], len(userB), userOff)
	// Workstation(44..52)
	putSecBuf(out[44:52], len(workstation), wsOff)
	// SessionKey(52..60) 空
	putSecBuf(out[52:60], 0, skOff)
	// Flags(60..64)
	flags := uint32(0x00008201 | 0x00000200) // UNICODE | NEGOTIATE_NTLM | NEGOTIATE_NTLM2_KEY
	binary.LittleEndian.PutUint32(out[60:64], flags)

	out = append(out, domainB...)
	out = append(out, userB...)
	out = append(out, workstation...)
	out = append(out, lmResp...)
	out = append(out, ntResp...)
	out = append(out, make([]byte, 16)...) // SessionKey
	return out, nil
}

// putSecBuf 写入 NTLM 的 Len(2)/MaxLen(2)/Offset(4) 结构。
func putSecBuf(dst []byte, n, off int) {
	if len(dst) < 8 {
		return
	}
	binary.LittleEndian.PutUint16(dst[0:2], uint16(n))
	binary.LittleEndian.PutUint16(dst[2:4], uint16(n))
	binary.LittleEndian.PutUint32(dst[4:8], uint32(off))
}

// ntlmV2Blob 构造 NTLMv2 的 client challenge 结构(temp 字段)。
//
// 结构: 0x01010000 | Reserved(4) | Timestamp(8) | ClientChallenge(8) | 0 | TargetInfo
// TargetInfo 留最小合法体(以 4 字节 0 结尾), 服务端仅用它做通道绑定, 不影响口令判定。
func ntlmV2Blob(challenge []byte) []byte {
	out := make([]byte, 0, 32)
	out = append(out, 0x01, 0x01, 0x00, 0x00) // Responserversion/HiResponserversion/Z(2)
	out = append(out, make([]byte, 4)...)     // Reserved
	ts := make([]byte, 8)
	_, _ = rand.Read(ts)
	out = append(out, ts...)
	cc := make([]byte, 8)
	_, _ = rand.Read(cc)
	out = append(out, cc...)
	out = append(out, make([]byte, 4)...) // Z(4)
	out = append(out, make([]byte, 4)...) // TargetInfo 终止(以 0 起始的 AV 对)
	return out
}

// ntlmNTHash 计算 NT-Hash = MD4(UTF16LE(pass))。
//
// 【注意是 MD4 不是 MD5】Windows NT 口令哈希用的是早已被破解淘汰的 MD4
// (RFC 1320), 这是公开已知值 NT-Hash("password")=8846F7EA... 的口径。
// 标准库从未收录 MD4, 故手写实现并用 RFC/已知向量在测试里锁死。
func ntlmNTHash(pass string) []byte {
	h := md4Sum(utf16LE(pass))
	return h[:]
}

// md4Sum 纯标准库 MD4(RFC 1320)。结构比 MD5 少一轮(48 步)且无第五个常量,
// 轮内 X 下标顺序是 NTLM 兼容实现最常见的出错点, 已用官方向量验证。
func md4Sum(data []byte) [16]byte {
	// 填充规则与 MD5 相同: 0x80 + 补零到 56 mod 64 + 64 位小端比特长度
	msg := make([]byte, 0, len(data)+72)
	msg = append(msg, data...)
	msg = append(msg, 0x80)
	for len(msg)%64 != 56 {
		msg = append(msg, 0)
	}
	var lenBytes [8]byte
	binary.LittleEndian.PutUint64(lenBytes[:], uint64(len(data))*8)
	msg = append(msg, lenBytes[:]...)

	a0, b0, c0, d0 := uint32(0x67452301), uint32(0xefcdab89), uint32(0x98badcfe), uint32(0x10325476)
	for off := 0; off < len(msg); off += 64 {
		var x [16]uint32
		for i := 0; i < 16; i++ {
			x[i] = binary.LittleEndian.Uint32(msg[off+i*4 : off+i*4+4])
		}
		a, b, c, d := a0, b0, c0, d0
		// 第 1 轮: F=(b&c)|(^b&d), 无常量但 **X[k] 要加**, k 顺序取 0..15, 移位 3/7/11/19
		for i := 0; i < 16; i++ {
			f := (b & c) | (^b & d)
			a, b, c, d = d, rotl32(a+f+x[i], [4]int{3, 7, 11, 19}[i%4]), b, c
		}
		// 第 2 轮: G=(b&c)|(b&d)|(c&d), 常量 0x5A827999, k 顺序 0,4,8..15, 移位 3/5/9/13
		k2 := [16]int{0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15}
		for i := 0; i < 16; i++ {
			g := (b & c) | (b & d) | (c & d)
			a, b, c, d = d, rotl32(a+g+0x5A827999+x[k2[i]], [4]int{3, 5, 9, 13}[i%4]), b, c
		}
		// 第 3 轮: H=b^c^d, 常量 0x6ED9EBA1, k 顺序 0,8,4,12.., 移位 3/9/11/15
		k3 := [16]int{0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15}
		for i := 0; i < 16; i++ {
			h := b ^ c ^ d
			a, b, c, d = d, rotl32(a+h+0x6ED9EBA1+x[k3[i]], [4]int{3, 9, 11, 15}[i%4]), b, c
		}
		a0, b0, c0, d0 = a0+a, b0+b, c0+c, d0+d
	}
	var out [16]byte
	binary.LittleEndian.PutUint32(out[0:4], a0)
	binary.LittleEndian.PutUint32(out[4:8], b0)
	binary.LittleEndian.PutUint32(out[8:12], c0)
	binary.LittleEndian.PutUint32(out[12:16], d0)
	return out
}

func rotl32(x uint32, n int) uint32 { return x<<uint(n) | x>>(32-uint(n)) }

// hmacMD5 计算 HMAC-MD5(key, msg)。
func hmacMD5(key, msg []byte) []byte {
	const blockSize = 64
	if len(key) > blockSize {
		s := md5.Sum(key)
		key = s[:]
	}
	k := make([]byte, blockSize)
	copy(k, key)
	ipad := make([]byte, blockSize)
	opad := make([]byte, blockSize)
	for i := 0; i < blockSize; i++ {
		ipad[i] = k[i] ^ 0x36
		opad[i] = k[i] ^ 0x5C
	}
	inner := md5.Sum(append(ipad, msg...))
	outer := md5.Sum(append(opad, inner[:]...))
	return outer[:]
}

// utf16LE 把字符串编码成 UTF-16LE 字节。
func utf16LE(s string) []byte {
	u := utf16.Encode([]rune(s))
	out := make([]byte, 0, len(u)*2)
	for _, r := range u {
		out = append(out, byte(r), byte(r>>8))
	}
	return out
}

// unicodeUpper ASCII 大写(User 字段在 NTLMv2 里按大写参与 HMAC)。
func unicodeUpper(s string) string { return strings.ToUpper(s) }

// indexBytes 在 b 中查找子串 sub 的起始下标(等价 bytes.Index, 避免额外依赖)。
func indexBytes(b, sub []byte) int {
	if len(sub) == 0 {
		return 0
	}
	for i := 0; i+len(sub) <= len(b); i++ {
		match := true
		for j := range sub {
			if b[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// rc4XOR 供其它协议复用(保留以免 rc4 导入被误判未使用)。
func rc4XOR(key, data []byte) []byte {
	c, err := rc4.NewCipher(key) //nolint:staticcheck // 协议规定
	if err != nil {
		return data
	}
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}
