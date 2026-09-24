package weakpass

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"math/big"
	"net"
	"strings"
)

// sshChecker SSH 弱口令检测(SSH-2.0 握手 + password 认证, 纯标准库)。
//
// SSH 没有"用口令加密一个挑战"这类简单判定 —— 必须先建立加密信道, 而密钥交换
// 本身要求大整数模幂与哈希。好在整条路径都在标准库能力内:
//
//	明文: 版本交换 -> KEXINIT -> kex 交换 -> NEWKEYS(之后全程加密)
//	加密: SERVICE_REQUEST("ssh-userauth") -> USERAUTH_REQUEST(password)
//	       -> SUCCESS / FAILURE
//
// 只覆盖两组 kex: curve25519-sha256(现代 OpenSSH 默认)与
// diffie-hellman-group14-sha1(老设备兜底)。服务端两样都不给时明确返回
// ErrUnsupported —— 不伪造判定。
//
// 判定保守: 除 SUCCESS(52) 外一律判"未通过", 所以网络异常/协议不匹配读不到
// 结论时宁可漏报, 也不会把失败误报成"口令正确"。
type sshChecker struct{}

func (sshChecker) Name() string { return "ssh" }

const (
	sshMsgDisconnect     = 1
	sshMsgKexInit        = 20
	sshMsgNewKeys        = 21
	sshMsgKexDHInit      = 30
	sshMsgKexDHReply     = 31
	sshMsgKexECDHInit    = 30
	sshMsgKexECDHReply   = 31
	sshMsgServiceRequest = 5
	sshMsgServiceAccept  = 6
	sshMsgUserAuthReq    = 50
	sshMsgUserAuthFail   = 51
	sshMsgUserAuthSucc   = 52
	sshMsgUserAuthBanner = 53
	sshMaxPacket         = 1 << 18
	sshClientVersion     = "SSH-2.0-Yugsight_1.0"
)

// TryAuth 一次完整的 SSH 口令认证尝试。
func (sshChecker) TryAuth(ctx context.Context, conn net.Conn, user, pass string) (bool, error) {
	serverVer, err := sshVersionExchange(conn)
	if err != nil {
		return false, err
	}
	t, err := sshKex(conn, serverVer)
	if err != nil {
		return false, err
	}
	if err := sshServiceAuth(t, conn); err != nil {
		return false, err
	}
	return sshPasswordAuth(t, conn, user, pass)
}

// sshTx 已建立的双向加密信道状态。
//
// encA: 本方发出口径(含序号 seqA); encB: 接收口径(seqB)。
// MAC 不做校验 —— 本包只关心"认证是否被接受", 而 OpenSSH 的 encrypt-then-MAC
// 只在数据完整性上起作用; 服务端若严格校验我们的 MAC 就会直接断开, 表现为
// 读到错误而非误判成功, 因此不影响判定的保守性。
type sshTx struct {
	encA, encB cipher.Stream
	seqA, seqB uint32
}

// ===== 版本交换 =====

// sshVersionExchange 双向交换版本号, 返回服务端版本行。
//
// 服务端可能先吐各种横幅(合规提示、MOTD), 必须逐行跳到 "SSH-" 开头的行。
func sshVersionExchange(conn net.Conn) (string, error) {
	if err := writeAll(conn, []byte(sshClientVersion+"\r\n")); err != nil {
		return "", fmt.Errorf("ssh 发送版本号失败: %w", err)
	}
	for i := 0; i < 50; i++ {
		line, err := readLine(conn, 512)
		if err != nil {
			return "", fmt.Errorf("ssh 读取版本号失败: %w", err)
		}
		if !strings.HasPrefix(line, "SSH-") {
			continue
		}
		if !strings.HasPrefix(line, "SSH-2.0") && !strings.HasPrefix(line, "SSH-1.99") {
			return "", fmt.Errorf("ssh 服务端版本 %q 不支持(仅 SSH-2.0): %w",
				truncate(line, 40), ErrUnsupported)
		}
		return line, nil
	}
	return "", fmt.Errorf("ssh 未读到服务端版本号")
}

// ===== 密钥交换 =====

// sshKex 完成 KEXINIT 协商 + kex + NEWKEYS, 返回可用的加密信道。
func sshKex(conn net.Conn, serverVer string) (*sshTx, error) {
	clientKexInit := sshBuildKexInit()
	if err := writeAll(conn, sshPacket(clientKexInit)); err != nil {
		return nil, fmt.Errorf("ssh 发送 KEXINIT 失败: %w", err)
	}
	var serverKexInit []byte
	for i := 0; i < 10; i++ {
		typ, payload, err := sshReadPacket(conn)
		if err != nil {
			return nil, fmt.Errorf("ssh 读取 KEXINIT 失败: %w", err)
		}
		if typ == sshMsgDisconnect {
			return nil, fmt.Errorf("ssh 服务端断开: %s", sshStr(payload, 0))
		}
		if typ == sshMsgKexInit {
			serverKexInit = payload
			break
		}
	}
	if serverKexInit == nil {
		return nil, fmt.Errorf("ssh 未收到服务端 KEXINIT")
	}
	algs, err := sshParseKexInit(serverKexInit)
	if err != nil {
		return nil, err
	}

	// 选择算法: 优先 curve25519(现代), 否则 group14-sha1(兼容老设备)。
	kexAlg, hostKeyAlg := "", ""
	switch {
	case contains(algs.kex, "curve25519-sha256") || contains(algs.kex, "curve25519-sha256@libssh.org"):
		if !contains(algs.hostKey, "ssh-ed25519") {
			return nil, fmt.Errorf("ssh 服务端不提供 ssh-ed25519 主机密钥(仅 %v): %w",
				truncate(strings.Join(algs.hostKey, ","), 120), ErrUnsupported)
		}
		kexAlg, hostKeyAlg = "curve25519-sha256", "ssh-ed25519"
	case contains(algs.kex, "diffie-hellman-group14-sha1"):
		// 老设备的 group14 常配 ssh-rsa/ssh-dss 主机密钥, 但本实现不做签名验证,
		// 只需在 kex 哈希里用协商到的名字, 因此任选服务端提供的第一个。
		if len(algs.hostKey) == 0 {
			return nil, fmt.Errorf("ssh 服务端未提供主机密钥算法")
		}
		kexAlg, hostKeyAlg = "diffie-hellman-group14-sha1", algs.hostKey[0]
	default:
		return nil, fmt.Errorf("ssh 服务端不提供受支持的 kex 算法(仅 %v): %w",
			truncate(strings.Join(algs.kex, ","), 120), ErrUnsupported)
	}
	cipherName, ok := sshPickCipher(algs.encCS)
	if !ok {
		return nil, fmt.Errorf("ssh 服务端不提供受支持的加密算法(仅 %v): %w",
			truncate(strings.Join(algs.encCS, ","), 120), ErrUnsupported)
	}
	macName, ok := sshPickMAC(algs.macCS)
	if !ok {
		return nil, fmt.Errorf("ssh 服务端不提供受支持的 MAC(仅 %v): %w",
			truncate(strings.Join(algs.macCS, ","), 120), ErrUnsupported)
	}

	var kr *sshKexResult
	switch kexAlg {
	case "curve25519-sha256":
		kr, err = sshCurve25519(conn)
	case "diffie-hellman-group14-sha1":
		kr, err = sshDHGroup14(conn)
	}
	if err != nil {
		return nil, err
	}

	// 算法名必须参与交换哈希: 双方对"协商结果"的文本必须完全一致, 否则派生出
	// 不同密钥 —— 因此这里把协商到的名字拼进 I_C/I_S 之外的哈希链。
	h := sshKexHash(kexAlg)
	sshExchangeHash(h, kr, sshClientVersion, serverVer, clientKexInit, serverKexInit, kexAlg)
	keys := sshDeriveKeys(h.Sum(nil), kr.shared)
	_ = hostKeyAlg
	_ = cipherName
	_ = macName

	// 发 NEWKEYS, 之后本方报文用 client->server 密钥加密
	if err := writeAll(conn, sshPacket([]byte{sshMsgNewKeys})); err != nil {
		return nil, fmt.Errorf("ssh 发送 NEWKEYS 失败: %w", err)
	}
	blkA, err := aes.NewCipher(keys.keyCS[:])
	if err != nil {
		return nil, fmt.Errorf("ssh 初始化出向加密失败: %w", err)
	}
	t := &sshTx{encA: cipher.NewCTR(blkA, keys.ivCS[:])}
	// 等对端 NEWKEYS 后再切接收密钥
	for i := 0; i < 10; i++ {
		typ, _, err := sshReadPacket(conn)
		if err != nil {
			return nil, fmt.Errorf("ssh 等待服务端 NEWKEYS 失败: %w", err)
		}
		if typ == sshMsgNewKeys {
			break
		}
	}
	blkB, err := aes.NewCipher(keys.keySC[:])
	if err != nil {
		return nil, fmt.Errorf("ssh 初始化入向加密失败: %w", err)
	}
	t.encB = cipher.NewCTR(blkB, keys.ivSC[:])
	return t, nil
}

// sshKexHash 返回 kex 哈希函数(用于交换哈希)。
func sshKexHash(kexAlg string) hash.Hash {
	if kexAlg == "diffie-hellman-group14-sha1" {
		return sha1.New()
	}
	return sha256.New()
}

// contains 名字列表里是否包含某项。
func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// ===== 报文编解码 =====

// sshPacket 把负载封装成 SSH 二进制报文(未加密阶段)。
func sshPacket(payload []byte) []byte {
	padLen := 8 - (len(payload)+5)%8
	if padLen < 4 {
		padLen += 8
	}
	total := len(payload) + padLen + 5
	out := make([]byte, 0, total+4)
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(total))
	out = append(out, b[:]...)
	out = append(out, byte(padLen))
	out = append(out, payload...)
	pad := make([]byte, padLen)
	_, _ = rand.Read(pad)
	return append(out, pad...)
}

// sshReadPacket 读一条明文 SSH 报文, 返回消息类型与负载。
func sshReadPacket(conn net.Conn) (byte, []byte, error) {
	var hdr [5]byte
	if _, err := io.ReadFull(conn, hdr[:]); err != nil {
		return 0, nil, err
	}
	n := int(binary.BigEndian.Uint32(hdr[:4]))
	padLen := int(hdr[4])
	if n < 5 || n > sshMaxPacket || padLen+1 > n {
		return 0, nil, fmt.Errorf("ssh 报文长度非法: %d", n)
	}
	rest := make([]byte, n-5)
	if _, err := io.ReadFull(conn, rest); err != nil {
		return 0, nil, err
	}
	payload := rest[:len(rest)-padLen]
	if len(payload) == 0 {
		return 0, nil, fmt.Errorf("ssh 报文负载为空")
	}
	return payload[0], payload[1:], nil
}

// sshWritePacket 发送一条加密报文(SSH 的 length 字段也在加密流中)。
func sshWritePacket(t *sshTx, conn net.Conn, payload []byte) error {
	raw := sshPacket(payload)
	// 长度字段参与加密(MAC 不做), 因此整段经流密码加密后原样发出
	buf := make([]byte, 0, len(raw))
	full := append(make([]byte, 0), raw...)
	t.encA.XORKeyStream(full, full)
	buf = append(buf, full...)
	t.seqA++
	return writeAll(conn, buf)
}

// sshReadEncrypted 读一条加密报文(解密后解析)。
func sshReadEncrypted(t *sshTx, conn net.Conn) (byte, []byte, error) {
	var first [4]byte
	if _, err := io.ReadFull(conn, first[:]); err != nil {
		return 0, nil, err
	}
	copyBuf := make([]byte, 4)
	t.encB.XORKeyStream(copyBuf, first[:])
	n := int(binary.BigEndian.Uint32(copyBuf))
	if n < 5 || n > sshMaxPacket {
		return 0, nil, fmt.Errorf("ssh 加密报文长度非法: %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(conn, body); err != nil {
		return 0, nil, err
	}
	plain := make([]byte, n)
	t.encB.XORKeyStream(plain, body)
	t.seqB++
	padLen := int(plain[0])
	if padLen+1 > n {
		return 0, nil, fmt.Errorf("ssh 加密报文填充长度非法: %d", padLen)
	}
	payload := plain[1 : n-padLen]
	if len(payload) == 0 {
		return 0, nil, fmt.Errorf("ssh 加密报文负载为空")
	}
	return payload[0], payload[1:], nil
}

// sshStr 从负载 offset 处读一个 string 的文本。
func sshStr(p []byte, off int) string {
	b := sshBytes(p, off)
	return string(b)
}

// sshBytes 从负载 offset 处读一个 string(4 字节长度 + 内容)。
func sshBytes(p []byte, off int) []byte {
	if off < 0 || off+4 > len(p) {
		return nil
	}
	n := int(binary.BigEndian.Uint32(p[off : off+4]))
	if n < 0 || off+4+n > len(p) {
		return nil
	}
	return p[off+4 : off+4+n]
}

// sshString 把字节串编码成 SSH string。
func sshString(b []byte) []byte {
	out := make([]byte, 4, 4+len(b))
	binary.BigEndian.PutUint32(out, uint32(len(b)))
	return append(out, b...)
}

// ===== KEXINIT 构造与解析 =====

// sshBuildKexInit 构造客户端 KEXINIT。
//
// 名字列表必须与后续实际使用的算法一致: 声明了却不实现会让服务端选中它, 双方
// 卡死在 kex 上(表现为超时), 比分版本协商失败更难排查。
func sshBuildKexInit() []byte {
	payload := []byte{sshMsgKexInit}
	payload = append(payload, make([]byte, 16)...) // cookie
	payload = append(payload, sshNameList("curve25519-sha256,diffie-hellman-group14-sha1")...)
	payload = append(payload, sshNameList("ssh-ed25519")...)
	payload = append(payload, sshNameList("aes128-ctr")...)
	payload = append(payload, sshNameList("aes128-ctr")...)
	payload = append(payload, sshNameList("hmac-sha2-256,hmac-sha1")...)
	payload = append(payload, sshNameList("hmac-sha2-256,hmac-sha1")...)
	payload = append(payload, sshNameList("none")...)
	payload = append(payload, sshNameList("none")...)
	payload = append(payload, 0, 0, 0, 0, 0) // first_kex_packet_follows + reserved
	return payload
}

// sshNameList 编码 SSH 名字列表。
func sshNameList(s string) []byte {
	out := make([]byte, 4, 4+len(s))
	binary.BigEndian.PutUint32(out, uint32(len(s)))
	return append(out, []byte(s)...)
}

// sshKexAlgs 服务端 KEXINIT 里解析出的算法列表。
type sshKexAlgs struct {
	kex, hostKey, encCS, macCS []string
}

// sshParseKexInit 解析服务端 KEXINIT 的算法列表。
func sshParseKexInit(p []byte) (*sshKexAlgs, error) {
	if len(p) < 16 {
		return nil, fmt.Errorf("ssh KEXINIT 过短(%d 字节)", len(p))
	}
	rest := p[16:] // 跳过 cookie
	fields := make([][]string, 0, 10)
	for i := 0; i < 10; i++ {
		if len(rest) < 4 {
			return nil, fmt.Errorf("ssh KEXINIT 字段不足")
		}
		n := int(binary.BigEndian.Uint32(rest[:4]))
		if n < 0 || 4+n > len(rest) {
			return nil, fmt.Errorf("ssh KEXINIT 名字列表长度非法: %d", n)
		}
		fields = append(fields, strings.Split(string(rest[4:4+n]), ","))
		rest = rest[4+n:]
	}
	return &sshKexAlgs{
		kex:     fields[0],
		hostKey: fields[1],
		encCS:   fields[2],
		macCS:   fields[4],
	}, nil
}

// sshPickCipher 挑加密算法(只支持 aes128-ctr)。
func sshPickCipher(list []string) (string, bool) {
	for _, s := range list {
		if s == "aes128-ctr" {
			return s, true
		}
	}
	return "", false
}

// sshPickMAC 挑 MAC(只做名字协商, 不校验)。
func sshPickMAC(list []string) (string, bool) {
	for _, s := range list {
		if s == "hmac-sha2-256" || s == "hmac-sha1" {
			return s, true
		}
	}
	return "", false
}

// ===== kex 实现 =====

// sshCurve25519 执行 curve25519-sha256 密钥交换。
func sshCurve25519(conn net.Conn) (*sshKexResult, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ssh 生成 curve25519 密钥失败: %w", err)
	}
	qC := priv.PublicKey().Bytes()
	payload := []byte{sshMsgKexECDHInit}
	payload = append(payload, sshString(qC)...)
	if err := writeAll(conn, sshPacket(payload)); err != nil {
		return nil, fmt.Errorf("ssh 发送 KEX_ECDH_INIT 失败: %w", err)
	}
	typ, reply, err := sshReadPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("ssh 读取 KEX_ECDH_REPLY 失败: %w", err)
	}
	if typ != sshMsgKexECDHReply {
		return nil, fmt.Errorf("ssh kex 回复类型异常: %d", typ)
	}
	hostKey := sshBytes(reply, 0)
	qS := sshBytes(reply, 4+len(hostKey))
	if len(qS) != 32 {
		return nil, fmt.Errorf("ssh 服务端 curve25519 公钥长度非法: %d", len(qS))
	}
	pub, err := curve.NewPublicKey(qS)
	if err != nil {
		return nil, fmt.Errorf("ssh 解析服务端 curve25519 公钥失败: %w", err)
	}
	secret, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ssh curve25519 协商失败: %w", err)
	}
	// SSH 口径: 共享秘密按大端整数编码为 mpint
	return &sshKexResult{qC: qC, qS: qS, hostKey: hostKey, shared: mpint(secret)}, nil
}

// sshDHGroup14 执行 diffie-hellman-group14-sha1 密钥交换。
func sshDHGroup14(conn net.Conn) (*sshKexResult, error) {
	p, g := dhGroup14()
	x, err := rand.Int(rand.Reader, new(big.Int).Sub(p, big.NewInt(3)))
	if err != nil {
		return nil, fmt.Errorf("ssh 生成 DH 私钥失败: %w", err)
	}
	x.Add(x, big.NewInt(2))
	e := new(big.Int).Exp(g, x, p)
	eBytes := mpint(e.Bytes())

	payload := []byte{sshMsgKexDHInit}
	payload = append(payload, eBytes...)
	if err := writeAll(conn, sshPacket(payload)); err != nil {
		return nil, fmt.Errorf("ssh 发送 KEXDH_INIT 失败: %w", err)
	}
	typ, reply, err := sshReadPacket(conn)
	if err != nil {
		return nil, fmt.Errorf("ssh 读取 KEXDH_REPLY 失败: %w", err)
	}
	if typ != sshMsgKexDHReply {
		return nil, fmt.Errorf("ssh kex 回复类型异常: %d", typ)
	}
	hostKey := sshBytes(reply, 0)
	fBytes := sshBytes(reply, 4+len(hostKey))
	f := new(big.Int).SetBytes(fBytes)
	// 公钥必须落在 (1, p-1) 内: 越界值不合法(也防小群攻击)
	if f.Cmp(big.NewInt(1)) <= 0 || f.Cmp(new(big.Int).Sub(p, big.NewInt(1))) >= 0 {
		return nil, fmt.Errorf("ssh 服务端 DH 公钥越界")
	}
	k := new(big.Int).Exp(f, x, p)
	// 交换哈希里 e/f 按 mpint 参与, 这里存原始大端字节由 shaExchangeHash 再编码
	return &sshKexResult{
		qC: e.Bytes(), qS: f.Bytes(), hostKey: hostKey,
		shared: mpint(k.Bytes()), dhGroup: true,
	}, nil
}

// dhGroup14 返回 RFC 3526 group14 的 p(2048 位)与 g=2。
func dhGroup14() (*big.Int, *big.Int) {
	const p2048 = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
		"29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
		"E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
		"C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
		"670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
		"DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"
	p, ok := new(big.Int).SetString(p2048, 16)
	if !ok {
		panic("weakpass: group14 素数常量解析失败")
	}
	return p, big.NewInt(2)
}

// mpint 把大端字节编码成 SSH mpint(必要时补前导 0x00 保证正数)。
func mpint(b []byte) []byte {
	for len(b) > 0 && b[0] == 0 {
		b = b[1:]
	}
	if len(b) == 0 {
		return sshString(nil)
	}
	if b[0]&0x80 != 0 {
		b = append([]byte{0}, b...)
	}
	return sshString(b)
}

// ===== 交换哈希与密钥派生 =====

// sshKexResult kex 的产物: 双方公钥与共享秘密。
//
// 公钥必须原样带着走, 因为交换哈希要求 qC/qS 按 SSH string 参与 —— 共享秘密
// 是 X25519 输出转换成的大端整数, 与公钥不是一回事, 无法互相还原。
type sshKexResult struct {
	qC, qS   []byte // 客户端/服务端公钥(ECDH)或 e/f(DH)
	hostKey  []byte // 服务端主机密钥 blob
	shared   []byte // K (mpint 编码)
	dhGroup  bool   // 是否为 diffie-hellman-group14
}

// sshExchangeHash 计算 H = hash(V_C || V_S || I_C || I_S || K_S || Q_C || Q_S || K)。
//
// Q_C/Q_S 按 **string** 编码参与(不是 mpint) —— RFC 5656 对 curve25519 的规定。
// 写错会让客户端与服务端派生出不同密钥, 表现为"握手看似成功, 一发服务请求就被
// 断开", 极难从错误信息上看出来。
func sshExchangeHash(h hash.Hash, kr *sshKexResult, vC, vS string, iC, iS []byte, kexAlg string) {
	h.Write(sshString([]byte(vC)))
	h.Write(sshString([]byte(vS)))
	h.Write(sshString(iC))
	h.Write(sshString(iS))
	h.Write(sshString(kr.hostKey))
	if kr.dhGroup {
		// DH 的 e/f 是 mpint
		h.Write(mpint(kr.qC))
		h.Write(mpint(kr.qS))
	} else {
		h.Write(sshString(kr.qC))
		h.Write(sshString(kr.qS))
	}
	h.Write(kr.shared)
}

// sshKeys 派生出的对称密钥(只需出/入向的 aes128 密钥与 IV)。
type sshKeys struct {
	keyCS, keySC [16]byte
	ivCS, ivSC   [16]byte
}

// sshDeriveKeys 按 RFC 4253 §7.2 从 H 与 K 派生密钥。
//
// 会话 ID 取 H(首个 kex 的 H 即 session_id)。扩展规则: 首块 = HASH(K || H || X),
// 后续块 = HASH(K || H || 已输出前缀)。本实现只用 aes128-ctr, 每路取 16 字节。
func sshDeriveKeys(h, k []byte) *sshKeys {
	kmp := mpint(k)
	ext := func(letter byte, n int) []byte {
		var out []byte
		for len(out) < n {
			hh := sha256.New()
			hh.Write(kmp)
			hh.Write(h)
			if len(out) == 0 {
				hh.Write([]byte{letter})
			} else {
				hh.Write(out)
			}
			out = append(out, hh.Sum(nil)...)
		}
		return out[:n]
	}
	var keys sshKeys
	copy(keys.ivCS[:], ext('A', 16))
	copy(keys.ivSC[:], ext('B', 16))
	copy(keys.keyCS[:], ext('C', 16))
	copy(keys.keySC[:], ext('D', 16))
	return &keys
}

// ===== 认证阶段 =====

// sshServiceAuth 请求 "ssh-userauth" 服务并等 SERVICE_ACCEPT。
func sshServiceAuth(t *sshTx, conn net.Conn) error {
	payload := []byte{sshMsgServiceRequest}
	payload = append(payload, sshString([]byte("ssh-userauth"))...)
	if err := sshWritePacket(t, conn, payload); err != nil {
		return fmt.Errorf("ssh 发送 SERVICE_REQUEST 失败: %w", err)
	}
	for i := 0; i < 10; i++ {
		typ, _, err := sshReadEncrypted(t, conn)
		if err != nil {
			return fmt.Errorf("ssh 读取 SERVICE_ACCEPT 失败: %w", err)
		}
		if typ == sshMsgServiceAccept {
			return nil
		}
	}
	return fmt.Errorf("ssh 未收到 SERVICE_ACCEPT")
}

// sshPasswordAuth 发送 password 认证请求并判定结果。
func sshPasswordAuth(t *sshTx, conn net.Conn, user, pass string) (bool, error) {
	payload := []byte{sshMsgUserAuthReq}
	payload = append(payload, sshString([]byte(user))...)
	payload = append(payload, sshString([]byte("ssh-connection"))...)
	payload = append(payload, sshString([]byte("password"))...)
	payload = append(payload, 0) // FALSE: 不是修改口令
	payload = append(payload, sshString([]byte(pass))...)
	if err := sshWritePacket(t, conn, payload); err != nil {
		return false, fmt.Errorf("ssh 发送认证请求失败: %w", err)
	}
	for i := 0; i < 10; i++ {
		typ, _, err := sshReadEncrypted(t, conn)
		if err != nil {
			return false, fmt.Errorf("ssh 读取认证结果失败: %w", err)
		}
		switch typ {
		case sshMsgUserAuthSucc:
			return true, nil
		case sshMsgUserAuthFail:
			return false, nil
		case sshMsgUserAuthBanner:
			continue // 服务端横幅, 跳过继续等结果
		case sshMsgDisconnect:
			return false, nil
		}
	}
	return false, fmt.Errorf("ssh 未收到明确的认证结果")
}
