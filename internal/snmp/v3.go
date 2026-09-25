// v3.go SNMPv3 USM 支持(二期): 引擎发现 + 鉴权(authNoPriv) + 加密(authPriv)。
//
// 纯标准库实现: HMAC-MD5-96 / HMAC-SHA1-96 鉴权, DES-CBC / AES-128-CFB 加密,
// 密钥本地化按 RFC 3414 的 1MB 重复法。
//
// ===== 为什么要做 v3 =====
//
// v2c 的社区串在网络上明文传输且只有"全有或全无"一种权限, 合规场景(等保/内网
// 审计)普遍要求 v3。本包此前只做 v2c 并把"v3 待做"写在文件头, 二期补齐。
//
// ===== 实现边界(诚实声明) =====
//
//   - 支持: usmNoAuthNoPriv / usmAuthNoPriv(MD5|SHA1) / usmAuthPriv(MD5|SHA1 + DES|AES128)
//   - 不支持: SHA-224/256/384/512(USM 的 HMAC-SHA2 变体, RFC 7860; 设备侧支持率
//     远低于 MD5/SHA1, 遇到会明确报"不支持"而不是静默降级成无鉴权)
//   - 不做引擎启动时间(engineBoots)同步纠正: 设备重启后 boots 递增, 本实现以
//     设备每次响应里带回的 boots/time 为准持续跟进(RFC 3414 的时间同步规则)
//
// ===== 验证状态 =====
//
// 单测用"本地 UDP 假 v3 引擎"做自环验证(构造响应 + 本地算 HMAC 校验), 覆盖
// 密钥本地化 / 鉴权参数 / 加解密 / 引擎发现解析。**与真实设备的互通性需真机联调**
// (不同厂商的 USM 实现细节差异只能靠实测), 未联调前不应声称"已验证支持"。
package snmp

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"strings"
	"time"
)

// V3Config SNMPv3 安全参数(USM)。
type V3Config struct {
	User string `json:"user"`
	// AuthProto 鉴权协议: 空 = 不鉴权; md5 / sha(sha1)
	AuthProto string `json:"authProto,omitempty"`
	AuthPass  string `json:"authPass,omitempty"`
	// PrivProto 加密协议: 空 = 不加密; des / aes(aes128)。
	// USM 规定 priv 必须配 auth(没有 auth 的 priv 无意义且设备普遍拒收)。
	PrivProto string `json:"privProto,omitempty"`
	PrivPass  string `json:"privPass,omitempty"`
	// Context 上下文名(多数设备留空即可)
	Context string `json:"context,omitempty"`
}

// v3Engine 引擎参数缓存(发现一次后复用)。
type v3Engine struct {
	id       []byte
	boots    uint32
	engTime  uint32
	syncedAt time.Time

	authProto string
	privProto string
	authKey   []byte
	privKey   []byte
}

// bootsTimeNow 当前应发给设备的 boots/time。
//
// engineTime 是"引擎启动至今的秒数", 必须在本地持续推进 —— 每次请求都去发现
// 引擎会多一倍网络往返(监控采集是几十个 OID 的批量, 开销显著)。
func (e *v3Engine) bootsTimeNow() (uint32, uint32) {
	return e.boots, e.engTime + uint32(time.Since(e.syncedAt)/time.Second)
}

// ErrV3Report 设备回了 report PDU(引擎发现 / 鉴权失败), 不是本次查询的答案。
var ErrV3Report = errors.New("SNMPv3 report(引擎发现或鉴权未通过)")

const securityModelUSM = 3

// v3 消息标志位(RFC 3412 msgFlags)。
const (
	v3FlagAuth      = 0x01
	v3FlagReportable = 0x02
	v3FlagPriv      = 0x04
)

// pduTagReport report PDU 的 tag([8] IMPLICIT PDU)。
const pduTagReport = 0xa8

// ===== 协议归一化 =====

func normAuthProto(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "noauth":
		return ""
	case "md5", "hmac-md5", "usmhmacmd5":
		return "md5"
	case "sha", "sha1", "hmac-sha1", "usmhmacsha1":
		return "sha1"
	}
	return "?" // 未知协议: 由调用方据此报"不支持"
}

func normPrivProto(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "none", "nopriv":
		return ""
	case "des", "usmdes":
		return "des"
	case "aes", "aes128", "usmaes128":
		return "aes"
	}
	return "?"
}

func hashOf(proto string) func() hash.Hash {
	if proto == "sha1" {
		return sha1.New
	}
	return md5.New
}

// ===== 密钥本地化(RFC 3414) =====
//
// 口令 -> 密钥两步: ① 口令重复填满 1MB 后哈希得 Kul; ② H(Kul || engineID || Kul)。
// 第二步是关键: 同一口令在不同引擎上必须派生出不同密钥, 否则一台设备的密钥
// 泄漏会波及全部设备(这就是"本地化"的全部意义)。
func passwordToKey(h func() hash.Hash, pass string, engineID []byte) []byte {
	const oneMB = 1024 * 1024
	hf := h()
	if pass != "" {
		buf := make([]byte, 0, oneMB)
		p := []byte(pass)
		for len(buf) < oneMB {
			buf = append(buf, p...)
		}
		hf.Write(buf[:oneMB])
	} else {
		hf.Write(nil)
	}
	kul := hf.Sum(nil)
	hf.Reset()
	hf.Write(kul)
	hf.Write(engineID)
	hf.Write(kul)
	return hf.Sum(nil)
}

// authParams 计算消息鉴权码(取前 12 字节 = HMAC-96)。
func authParams(proto string, key, msg []byte) []byte {
	m := hmac.New(hashOf(proto), key)
	m.Write(msg)
	out := m.Sum(nil)
	if len(out) > 12 {
		out = out[:12]
	}
	return out
}

// ===== 加解密 =====

// privEncrypt 加密 ScopedPDU, 返回 (密文, privParams)。
//
// DES(RFC 3414): IV = preIV XOR salt, salt = boots||time 放在 privParams;
// AES(RFC 3826): IV = boots||time||salt(16B), privParams 只放 8 字节随机 salt。
// 两者 salt 语义不同, 不能共用一个推导 —— 混用会得到"设备解密失败但看不出原因"。
func privEncrypt(eng *v3Engine, plain, salt []byte) ([]byte, []byte, error) {
	boots, t := eng.bootsTimeNow()
	if eng.privProto == "aes" {
		if len(eng.privKey) < 16 {
			return nil, nil, errors.New("AES 密钥不足 16 字节")
		}
		block, err := aes.NewCipher(eng.privKey[:16])
		if err != nil {
			return nil, nil, err
		}
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv[0:4], boots)
		binary.BigEndian.PutUint32(iv[4:8], t)
		copy(iv[8:], salt)
		ct := make([]byte, len(plain))
		cipher.NewCFBEncrypter(block, iv).XORKeyStream(ct, plain)
		return ct, salt, nil
	}
	// des
	if len(eng.privKey) < 16 {
		return nil, nil, errors.New("DES 密钥不足 16 字节(key 8 + preIV 8)")
	}
	block, err := des.NewCipher(eng.privKey[:8])
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, 8)
	for i := 0; i < 8; i++ {
		iv[i] = eng.privKey[8+i] ^ salt[i]
	}
	padded := pkcs7Pad(plain, 8)
	ct := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ct, padded)
	return ct, salt, nil
}

// privDecrypt 解密响应里的 encryptedPDU。
//
// boots/time 必须用**响应报文里**带回的值, 不能是本端推算值: AES 的 IV 由
// boots||time||salt 组成, 两端若各算各的, 跨秒边界就会出现"偶发解密失败"
// (现象极难复现, 表现为监控指标偶发整轮为空)。
func privDecrypt(eng *v3Engine, ct, privParams []byte, boots, t uint32) ([]byte, error) {
	if eng.privProto == "aes" {
		block, err := aes.NewCipher(eng.privKey[:16])
		if err != nil {
			return nil, err
		}
		iv := make([]byte, 16)
		binary.BigEndian.PutUint32(iv[0:4], boots)
		binary.BigEndian.PutUint32(iv[4:8], t)
		copy(iv[8:], privParams)
		pt := make([]byte, len(ct))
		cipher.NewCFBDecrypter(block, iv).XORKeyStream(pt, ct)
		return pt, nil
	}
	// 解密用响应里带回的 privParams 作 salt(不是本端发出的那个)
	block, err := des.NewCipher(eng.privKey[:8])
	if err != nil {
		return nil, err
	}
	iv := make([]byte, 8)
	for i := 0; i < 8; i++ {
		var s byte
		if i < len(privParams) {
			s = privParams[i]
		}
		iv[i] = eng.privKey[8+i] ^ s
	}
	if len(ct)%8 != 0 {
		return nil, fmt.Errorf("DES 密文长度 %d 非 8 的倍数", len(ct))
	}
	pt := make([]byte, len(ct))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(pt, ct)
	// 解密后是完整 ScopedPDU 的 TLV, 尾部填充字节由 TLV 长度自然忽略
	return pt, nil
}

func pkcs7Pad(b []byte, block int) []byte {
	pad := block - len(b)%block
	out := make([]byte, len(b)+pad)
	copy(out, b)
	for i := len(b); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

// ===== 消息构造 =====

// intU32 编码 INTEGER(BER 最小字节数, 正数)。
func intU32(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	i := 0
	for i < 3 && b[i] == 0 {
		i++
	}
	return tlvBytes(tagInteger, b[i:])
}

// buildV3Message 构造 v3 消息(USM + ScopedPDU)。
func (c *Client) buildV3Message(pdu []byte) []byte {
	c.v3Mu.Lock()
	eng := c.v3Eng
	c.v3Mu.Unlock()
	if eng == nil {
		// 理论上不会走到(ensureV3Engine 先跑); 保底用空引擎发一个可报告的报文,
		// 设备会回 report 而不是被一条畸形报文打挂。
		eng = &v3Engine{}
	}
	return c.buildV3With(eng, pdu, false)
}

// buildV3With 按给定引擎参数构造消息(发现包与正常包共用)。
//
// reportable 位只在引擎发现阶段置 1: 设备仅在收到 reportable 报文时才回 report,
// 少了这一位表现为"连接超时"而不是"引擎发现失败", 排查方向完全不同。
func (c *Client) buildV3With(eng *v3Engine, pdu []byte, reportable bool) []byte {
	cfg := c.V3
	if cfg == nil {
		cfg = &V3Config{}
	}
	auth := len(eng.authKey) > 0
	priv := len(eng.privKey) >= 16 && eng.privProto != ""
	flags := 0
	if auth {
		flags |= v3FlagAuth
	}
	if priv {
		flags |= v3FlagPriv
	}
	if reportable {
		flags |= v3FlagReportable
	}

	msgID := uint32(c.reqID.Add(1) % 0x7fffffff)
	boots, t := eng.bootsTimeNow()

	scoped := seq(
		tlvBytes(tagOctetStr, eng.id),
		tlvBytes(tagOctetStr, []byte(cfg.Context)),
		pdu,
	)
	data := scoped
	privParams := []byte{}
	if priv {
		salt := make([]byte, 8)
		if eng.privProto == "aes" {
			_, _ = rand.Read(salt) // AES 的 salt 随机(DES 用 boots||time 便于对端复算 IV)
		} else {
			binary.BigEndian.PutUint32(salt[0:4], boots)
			binary.BigEndian.PutUint32(salt[4:8], t)
		}
		ct, pp, err := privEncrypt(eng, scoped, salt)
		if err == nil {
			data = tlvBytes(tagOctetStr, ct)
			privParams = pp
		} else {
			// 加密失败 -> 退到 authNoPriv。安全级别降到设备不接受时, 设备会回
			// report(可诊断), 好过发一条结构非法的报文。
			flags &= ^v3FlagPriv
		}
	}

	authP := []byte{}
	if auth {
		authP = make([]byte, 12) // 先填 12 字节 0, 算完 MAC 再重建
	}
	header := seq(
		intU32(msgID),
		intU32(65507),
		tlvBytes(tagOctetStr, []byte{byte(flags)}),
		intField(securityModelUSM),
	)
	usm := seq(
		tlvBytes(tagOctetStr, eng.id),
		intU32(boots),
		intU32(t),
		tlvBytes(tagOctetStr, []byte(cfg.User)),
		tlvBytes(tagOctetStr, authP),
		tlvBytes(tagOctetStr, privParams),
	)
	msg := seq(
		intField(3),
		header,
		tlvBytes(tagOctetStr, usm),
		data,
	)
	if auth {
		mac := authParams(eng.authProto, eng.authKey, msg)
		usm = seq(
			tlvBytes(tagOctetStr, eng.id),
			intU32(boots),
			intU32(t),
			tlvBytes(tagOctetStr, []byte(cfg.User)),
			tlvBytes(tagOctetStr, mac),
			tlvBytes(tagOctetStr, privParams),
		)
		// MAC 与原占位等长(12 字节), 消息长度不变 —— 重建而不是就地替换,
		// 就地替换要求精确知道 authParams 的偏移, 易错且无法被单测覆盖。
		msg = seq(intField(3), header, tlvBytes(tagOctetStr, usm), data)
	}
	return msg
}

// buildV3Discovery 引擎发现报文: 空引擎参数 + reportable 标志。
//
// 发现请求不能用鉴权(还不知道引擎 ID, 无法派生本地化密钥) —— 这是 v3 握手
// 必须先走 discovery 的原因, 也是它无法被"省掉"的原因。
func (c *Client) buildV3Discovery() []byte {
	eng := &v3Engine{}
	return c.buildV3With(eng, pduTLV(pduTagGet,
		intField(int(c.reqID.Add(1)%0x7fffffff)),
		intField(0), intField(0),
		varbindSeq(nil),
	), true)
}

// ===== 引擎发现与同步 =====

// ensureV3Engine 首次调用时做一次引擎发现并派生密钥。
//
// 持锁做网络往返是刻意的: 并发采集同一目标时只发现一次(发现包不带鉴权,
// 多发只会增加被设备限速的风险), 且锁内不调用任何会再次加锁的函数。
func (c *Client) ensureV3Engine(ctx context.Context) error {
	if c.V3 == nil {
		return nil
	}
	c.v3Mu.Lock()
	defer c.v3Mu.Unlock()
	if c.v3Eng != nil {
		return nil
	}
	resp, err := c.roundTrip(ctx, c.buildV3Discovery())
	if err != nil {
		return fmt.Errorf("SNMPv3 引擎发现失败(设备不可达?): %w", err)
	}
	eng, err := parseV3Engine(resp)
	if err != nil {
		return err
	}
	eng.authProto, eng.privProto, err = validateV3Config(c.V3)
	if err != nil {
		return err
	}
	// priv 密钥按 RFC 用鉴权协议的哈希派生; noAuth 时(不可能到这)退 MD5
	khash := md5.New
	if eng.authProto == "sha1" {
		khash = sha1.New
	}
	if eng.authProto != "" {
		eng.authKey = passwordToKey(hashOf(eng.authProto), c.V3.AuthPass, eng.id)
	}
	if eng.privProto != "" {
		eng.privKey = passwordToKey(khash, c.V3.PrivPass, eng.id)
		if len(eng.privKey) < 16 && eng.privProto == "des" {
			return errors.New("DES 密钥派生长度不足")
		}
		if len(eng.privKey) < 16 && eng.privProto == "aes" {
			return errors.New("AES 密钥派生长度不足")
		}
	}
	c.v3Eng = eng
	return nil
}

// validateV3Config 校验并归一化 v3 安全参数。
//
// 抽成纯函数是为了能在无网络的情况下单测: 这几个判断错了的表现是"设备一直
// 报鉴权失败", 而真正原因在配置里, 靠联调很难定位。
func validateV3Config(cfg *V3Config) (authProto, privProto string, err error) {
	if cfg == nil {
		return "", "", errors.New("SNMPv3 配置为空")
	}
	authProto = normAuthProto(cfg.AuthProto)
	privProto = normPrivProto(cfg.PrivProto)
	switch {
	case authProto == "?":
		return "", "", fmt.Errorf("不支持的 v3 鉴权协议: %s(支持 md5 / sha)", cfg.AuthProto)
	case privProto == "?":
		return "", "", fmt.Errorf("不支持的 v3 加密协议: %s(支持 des / aes)", cfg.PrivProto)
	case privProto != "" && authProto == "":
		// USM 没有"只加密不鉴权"这一档: 设备普遍拒收, 且没有完整性保护时
		// 加密本身也失去意义 —— 明确报错而不是悄悄降级成明文。
		return "", "", errors.New("SNMPv3 配置错误: 加密(priv)必须搭配鉴权(auth)")
	}
	return authProto, privProto, nil
}

// parseV3Engine 从 report 响应里取引擎参数。
func parseV3Engine(b []byte) (*v3Engine, error) {
	outer, _, err := decodeTLV(b)
	if err != nil || outer.tag != 0x30 {
		return nil, errors.New("SNMPv3 发现响应格式错误")
	}
	v, r1, err := decodeTLV(outer.content)
	if err != nil {
		return nil, err
	}
	if v.tag != tagInteger || len(v.content) == 0 || v.content[0] != 3 {
		return nil, errors.New("SNMPv3 发现响应版本非 3")
	}
	_, r2, err := decodeTLV(r1) // HeaderData
	if err != nil {
		return nil, err
	}
	spTLV, _, err := decodeTLV(r2)
	if err != nil || spTLV.tag != tagOctetStr {
		return nil, errors.New("SNMPv3 安全参数缺失")
	}
	usm, _, err := decodeTLV(spTLV.content)
	if err != nil || usm.tag != 0x30 {
		return nil, errors.New("SNMPv3 USM 参数缺失")
	}
	eid, u1, err := decodeTLV(usm.content)
	if err != nil || eid.tag != tagOctetStr {
		return nil, errors.New("SNMPv3 引擎 ID 缺失")
	}
	bootsT, u2, err := decodeTLV(u1)
	if err != nil {
		return nil, err
	}
	timeT, _, err := decodeTLV(u2)
	if err != nil {
		return nil, err
	}
	boots, _ := decodeUint32(bootsT.content)
	t, _ := decodeUint32(timeT.content)
	if len(eid.content) == 0 {
		return nil, errors.New("SNMPv3 引擎 ID 为空(设备未回 usmStatsUnknownEngineIDs)")
	}
	return &v3Engine{id: append([]byte(nil), eid.content...), boots: uint32(boots), engTime: uint32(t), syncedAt: time.Now()}, nil
}

// syncV3EngineFrom 用响应里带回的引擎参数跟进 boots/time(设备重启后 boots 递增)。
func (c *Client) syncV3EngineFrom(id []byte, boots, t uint32) {
	if len(id) == 0 {
		return
	}
	c.v3Mu.Lock()
	defer c.v3Mu.Unlock()
	e := c.v3Eng
	if e == nil {
		return
	}
	if boots > e.boots || (boots == e.boots && t > e.engTime+uint32(time.Since(e.syncedAt)/time.Second)) {
		e.boots = boots
		e.engTime = t
		e.syncedAt = time.Now()
	}
}

// ===== 响应解析 =====

// parseV3Message 解析 v3 响应(解密 + 取 ScopedPDU 内的 PDU)。
func (c *Client) parseV3Message(b []byte) ([]Varbind, int, error) {
	outer, _, err := decodeTLV(b)
	if err != nil || outer.tag != 0x30 {
		return nil, 0, errors.New("SNMP 消息外层非 sequence")
	}
	v, r1, err := decodeTLV(outer.content)
	if err != nil {
		return nil, 0, err
	}
	if v.tag != tagInteger || len(v.content) == 0 || v.content[0] != 3 {
		return nil, 0, errors.New("版本非 v3(3)")
	}
	_, r2, err := decodeTLV(r1) // HeaderData
	if err != nil {
		return nil, 0, err
	}
	spTLV, r3, err := decodeTLV(r2)
	if err != nil || spTLV.tag != tagOctetStr {
		return nil, 0, errors.New("SNMPv3 安全参数缺失")
	}
	usm, _, err := decodeTLV(spTLV.content)
	if err != nil || usm.tag != 0x30 {
		return nil, 0, errors.New("SNMPv3 USM 参数缺失")
	}
	eid, u1, err := decodeTLV(usm.content)
	if err != nil {
		return nil, 0, err
	}
	bootsT, u2, err := decodeTLV(u1)
	if err != nil {
		return nil, 0, err
	}
	timeT, u3, err := decodeTLV(u2)
	if err != nil {
		return nil, 0, err
	}
	_, u4, err := decodeTLV(u3) // userName
	if err != nil {
		return nil, 0, err
	}
	_, u5, err := decodeTLV(u4) // authParams
	if err != nil {
		return nil, 0, err
	}
	privT, _, err := decodeTLV(u5) // privParams
	if err != nil {
		return nil, 0, err
	}
	boots, _ := decodeUint32(bootsT.content)
	t, _ := decodeUint32(timeT.content)
	c.syncV3EngineFrom(eid.content, uint32(boots), uint32(t))

	dataTLV, _, err := decodeTLV(r3)
	if err != nil {
		return nil, 0, errors.New("SNMPv3 数据段缺失")
	}
	var scoped []byte
	if dataTLV.tag == tagOctetStr {
		// 加密响应
		c.v3Mu.Lock()
		eng := c.v3Eng
		c.v3Mu.Unlock()
		if eng == nil || eng.privProto == "" {
			return nil, 0, errors.New("响应已加密但未配置 priv 口令")
		}
		scoped, err = privDecrypt(eng, dataTLV.content, privT.content, uint32(boots), uint32(t))
		if err != nil {
			return nil, 0, fmt.Errorf("响应解密失败(口令/引擎参数不匹配?): %w", err)
		}
	} else {
		// 明文: dataTLV 就是 ScopedPDU 的 SEQUENCE, 重新编码回完整 TLV
		scoped = tlvBytes(dataTLV.tag, dataTLV.content)
	}
	sp, _, err := decodeTLV(scoped)
	if err != nil || sp.tag != 0x30 {
		return nil, 0, errors.New("SNMPv3 ScopedPDU 解析失败")
	}
	_, s1, err := decodeTLV(sp.content) // contextEngineID
	if err != nil {
		return nil, 0, err
	}
	_, s2, err := decodeTLV(s1) // contextName
	if err != nil {
		return nil, 0, err
	}
	pdu, _, err := decodeTLV(s2)
	if err != nil {
		return nil, 0, errors.New("SNMPv3 PDU 缺失")
	}
	if pdu.tag == pduTagReport {
		return nil, 0, ErrV3Report
	}
	if pdu.tag != pduTagResponse && pdu.tag != 0x30 {
		return nil, 0, fmt.Errorf("PDU tag 0x%x 非 getResponse", pdu.tag)
	}
	return parsePDUVars(pdu)
}
