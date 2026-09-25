package snmp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"strings"
	"testing"
	"time"
)

// 注意: 本文件全部离线自环验证(构造报文 -> 本包解析), 不发真实网络包。
// 与真实设备的互通性需真机联调 —— 未联调前 v3 只应声称"已实现"而非"已验证"。

// ===== 协议归一化 =====

func TestNormProtoUnsupported(t *testing.T) {
	// 契约: 不支持的协议必须报"不支持", 不能静默降级成无鉴权(那是安全回退)
	if got := normAuthProto("sha256"); got != "?" {
		t.Fatalf("sha256 应判为不支持, 得到 %q", got)
	}
	if got := normPrivProto("aes256"); got != "?" {
		t.Fatalf("aes256 应判为不支持, 得到 %q", got)
	}
	if normAuthProto("MD5") != "md5" || normAuthProto("sha") != "sha1" {
		t.Fatal("md5/sha 归一化错误")
	}
	if normPrivProto("AES128") != "aes" || normPrivProto("") != "" {
		t.Fatal("priv 归一化错误")
	}
}

// ===== 密钥本地化 =====

func TestPasswordToKeyIsEngineScoped(t *testing.T) {
	// 契约(安全): 同一口令在不同引擎上必须派生出不同密钥 —— 否则一台设备的
	// 密钥泄漏会波及全部设备, 这正是"密钥本地化"存在的唯一理由。
	a := passwordToKey(md5.New, "pass", []byte{0x01, 0x02, 0x03})
	b := passwordToKey(md5.New, "pass", []byte{0x01, 0x02, 0x04})
	if string(a) == string(b) {
		t.Fatal("不同引擎 ID 派生出了相同密钥")
	}
	// 同输入必须稳定(否则同一会话内消息会互相鉴权失败)
	if string(a) != string(passwordToKey(md5.New, "pass", []byte{0x01, 0x02, 0x03})) {
		t.Fatal("同输入密钥不稳定")
	}
	if len(a) != 16 || len(passwordToKey(sha1.New, "pass", []byte{0x01})) != 20 {
		t.Fatal("密钥长度应为哈希长度(MD5=16 / SHA1=20)")
	}
}

func TestAuthParamsIsHMAC96(t *testing.T) {
	key := []byte("0123456789abcdef")
	msg := []byte("message")
	got := authParams("md5", key, msg)
	m := hmac.New(md5.New, key)
	m.Write(msg)
	want := m.Sum(nil)
	if len(got) != 12 || string(got) != string(want[:12]) {
		t.Fatalf("鉴权码应为 HMAC 前 12 字节(HMAC-96), 得到 %x", got)
	}
}

// ===== 加解密 =====

func TestPrivRoundTripDES(t *testing.T) {
	eng := &v3Engine{privProto: "des", privKey: passwordToKey(md5.New, "privpass", []byte{0xaa, 0xbb})}
	plain := seq(intField(1), intField(2)) // 任意 TLV 内容
	salt := []byte{0, 0, 0, 1, 0, 0, 0, 2}
	ct, pp, err := privEncrypt(eng, plain, salt)
	if err != nil {
		t.Fatal(err)
	}
	if string(pp) != string(salt) {
		t.Fatal("DES 的 privParams 应就是 salt(对端靠它复算 IV)")
	}
	pt, err := privDecrypt(eng, ct, pp, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	// 解密后应能解出原 TLV(尾部 PKCS#7 填充由 TLV 长度自然忽略)
	outer, _, err := decodeTLV(pt)
	if err != nil || outer.tag != 0x30 || string(outer.content) != string(plain[2:]) {
		t.Fatalf("DES 往返内容不一致: %x", pt)
	}
}

func TestPrivRoundTripAES(t *testing.T) {
	eng := &v3Engine{privProto: "aes", privKey: passwordToKey(md5.New, "privpass", []byte{0xaa, 0xbb})}
	plain := seq(intField(7))
	salt := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	ct, pp, err := privEncrypt(eng, plain, salt)
	if err != nil {
		t.Fatal(err)
	}
	if string(pp) != string(salt) {
		t.Fatal("AES 的 privParams 应只放 8 字节 salt")
	}
	// 解密必须用"响应报文里"的 boots/time(与加密时同一取值才对得上)
	boots, tm := eng.bootsTimeNow()
	pt, err := privDecrypt(eng, ct, pp, boots, tm)
	if err != nil {
		t.Fatal(err)
	}
	if string(pt) != string(plain) {
		t.Fatal("AES 往返内容不一致")
	}
	// 契约: 用错 boots/time 必须解不出(否则监控会偶发拿到乱码而不是报错)
	bad, err := privDecrypt(eng, ct, pp, boots+1, tm)
	if err == nil && string(bad) == string(plain) {
		t.Fatal("boots/time 不符却解密成功: IV 推导有问题")
	}
}

// ===== 消息构造与解析 =====

// v3Client 构造一个 authPriv 客户端(不发起真实发现)。
func v3Client(t *testing.T, priv string) *Client {
	t.Helper()
	c := NewClient("127.0.0.1:161", "", time.Second)
	c.V3 = &V3Config{User: "monitor", AuthProto: "sha1", AuthPass: "authpass", PrivProto: priv, PrivPass: "privpass"}
	eid := []byte{0x80, 0x00, 0x1f, 0x88, 0x01, 0x02}
	c.v3Eng = &v3Engine{
		id: eid, boots: 3, engTime: 100, syncedAt: time.Now(),
		authProto: "sha1", privProto: priv,
		authKey: passwordToKey(sha1.New, "authpass", eid),
	}
	if priv != "" {
		c.v3Eng.privKey = passwordToKey(sha1.New, "privpass", eid)
	}
	return c
}

func TestV3MessageRoundTripAuthNoPriv(t *testing.T) {
	c := v3Client(t, "")
	pdu := pduTLV(pduTagResponse,
		intField(42), intField(0), intField(0),
		varbindSeq([]string{"1.3.6.1.2.1.1.1.0"}),
	)
	msg := c.buildV3With(c.v3Eng, pdu, false)
	vbs, errStatus, err := c.parseV3Message(msg)
	if err != nil {
		t.Fatalf("自环解析失败: %v", err)
	}
	if errStatus != 0 || len(vbs) != 1 {
		t.Fatalf("varbinds 解析错误: %+v status=%d", vbs, errStatus)
	}
	if vbs[0].OID != "1.3.6.1.2.1.1.1.0" {
		t.Fatalf("OID 不一致: %s", vbs[0].OID)
	}
}

func TestV3MessageRoundTripAuthPriv(t *testing.T) {
	for _, proto := range []string{"des", "aes"} {
		c := v3Client(t, proto)
		pdu := pduTLV(pduTagResponse,
			intField(43), intField(0), intField(0),
			varbindSeq([]string{"1.3.6.1.2.1.1.5.0"}),
		)
		msg := c.buildV3With(c.v3Eng, pdu, false)
		vbs, _, err := c.parseV3Message(msg)
		if err != nil {
			t.Fatalf("%s 自环解析失败(加解密不对称?): %v", proto, err)
		}
		if len(vbs) != 1 || vbs[0].OID != "1.3.6.1.2.1.1.5.0" {
			t.Fatalf("%s varbind 解错: %+v", proto, vbs)
		}
	}
}

func TestV3AuthParamsCoversWholeMessage(t *testing.T) {
	// 契约: 鉴权码必须覆盖"整条消息"(含 msgID)。若有人改成只签 PDU 或只签
	// 固定字段, 两条内容相同但 msgID 不同的消息会得到同一个 MAC, 设备侧
	// 表现为"第一条能过、之后全部鉴权失败" —— 极难定位, 故在此钉死。
	c := v3Client(t, "")
	m1 := c.buildV3With(c.v3Eng, pduTLV(pduTagGet, intField(1), intField(0), intField(0), varbindSeq(nil)), false)
	m2 := c.buildV3With(c.v3Eng, pduTLV(pduTagGet, intField(1), intField(0), intField(0), varbindSeq(nil)), false)
	mac1, mac2 := extractAuthParams(t, m1), extractAuthParams(t, m2)
	if len(mac1) != 12 {
		t.Fatalf("鉴权码应为 HMAC-96(12 字节), 得到 %d", len(mac1))
	}
	if string(mac1) == string(mac2) {
		t.Fatal("两条不同 msgID 的消息鉴权码相同: MAC 未覆盖整条消息")
	}
	// 换用户后 MAC 必须变(USM 参数参与签名)
	c2 := v3Client(t, "")
	c2.V3.User = "other"
	m3 := c2.buildV3With(c2.v3Eng, pduTLV(pduTagGet, intField(1), intField(0), intField(0), varbindSeq(nil)), false)
	if string(extractAuthParams(t, m3)) == string(mac1) {
		t.Fatal("换用户后鉴权码未变: USM 参数未参与签名")
	}
}

// extractAuthParams 从 v3 消息里取出鉴权码字段。
func extractAuthParams(t *testing.T, msg []byte) []byte {
	t.Helper()
	outer, _, err := decodeTLV(msg)
	if err != nil {
		t.Fatal(err)
	}
	_, r1, _ := decodeTLV(outer.content)
	_, r2, _ := decodeTLV(r1)
	spTLV, _, _ := decodeTLV(r2)
	usm, _, _ := decodeTLV(spTLV.content)
	_, u1, _ := decodeTLV(usm.content)
	_, u2, _ := decodeTLV(u1)
	_, u3, _ := decodeTLV(u2)
	_, u4, _ := decodeTLV(u3)
	authT, _, err := decodeTLV(u4)
	if err != nil {
		t.Fatal(err)
	}
	return authT.content
}

// ===== 引擎发现 =====

func TestV3DiscoveryAndEngineParse(t *testing.T) {
	c := v3Client(t, "")
	c.v3Eng = nil // 强制走发现流程
	disc := c.buildV3Discovery()

	// 契约: 发现报文必须带 reportable 标志, 否则设备不回 report(表现为超时)
	outer, _, err := decodeTLV(disc)
	if err != nil {
		t.Fatal(err)
	}
	_, r1, _ := decodeTLV(outer.content)
	header, _, _ := decodeTLV(r1)
	_, h1, _ := decodeTLV(header.content)
	_, h2, _ := decodeTLV(h1)
	flagsTLV, _, _ := decodeTLV(h2)
	if flagsTLV.tag != tagOctetStr || len(flagsTLV.content) == 0 || flagsTLV.content[0]&v3FlagReportable == 0 {
		t.Fatalf("发现报文缺 reportable 标志: %x", flagsTLV.content)
	}

	// 构造设备的 report 响应: engineID + boots/time
	eid := []byte{0x80, 0x00, 0x1f, 0x88, 0xaa, 0xbb}
	usm := seq(
		tlvBytes(tagOctetStr, eid),
		intU32(7), intU32(1234),
		tlvBytes(tagOctetStr, nil),
		tlvBytes(tagOctetStr, nil),
		tlvBytes(tagOctetStr, nil),
	)
	report := seq(
		intField(3),
		seq(intU32(1), intU32(65507), tlvBytes(tagOctetStr, []byte{v3FlagReportable}), intField(securityModelUSM)),
		tlvBytes(tagOctetStr, usm),
		seq(tlvBytes(tagOctetStr, eid), tlvBytes(tagOctetStr, nil),
			pduTLV(pduTagReport, intField(1), intField(0), intField(0), varbindSeq(nil))),
	)
	eng, err := parseV3Engine(report)
	if err != nil {
		t.Fatalf("引擎参数解析失败: %v", err)
	}
	if string(eng.id) != string(eid) || eng.boots != 7 || eng.engTime != 1234 {
		t.Fatalf("引擎参数解析错误: %+v", eng)
	}
	// engineTime 必须随本地时间推进(否则连续请求会带上同一个 time 值)
	_, t1 := eng.bootsTimeNow()
	eng.syncedAt = eng.syncedAt.Add(-5 * time.Second)
	_, t2 := eng.bootsTimeNow()
	if t2-t1 != 5 {
		t.Fatalf("engineTime 未随时间推进: %d -> %d", t1, t2)
	}
}

func TestValidateV3Config(t *testing.T) {
	// 契约: 配置错误必须在"发现阶段"就报错(带明确原因), 而不是等发出请求后
	// 被设备以鉴权失败拒绝 —— 那时日志只写"authFailure", 排查方向完全不同。
	if _, _, err := validateV3Config(&V3Config{User: "u", AuthProto: "sha256"}); err == nil ||
		!strings.Contains(err.Error(), "鉴权协议") {
		t.Fatalf("sha256 应报鉴权协议不支持, 得到 %v", err)
	}
	if _, _, err := validateV3Config(&V3Config{User: "u", AuthProto: "md5", PrivProto: "aes256"}); err == nil ||
		!strings.Contains(err.Error(), "加密协议") {
		t.Fatalf("aes256 应报加密协议不支持, 得到 %v", err)
	}
	if _, _, err := validateV3Config(&V3Config{User: "u", PrivProto: "des"}); err == nil ||
		!strings.Contains(err.Error(), "必须搭配鉴权") {
		t.Fatalf("只配 priv 应报错, 得到 %v", err)
	}
	a, p, err := validateV3Config(&V3Config{User: "u", AuthProto: "SHA", PrivProto: "AES128"})
	if err != nil || a != "sha1" || p != "aes" {
		t.Fatalf("正常配置应通过并归一化: %v %v %v", a, p, err)
	}
	if _, _, err := validateV3Config(nil); err == nil {
		t.Fatal("空配置应报错")
	}
}
