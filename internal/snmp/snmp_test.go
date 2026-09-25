// snmp_test.go 离线契约测试(不依赖网络/时序, 遵守项目测试规则 12)。
//
// 核心契约: BER/消息编码错了整个 SNMP 互通就废, 故用"经典 sysDescr GET
// 请求的完整字节序列"做跨实现锚点(任何标准 SNMP 栈对它的字节都一致),
// 以及手工构造的响应报文验证解析与类型消歧。
package snmp

import (
	"bytes"
	"testing"
)

func TestOIDRoundTrip(t *testing.T) {
	// 8072/2021 覆盖多字节 base-128 弧
	for _, s := range []string{"1.3.6.1.2.1.1.1", "1.3.6.1.4.1.8072.1.9.2.1", "1.3.6.1.4.1.2021.9.1", "1.2.3"} {
		arc, err := ParseOID(s)
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if got := FormatOID(arc); got != s {
			t.Fatalf("Format(%s) = %s", s, got)
		}
		dec, err := DecodeOID(EncodeOID(arc))
		if err != nil {
			t.Fatalf("DecodeOID(%s): %v", s, err)
		}
		if FormatOID(dec) != s {
			t.Fatalf("编码回环 %s -> %s", s, FormatOID(dec))
		}
	}
}

func TestOIDDecodeKnown(t *testing.T) {
	// 1.3.6.1.2.1: 首两弧合并 1*40+3=43(0x2b)
	arc, err := DecodeOID([]byte{0x2b, 0x06, 0x01, 0x02, 0x01})
	if err != nil {
		t.Fatal(err)
	}
	if FormatOID(arc) != "1.3.6.1.2.1" {
		t.Fatalf("got %s", FormatOID(arc))
	}
}

func TestOIDInvalid(t *testing.T) {
	for _, bad := range []string{"", "1", "a.b.c", "3.6.1", "-1.2", "1.2.3."} {
		if _, err := ParseOID(bad); err == nil {
			t.Fatalf("%q 应为非法 OID", bad)
		}
	}
}

func TestOIDCompareAndExtension(t *testing.T) {
	a, _ := ParseOID("1.3.6.1.2.1.2.2.1")   // ifTable
	b, _ := ParseOID("1.3.6.1.2.1.2.2.1.1.5") // ifIndex.5
	c, _ := ParseOID("1.3.6.1.2.1.2.2.10")  // ifXTable(相邻表)
	if CompareOID(a, b) != -1 {
		t.Fatal("a < b 应成立")
	}
	if !IsExtension(a, b) {
		t.Fatal("b 应是 a 的扩展")
	}
	if IsExtension(a, c) {
		t.Fatal("ifXTable 不是 ifTable 的扩展(walk 终止判据)")
	}
	if !IsExtension(a, a) {
		t.Fatal("自身应是自身的扩展")
	}
}

func TestBERLenRoundTrip(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 300, 65535, 16777215} {
		e := encodeLen(n)
		d, m, err := decodeLen(e)
		if err != nil {
			t.Fatalf("%d: %v", n, err)
		}
		if d != n || m != len(e) {
			t.Fatalf("len %d: 解得 %d 消耗 %d/%d", n, d, m, len(e))
		}
	}
}

func TestTLVRoundTrip(t *testing.T) {
	content := []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01}
	got, rest, err := decodeTLV(tlvBytes(tagOID, content))
	if err != nil {
		t.Fatal(err)
	}
	if got.tag != tagOID || !bytes.Equal(got.content, content) || len(rest) != 0 {
		t.Fatalf("tag=%x content=%x rest=%d", got.tag, got.content, len(rest))
	}
	// 长格式长度(>127)
	got2, rest2, err := decodeTLV(tlvBytes(tagOctetStr, make([]byte, 300)))
	if err != nil || len(got2.content) != 300 || len(rest2) != 0 {
		t.Fatalf("长格式长度解析失败: %v", err)
	}
}

func TestV2CGetRequestBytes(t *testing.T) {
	// 经典 sysDescr GET: 任何标准 SNMP 栈产出的字节序列都应如下
	// (reqID 首次 Add(1) 为 1, 保证确定性)。PDU tag 必须是 0xA0
	// (context [0]), 用 0x30 多数设备拒收。
	c := NewClient("1.2.3.4", "public", 0)
	got := c.buildGet([]string{"1.3.6.1.2.1.1.1.0"})
	want := []byte{
		0x30, 0x26,
		0x02, 0x01, 0x01, // version 1 (v2c)
		0x04, 0x06, 'p', 'u', 'b', 'l', 'i', 'c',
		0xa0, 0x19,
		0x02, 0x01, 0x01, // reqid=1
		0x02, 0x01, 0x00, 0x02, 0x01, 0x00, // err-status, err-index
		0x30, 0x0e, 0x30, 0x0c,
		0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00,
		0x05, 0x00,
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("GET 请求与经典编码不符:\n got % x\nwant % x", got, want)
	}
}

func TestV2CGetBulkRequest(t *testing.T) {
	c := NewClient("1.2.3.4", "public", 0)
	got := c.buildGetBulk([]string{"1.3.6.1.2.1.2.2.1"}, 1, 10)
	i := bytes.Index(got, []byte{0xa5})
	if i < 0 {
		t.Fatal("未找到 getBulk(0xa5) PDU tag")
	}
	// non-repetitions=1, max-repetitions=10(0x0a)
	if !bytes.Contains(got[i:], []byte{0x02, 0x01, 0x01, 0x02, 0x01, 0x0a}) {
		t.Fatalf("nonRep/maxRep 字段错误: % x", got[i:])
	}
}

func TestParseResponse(t *testing.T) {
	// 手工构造 getResponse(tag=0xA2): 内容 = reqid/err/idx/varbinds
	varbinds := []byte{}
	addVB := func(oid []byte, tag byte, val []byte) {
		varbinds = append(varbinds, seq(tlvBytes(tagOID, oid), tlvBytes(int(tag), val))...)
	}
	addVB([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01}, 0x04, []byte("RGOS switch"))
	addVB([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x07}, tagCounter32, []byte{0, 0, 0, 0x07})
	addVB([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x03}, tagTimeTicks, []byte{0, 0, 0x12, 0x34})
	addVB([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x02}, 0x06, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x05})
	// hrStorageUsed: 1.3.6.1.2.1.25.2.3.1.5 → 25=0x19
	addVB([]byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x19, 0x02, 0x03, 0x01, 0x05}, tagCounter64, []byte{0, 0, 0, 0, 0, 0, 0x10, 0})
	msg := seq(
		intField(1),
		tlvBytes(tagOctetStr, []byte("public")),
		pduTLV(pduTagResponse, intField(1), intField(0), intField(0), seq(varbinds)),
	)

	vbs, errStatus, err := parseResponse(msg, "public")
	if err != nil {
		t.Fatal(err)
	}
	if errStatus != 0 || len(vbs) != 5 {
		t.Fatalf("errStatus=%d varbinds=%d", errStatus, len(vbs))
	}
	want := map[string]Varbind{
		"1.3.6.1.2.1.1.1":        {Type: "octetstring", Value: "RGOS switch"},
		"1.3.6.1.2.1.1.7":        {Type: "counter32", Value: "7"},
		"1.3.6.1.2.1.1.3":        {Type: "timeticks", Value: "4660"},
		"1.3.6.1.2.1.1.2":        {Type: "oid", Value: "1.3.6.1.2.1.5"},
		"1.3.6.1.2.1.25.2.3.1.5": {Type: "counter64", Value: "4096"},
	}
	for _, v := range vbs {
		w, ok := want[v.OID]
		if !ok {
			t.Fatalf("意外 OID %s", v.OID)
		}
		if v.Type != w.Type || v.Value != w.Value {
			t.Fatalf("%s: got %s/%s want %s/%s", v.OID, v.Type, v.Value, w.Type, w.Value)
		}
	}
}

func TestParseResponseNoSuch(t *testing.T) {
	// v2 批量 GET 中单个 OID 不存在: errStatus=0, varbind 值为异常 tag
	msg := seq(
		intField(1), tlvBytes(tagOctetStr, []byte("public")),
		pduTLV(pduTagResponse, intField(1), intField(0), intField(0),
			seq(seq(tlvBytes(tagOID, []byte{0x2b, 0x06, 0x01, 0x02, 0x01, 0x63}), tlvBytes(0x80, nil)))),
	)
	vbs, errStatus, err := parseResponse(msg, "public")
	if err != nil || errStatus != 0 || len(vbs) != 1 {
		t.Fatalf("err=%v status=%d n=%d", err, errStatus, len(vbs))
	}
	if !isNoSuchType(vbs[0].Type) {
		t.Fatalf("应识别为异常值, got %s", vbs[0].Type)
	}
}

func TestParseResponseCommunityMismatch(t *testing.T) {
	msg := seq(intField(1), tlvBytes(tagOctetStr, []byte("private")),
		pduTLV(pduTagResponse, intField(1), intField(0), intField(0), seq()))
	if _, _, err := parseResponse(msg, "public"); err == nil {
		t.Fatal("community 不匹配应报错(防串台)")
	}
}

func TestDecodeValueSpecialOctets(t *testing.T) {
	typ, text, _, err := decodeValue(tagOctetStr, []byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	if err != nil || typ != "octetstring" || text != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("MAC 格式: %s %s %v", typ, text, err)
	}
	typ2, text2, _, _ := decodeValue(tagIPAddress, []byte{172, 16, 199, 1})
	if typ2 != "ipaddress" || text2 != "172.16.199.1" {
		t.Fatalf("IP 格式: %s %s", typ2, text2)
	}
	// 长度 4 的 OctetString 是合法字符串, 绝不能与 Counter32 混淆
	// (旧实现靠长度消歧, 真机 Counter32 走的是专属 tag 0x41)。
	typ3, _, _, err3 := decodeValue(tagOctetStr, []byte{0, 0, 0, 7})
	if err3 != nil || typ3 != "octetstring" {
		t.Fatalf("4 字节 OctetString 应为字符串, got %s (%v)", typ3, err3)
	}
}

func TestMIBWellFormed(t *testing.T) {
	// 契约: 表子列 OID 必须等于 表基+子列索引, 否则 groupRows 会静默丢列
	for _, m := range Scalars {
		if _, err := ParseOID(m.OID); err != nil {
			t.Fatalf("标量 %s: %v", m.OID, err)
		}
	}
	for _, tb := range Tables {
		base, err := ParseOID(tb.Base)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[int]bool{}
		for sub, m := range tb.Subs {
			if seen[sub] {
				t.Fatalf("%s 子列 %d 重复", tb.Base, sub)
			}
			seen[sub] = true
			col := append(append([]int{}, base...), sub)
			if FormatOID(col) != m.OID {
				t.Fatalf("%s.%d 的 OID 应为 %s 实为 %s", tb.Base, sub, FormatOID(col), m.OID)
			}
			// Hidden 辅助列(如 hrStorageUnits)不进 SubOrder 是设计行为, 跳过检查
			if m.Hidden {
				continue
			}
			if _, ok := tb.subOrderSeen()[m.Name]; !ok {
				t.Fatalf("子列 %s 不在 SubOrder 中(展示会丢)", m.Name)
			}
		}
	}
}

func (tb TableMib) subOrderSeen() map[string]bool {
	m := map[string]bool{}
	for _, n := range tb.SubOrder {
		m[n] = true
	}
	return m
}
