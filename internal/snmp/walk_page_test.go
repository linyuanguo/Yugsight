// walk_page_test.go 用本机回环 UDP 假设备守住 Walk 分页契约。
//
// 真机锐捷实测踩出两个坑, 本文件是它们的回归防线:
//  1. 游标必须推进 —— 下一页请求要用"上页最后实例"当起点, 否则设备每页
//     都回同一批, 被 floor 判断跳空后误判"无数据"(实测 ifTable 全空);
//  2. non-repeaters 必须为 0 —— 传 1 时设备按 GETNEXT 只回 1 条
//     (实测 walk 只拿到 ifIndex.1 一条就停)。
// 假设备按页应答并记录每页请求的起始 OID 与 non-repeater, 直接断言这两个
// 契约; 回环不可用时 Skip(由真机联调覆盖)。
package snmp

import (
	"context"
	"net"
	"testing"
	"time"
)

// pageScript 一页应答脚本: 收到请求后按脚本返回 varbind 列表。
type pageScript struct {
	// oids 本页返回的 OID; 传 endOfMibView=true 时返回异常值而非数据
	oids         []string
	endOfMibView bool
	outOfTable   bool // 返回一个表前缀之外的 OID, 触发"走出本表"
}

// fakeDevice 回环 UDP 假 SNMP 设备: 记录每页请求, 按脚本应答。
type fakeDevice struct {
	pages   []pageScript
	reqOIDs []string // 每页请求的起始 OID(游标推进契约的证据)
	nonReps []int    // 每页请求的 non-repeaters(nonRep=0 契约的证据)
}

// startFakeDevice 启动假设备, 返回客户端与设备句柄。
func startFakeDevice(t *testing.T, d *fakeDevice, community string) *Client {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("回环 UDP 不可用, 由真机联调覆盖: %v", err)
	}
	t.Cleanup(func() { pc.Close() })

	go func() {
		buf := make([]byte, 4096)
		for i := 0; ; i++ {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			// 只处理前 len(pages) 页, 之后静默(客户端超时自然收尾)
			if i >= len(d.pages) {
				continue
			}
			script := d.pages[i]
			reqOID, nonRep := parseBulkRequest(buf[:n])
			d.reqOIDs = append(d.reqOIDs, reqOID)
			d.nonReps = append(d.nonReps, nonRep)

			var resp []byte
			switch {
			case script.endOfMibView:
				resp = buildResponse(community, []Varbind{{OID: script.oids[0], Type: "endofmibview"}})
			case script.outOfTable:
				resp = buildResponse(community, []Varbind{{OID: "1.3.6.1.99.1.1", Type: "integer", Value: "1"}})
			default:
				vbs := make([]Varbind, 0, len(script.oids))
				for _, o := range script.oids {
					vbs = append(vbs, Varbind{OID: o, Type: "integer", Value: "1"})
				}
				resp = buildResponse(community, vbs)
			}
			pc.WriteTo(resp, addr)
		}
	}()

	c := NewClient(pc.LocalAddr().String(), community, 2*time.Second)
	return c
}

// parseBulkRequest 从 GETBULK 请求字节提取第一个 varbind OID 与
// non-repeaters 字段(测试专用轻量解析, 不复用面向 getResponse 的
// parseResponse)。
func parseBulkRequest(b []byte) (string, int) {
	outer, _, err := decodeTLV(b)
	if err != nil || outer.tag != 0x30 {
		return "", -1
	}
	_, rest2, _ := decodeTLV(outer.content)    // version
	_, rest3, _ := decodeTLV(rest2)            // community
	pdu, _, err := decodeTLV(rest3)            // PDU(0xa5)
	if err != nil || pdu.tag != pduTagGetBulk {
		return "", -1
	}
	_, r1, _ := decodeTLV(pdu.content)          // reqid
	nonTLV, r2, _ := decodeTLV(r1)              // non-repeaters
	nonRep64, _ := decodeInt(nonTLV.content)
	nonRep := int(nonRep64)
	_, r3, _ := decodeTLV(r2)                   // max-repetitions
	vbTLV, _, err := decodeTLV(r3)
	if err != nil || vbTLV.tag != 0x30 {
		return "", nonRep
	}
	pair, _, err := decodeTLV(vbTLV.content)
	if err != nil || pair.tag != 0x30 {
		return "", nonRep
	}
	oidTLV, _, err := decodeTLV(pair.content)
	if err != nil || oidTLV.tag != tagOID {
		return "", nonRep
	}
	arc, err := DecodeOID(oidTLV.content)
	if err != nil {
		return "", nonRep
	}
	return FormatOID(arc), nonRep
}

// buildResponse 构造 v2c getResponse(varbind 值直接给 Varbind)。
func buildResponse(community string, vbs []Varbind) []byte {
	content := make([]byte, 0, 128)
	for _, v := range vbs {
		arc, err := ParseOID(v.OID)
		if err != nil {
			continue
		}
		var val []byte
		switch v.Type {
		case "endofmibview":
			val = tlvBytes(0x82, nil)
		case "integer":
			val = tlvBytes(tagInteger, []byte{1})
		default:
			val = tlvBytes(tagNull, nil)
		}
		content = append(content, seq(tlvBytes(tagOID, EncodeOID(arc)), val)...)
	}
	return seq(
		intField(1),
		tlvBytes(tagOctetStr, []byte(community)),
		pduTLV(pduTagResponse, intField(1), intField(0), intField(0), seq(content)),
	)
}

// TestWalkPagedCursor 锁定分页两契约: 游标推进(页 2 起点必须是页 1 末条
// 实例)+ non-repeaters=0; 数据按页拼接收齐且正常终止。
func TestWalkPagedCursor(t *testing.T) {
	base := "1.3.6.1.2.1.2.2.1"
	d := &fakeDevice{pages: []pageScript{
		{oids: []string{base + ".1.1", base + ".1.2", base + ".1.3"}},
		{oids: []string{base + ".2.1"}},
		{oids: []string{base + ".1.3"}, endOfMibView: true},
	}}
	c := startFakeDevice(t, d, "pub")

	vbs, err := c.Walk(context.Background(), base, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) != 4 {
		t.Fatalf("应收齐 4 条(页 1 三条 + 页 2 一条), got %d", len(vbs))
	}
	if len(d.reqOIDs) != 3 {
		t.Fatalf("应有 3 页请求, got %d", len(d.reqOIDs))
	}
	// 契约 1: 页 2 请求起点 = 页 1 末条实例(游标推进)
	if d.reqOIDs[1] != base+".1.3" {
		t.Fatalf("页 2 起点应为页 1 末条 %s, 实为 %s", base+".1.3", d.reqOIDs[1])
	}
	// 契约 2: non-repeaters 必须为 0(传 1 设备只回 1 条)
	for i, nr := range d.nonReps {
		if nr != 0 {
			t.Fatalf("第 %d 页 non-repeaters 应为 0, 实为 %d", i+1, nr)
		}
	}
}

// TestWalkOutOfTable: 第一页就返回表前缀之外的 OID 时, walk 应立即
// 空收(设备不支持该表的场景, 不能带出邻表数据)。
func TestWalkOutOfTable(t *testing.T) {
	base := "1.3.6.1.2.1.25.3.3.1"
	d := &fakeDevice{pages: []pageScript{{outOfTable: true}}}
	c := startFakeDevice(t, d, "pub")

	vbs, err := c.Walk(context.Background(), base, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) != 0 {
		t.Fatalf("走出表前缀应空收, got %d 条", len(vbs))
	}
}

// TestWalkEndOfMibView: 表尾用 v2 异常值而非 errStatus 标记时(个别实现
// 如此), walk 也应正常终止, 且异常值本身不入结果。
func TestWalkEndOfMibView(t *testing.T) {
	base := "1.3.6.1.2.1.2.2.1"
	d := &fakeDevice{pages: []pageScript{
		{oids: []string{base + ".1.1", base + ".1.2"}},
		{oids: []string{base + ".1.2"}, endOfMibView: true},
	}}
	c := startFakeDevice(t, d, "pub")

	vbs, err := c.Walk(context.Background(), base, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(vbs) != 2 {
		t.Fatalf("应收 2 条后正常终止, got %d", len(vbs))
	}
	for _, v := range vbs {
		if isNoSuchType(v.Type) {
			t.Fatalf("异常值不应入结果: %s %s", v.OID, v.Type)
		}
	}
}
