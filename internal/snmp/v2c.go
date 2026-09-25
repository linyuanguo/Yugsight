// v2c.go SNMPv2c 客户端: GET / GETBULK / 表 walk。纯标准库(UDP + 本包 BER)。
//
// 为什么只做 v2c: v2c 是社区串鉴权(无加密), 标准库即可完整实现; v3 的 USM
// 需要 HMAC-SHA/AES 全套, 内网监控场景 v2c 足够, 待有合规要求时再在本包
// 内加 v3.go(可复用 ber.go/oid.go)。
//
// 错误语义: 设备不可达/超时返回 error; 设备应答了但"没有这个 OID"
// (noSuchObject/noSuchInstance/endOfMibView) 返回 errStatus 非 0 而不
// 返回 error —— 监控场景要区分"设备哑了"和"设备不支持该指标", 两者的
// 运维动作完全不同。
package snmp

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

// SNMP 值 tag(SMI 定义)。UNIVERSAL 类 + SNMP 专用 APPLICATION 类
// (0x40|n)。真机锐捷实测踩坑: TimeTicks 真值是 0x43 而非 0x2b——0x2b
// 只是十进制 43 的十六进制巧合, 之前按 0x2b 匹配导致 sysUpTime 全部
// 无法解码; Gauge32=0x42/Counter64=0x46 混淆会让接口带宽/流量丢失。
const (
	tagInteger   = 0x02 // UNIVERSAL 2
	tagOctetStr  = 0x04 // UNIVERSAL 4
	tagNull      = 0x05 // UNIVERSAL 5
	tagOID       = 0x06 // UNIVERSAL 6
	tagIPAddress = 0x40 // [APPLICATION 0] IMPLICIT OCTET STRING(4 字节)
	tagCounter32 = 0x41 // [APPLICATION 1] IMPLICIT INTEGER
	tagGauge32   = 0x42 // [APPLICATION 2] IMPLICIT INTEGER
	tagTimeTicks = 0x43 // [APPLICATION 3] IMPLICIT INTEGER(百分秒)
	tagOpaque    = 0x44 // [APPLICATION 4] IMPLICIT OCTET STRING
	tagCounter64 = 0x46 // [APPLICATION 6] IMPLICIT INTEGER64
)

// PDU 类型(RFC 3416 的上下文类 tag, 不是 UNIVERSAL 16=0x30 ——
// 用 0x30 包 PDU 多数设备会拒收, 是实测踩过的互通性坑):
const (
	pduTagGet      = 0xa0 // GetRequest     [0] IMPLICIT PDU
	pduTagResponse = 0xa2 // Response       [2]
	pduTagGetBulk  = 0xa5 // GetBulkRequest [5]
)

// errNoError 等 error-status 值(RFC 3416)。
const (
	errNoError      = 0
	errNoSuchObject = 5
	errNoSuchInst   = 6
	errEndOfMibView = 7
)

// Varbind 一个 OID-值对(响应的最小单元)。
type Varbind struct {
	OID   string
	Type  string // integer/counter32/counter64/gauge32/timeticks/octetstring/oid/ipaddress/null/unknown
	Value string // 人类可读文本
	Num   int64  // 数值型时的数值
}

// Client SNMP 客户端(v2c 社区串 / v3 USM 共用)。
type Client struct {
	Addr      string // host:port
	Community string
	Timeout   time.Duration

	// V3 非空 = 走 SNMPv3(USM 鉴权/加密), 见 v3.go; 为 nil 即 v2c 社区串模式。
	// 刻意不新增 v3 专用客户端类型: 上层的采集逻辑(Get/GetBulk/Walk)与版本无关,
	// 两个类型会导致调用方分支化且两份实现必然漂移。
	V3 *V3Config

	v3Eng *v3Engine // v3 引擎参数缓存(发现一次后复用, 见 ensureV3Engine)
	v3Mu  sync.Mutex

	reqID atomic.Uint32
}

// NewClient 创建客户端; Addr 无端口时自动补 :161。
func NewClient(addr, community string, timeout time.Duration) *Client {
	if _, _, err := net.SplitHostPort(addr); err != nil {
		addr = net.JoinHostPort(addr, "161")
	}
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	return &Client{Addr: addr, Community: community, Timeout: timeout}
}

// errStatusText 错误状态 → 可读文本(日志/前端展示用)。
func errStatusText(s int) string {
	switch s {
	case errNoError:
		return ""
	case errNoSuchObject:
		return "noSuchObject"
	case errNoSuchInst:
		return "noSuchInstance"
	case errEndOfMibView:
		return "endOfMibView"
	}
	return fmt.Sprintf("errStatus=%d", s)
}

// isNoSuchType 判断 varbind 是否为 v2 异常值(该 OID 无实例)。
func isNoSuchType(t string) bool {
	return t == "nosuchobject" || t == "nosuchinstance" || t == "endofmibview"
}

// decodeUintBe 大端无符号整数宽容解码。
// 真机锐捷实测踩坑: 设备给 TimeTicks 回了 5 字节(前导 0x00 填充的
// b4d52df5), 硬性要求 4 字节会把合法值拒之门外 —— BER 允许前导零,
// 只钳值域不限字节数(32 位型 ≤5 字节)。
func decodeUintBe(b []byte) (uint64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, fmt.Errorf("无符号整数长度异常: %d", len(b))
	}
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v, nil
}

func decodeUint32(b []byte) (uint64, error) {
	if len(b) > 5 { // 5 = 前导 0x00 + 4 字节有效
		return 0, fmt.Errorf("uint32 长度异常: %d", len(b))
	}
	v, err := decodeUintBe(b)
	if err != nil {
		return 0, err
	}
	if v > 0xffffffff {
		return 0, fmt.Errorf("uint32 值越界: %d", v)
	}
	return v, nil
}

// ---- 消息构造 ----

func seq(parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return tlvBytes(0x30, body)
}

func intField(v int) []byte {
	return tlvBytes(tagInteger, []byte{byte(v)})
}

func varbindSeq(oids []string) []byte {
	var inner []byte
	for _, o := range oids {
		arc, err := ParseOID(o)
		if err != nil {
			continue // 非法 OID 跳过; 上层 Collect 会把它标记为失败
		}
		inner = append(inner, seq(tlvBytes(tagOID, EncodeOID(arc)), tlvBytes(tagNull, nil))...)
	}
	return seq(inner)
}

// pduTLV 编码 context-specific constructed PDU(0xA0/0xA2/0xA5)。
func pduTLV(tag int, parts ...[]byte) []byte {
	var body []byte
	for _, p := range parts {
		body = append(body, p...)
	}
	return tlvBytes(tag, body)
}

func (c *Client) buildGet(oids []string) []byte {
	pdu := pduTLV(pduTagGet,
		intField(int(c.reqID.Add(1)%0x7fffffff)),
		intField(0), intField(0), // error-status, error-index
		varbindSeq(oids),
	)
	return c.buildMessage(pdu)
}

func (c *Client) buildGetBulk(oids []string, nonRep, maxRep int) []byte {
	pdu := pduTLV(pduTagGetBulk,
		intField(int(c.reqID.Add(1)%0x7fffffff)),
		intField(nonRep), intField(maxRep),
		varbindSeq(oids),
	)
	return c.buildMessage(pdu)
}

// buildMessage v2c 消息 = SEQ(version=1, community, PDU);
// V3 非空时改为 v3 消息(USM, 见 v3.go)。
func (c *Client) buildMessage(pdu []byte) []byte {
	if c.V3 != nil {
		return c.buildV3Message(pdu)
	}
	return seq(
		intField(1),
		tlvBytes(tagOctetStr, []byte(c.Community)),
		pdu,
	)
}

// parseResponseOf 按版本分发响应解析(v2c / v3 消息结构完全不同)。
func (c *Client) parseResponseOf(b []byte) ([]Varbind, int, error) {
	if c.V3 != nil {
		return c.parseV3Message(b)
	}
	return parseResponse(b, c.Community)
}

// ---- 传输 ----

func (c *Client) deadline(ctx context.Context) time.Time {
	d := time.Now().Add(c.Timeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(d) {
		d = dl
	}
	return d
}

// roundTrip 一次 UDP 往返(每请求一条新连接, 监控频率下无连接复用必要)。
func (c *Client) roundTrip(ctx context.Context, msg []byte) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	dl := c.deadline(ctx)
	conn, err := net.DialTimeout("udp", c.Addr, time.Until(dl))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetWriteDeadline(dl); err != nil {
		return nil, err
	}
	if _, err := conn.Write(msg); err != nil {
		return nil, err
	}
	if err := conn.SetReadDeadline(dl); err != nil {
		return nil, err
	}
	// SNMP 响应上限 ~65507 字节, 65536 缓冲足够。
	buf := make([]byte, 65536)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err // 超时表现为 timeout, 由调用方呈现"设备不可达"
	}
	return buf[:n], nil
}

// decodeValue 按 tag 解码一个值。APPLICATION 类 tag 各有专属编码,
// 不存在歧义, 不靠内容长度猜测(长度 4 的 OctetString 是合法字符串)。
func decodeValue(tag int, content []byte) (string, string, int64, error) {
	switch {
	case tag == tagInteger:
		v, err := decodeInt(content)
		if err != nil {
			return "", "", 0, err
		}
		return "integer", strconv.FormatInt(v, 10), v, nil
	case tag == tagOctetStr, tag == tagOpaque:
		t := "octetstring"
		if tag == tagOpaque {
			t = "opaque"
		}
		return t, formatOctets(content), 0, nil
	case tag == tagNull:
		return "null", "", 0, nil
	case tag == tagOID:
		arc, err := DecodeOID(content)
		if err != nil {
			return "", "", 0, err
		}
		return "oid", FormatOID(arc), 0, nil
	case tag == tagIPAddress:
		if len(content) != 4 {
			return "", "", 0, fmt.Errorf("ipaddress 长度异常: %d", len(content))
		}
		return "ipaddress", net.IP(content).String(), 0, nil
	case tag == tagCounter32:
		v, err := decodeUint32(content)
		if err != nil {
			return "", "", 0, err
		}
		return "counter32", strconv.FormatUint(v, 10), int64(v), nil
	case tag == tagGauge32:
		v, err := decodeUint32(content)
		if err != nil {
			return "", "", 0, err
		}
		return "gauge32", strconv.FormatUint(v, 10), int64(v), nil
	case tag == tagTimeTicks:
		v, err := decodeUint32(content)
		if err != nil {
			return "", "", 0, err
		}
		return "timeticks", strconv.FormatUint(v, 10), int64(v), nil
	case tag == tagCounter64:
		if len(content) == 0 || len(content) > 9 {
			return "", "", 0, fmt.Errorf("counter64 长度异常: %d", len(content))
		}
		v, err := decodeUintBe(content)
		if err != nil {
			return "", "", 0, err
		}
		return "counter64", strconv.FormatUint(v, 10), int64(v), nil
	case tag == 0x80:
		// v2 异常值是上下文类 tag(0x80/0x81/0x82), GET 批量请求里单个 OID
		// 不存在时 errStatus 仍为 0, 靠 varbind 值逐个标记。
		return "nosuchobject", "", 0, nil
	case tag == 0x81:
		return "nosuchinstance", "", 0, nil
	case tag == 0x82:
		return "endofmibview", "", 0, nil
	}
	// 未知 tag 不报错: 返回可读占位, 让整条响应还能用(降级不崩溃)。
	return "unknown", hex.EncodeToString(content), 0, nil
}

// parseResponse 解析 v2c getResponse; 返回 varbinds 与 error-status。
func parseResponse(b []byte, community string) ([]Varbind, int, error) {
	outer, rest, err := decodeTLV(b)
	if err != nil {
		return nil, 0, err
	}
	if outer.tag != 0x30 || len(rest) != 0 {
		return nil, 0, errors.New("SNMP 消息外层非 sequence")
	}
	f, rest2, err := decodeTLV(outer.content)
	if err != nil || f.tag != tagInteger || len(f.content) == 0 || f.content[0] != 1 {
		return nil, 0, errors.New("版本非 v2c(1)")
	}
	comm, rest3, err := decodeTLV(rest2)
	if err != nil || comm.tag != tagOctetStr {
		return nil, 0, errors.New("community 缺失")
	}
	if string(comm.content) != community {
		return nil, 0, fmt.Errorf("community 不匹配(设备回 %q)", string(comm.content))
	}
	pdu, _, err := decodeTLV(rest3)
	if err != nil {
		return nil, 0, errors.New("PDU 缺失")
	}
	// RFC 规定 getResponse tag=0xA2; 个别实现误用 0x30, 宽容接受。
	// PDU type 在 tag 里而非内容首字段 —— 内容首字段是 reqid。
	if pdu.tag != pduTagResponse && pdu.tag != 0x30 {
		return nil, 0, fmt.Errorf("PDU tag 0x%x 非 getResponse", pdu.tag)
	}
	return parsePDUVars(pdu)
}

// parsePDUVars 解析 PDU 内容(reqid / error-status / error-index / varbinds)。
//
// v2c 与 v3 只有"消息外壳"不同, PDU 内部结构完全一致 —— 抽出来共用, 避免
// 两份实现在 varbind 解码上漂移(v3 单测也要覆盖这段)。
func parsePDUVars(pdu tlv) ([]Varbind, int, error) {
	// PDU 内容: reqid, errstatus, errindex, varbinds
	reqTLV, r1, err := decodeTLV(pdu.content)
	if err != nil || reqTLV.tag != tagInteger {
		return nil, 0, errors.New("reqid 缺失")
	}
	stTLV, r2, err := decodeTLV(r1)
	if err != nil || stTLV.tag != tagInteger {
		return nil, 0, errors.New("error-status 缺失")
	}
	errStatus64, err := decodeInt(stTLV.content)
	if err != nil {
		return nil, 0, err
	}
	errStatus := int(errStatus64)
	idxTLV, r3, err := decodeTLV(r2)
	if err != nil || idxTLV.tag != tagInteger {
		return nil, 0, errors.New("error-index 缺失")
	}
	vbTLV, _, err := decodeTLV(r3)
	if err != nil || vbTLV.tag != 0x30 {
		return nil, 0, errors.New("varbinds 格式错误")
	}
	var out []Varbind
	restv := vbTLV.content
	for len(restv) > 0 {
		pair, r2, err := decodeTLV(restv)
		if err != nil || pair.tag != 0x30 {
			return out, errStatus, errors.New("varbind 格式错误(已取部分)")
		}
		oidTLV, pv, err := decodeTLV(pair.content)
		if err != nil || oidTLV.tag != tagOID {
			return out, errStatus, errors.New("varbind OID 格式错误(已取部分)")
		}
		arc, err := DecodeOID(oidTLV.content)
		if err != nil {
			return out, errStatus, err
		}
		valTLV, _, err := decodeTLV(pv)
		if err != nil {
			return out, errStatus, err
		}
		typ, text, num, err := decodeValue(valTLV.tag, valTLV.content)
		if err != nil {
			// 单条 varbind 解码失败不拖垮整批: 标 unknown 继续。
			out = append(out, Varbind{OID: FormatOID(arc), Type: "unknown", Value: hex.EncodeToString(valTLV.content)})
		} else {
			out = append(out, Varbind{OID: FormatOID(arc), Type: typ, Value: text, Num: num})
		}
		restv = r2
	}
	return out, errStatus, nil
}

// Get 批量取多个 OID 的值(一次往返)。
// 返回 varbinds(顺序对应请求)与 errStatus; 设备不可达/超时时 err 非 nil
// 且 errStatus 为 -1。
func (c *Client) Get(ctx context.Context, oids ...string) ([]Varbind, int, error) {
	if len(oids) == 0 {
		return nil, -1, errors.New("Get 需要至少一个 OID")
	}
	if err := c.ensureV3Engine(ctx); err != nil {
		return nil, -1, err
	}
	b, err := c.roundTrip(ctx, c.buildGet(oids))
	if err != nil {
		return nil, -1, err
	}
	vbs, errStatus, err := c.parseResponseOf(b)
	if err != nil {
		return nil, -1, err
	}
	return vbs, errStatus, nil
}

// GetBulk 一次 GETBULK(用于表走的单页)。
func (c *Client) GetBulk(ctx context.Context, starts []string, nonRep, maxRep int) ([]Varbind, int, error) {
	if len(starts) == 0 {
		return nil, -1, errors.New("GetBulk 需要至少一个起始 OID")
	}
	if maxRep <= 0 {
		maxRep = 50
	}
	if err := c.ensureV3Engine(ctx); err != nil {
		return nil, -1, err
	}
	b, err := c.roundTrip(ctx, c.buildGetBulk(starts, nonRep, maxRep))
	if err != nil {
		return nil, -1, err
	}
	vbs, errStatus, err := c.parseResponseOf(b)
	if err != nil {
		return nil, -1, err
	}
	return vbs, errStatus, nil
}

// Walk 遍历一张表(GETBULK 分页), 返回表内全部实例(OID 字典序 = 列优先)。
// 走出表前缀、errStatus 非 0 或收到 v2 异常值(endOfMibView 等)即停。
// 假定起始位是表基 OID(非实例)—— 本包唯一用法。
//
// 分页两个关键(真机锐捷实测踩坑):
//  1. 游标必须推进: 下一页从"上页最后一个实例"请求, 否则设备每页都回
//     同一批实例, 被防倒退判断全部跳过后误判"无数据";
//  2. non-repeaters 必须为 0: walk 的起始 varbind 是 repeater, 传 1 会让
//     设备按 GETNEXT 语义只回 1 条(max-repetitions 对 non-repeater 无效)。
func (c *Client) Walk(ctx context.Context, table string, maxRep int) ([]Varbind, error) {
	base, err := ParseOID(table)
	if err != nil {
		return nil, err
	}
	if maxRep <= 0 {
		maxRep = 50
	}
	// cursor: 本页请求起点(首页=表基, 之后=上页最后收集的实例);
	// floor: 防倒退基线(已收集的最后实例)。首页相同, 语义不同。
	cursor := FormatOID(base)
	floor := base
	var out []Varbind
	for {
		vbs, errStatus, err := c.GetBulk(ctx, []string{cursor}, 0, maxRep)
		if err != nil {
			return out, err
		}
		if errStatus != errNoError {
			return out, nil // noSuchObject/endOfMibView = 无此表或表已走完
		}
		advanced := false
		for _, vb := range vbs {
			if isNoSuchType(vb.Type) {
				return out, nil // 个别实现以异常值而非 errStatus 标表尾
			}
			arc, _ := ParseOID(vb.OID)
			if !IsExtension(base, arc) {
				return out, nil // 走出本表(进入相邻表, 如 ifTable→ifXTable)
			}
			// 未前进的重复(设备异常回包)跳过; 单调游标保证分页必然推进。
			if CompareOID(arc, floor) <= 0 {
				continue
			}
			out = append(out, vb)
			floor = arc
			cursor = vb.OID
			advanced = true
		}
		if !advanced {
			return out, nil // 本页无新数据, 防死循环
		}
	}
}
