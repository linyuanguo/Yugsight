// ber.go 最小 BER(基本编码规则)编解码 —— 只覆盖 SNMP 用得到的子集。
//
// 为什么不直接用 encoding/asn1: 它的结构体标签绑定模型无法表达 SNMP
// varbind 的"任意 tag + 任意内容"形态, 且 SNMP 的 APPLICATION 类值
// (Counter32/Gauge32/TimeTicks 等)需要专属 tag 语义。自己实现约百行,
// 完整覆盖 GET/GETBULK, 无第三方依赖(项目硬约束)。
package snmp

import (
	"encoding/hex"
	"errors"
	"fmt"
)

// tlv 一个解析后的 TLV(tag-length-value)。
type tlv struct {
	tag     int
	content []byte
}

// encodeLen 编码长度字段(短格式 <128, 长格式否则)。
func encodeLen(n int) []byte {
	if n < 0x80 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

// tlvBytes 编码 TLV。
func tlvBytes(tag int, content []byte) []byte {
	out := append([]byte{byte(tag)}, encodeLen(len(content))...)
	return append(out, content...)
}

// decodeLen 解长度字段, 返回长度值与消耗字节数。
func decodeLen(b []byte) (int, int, error) {
	if len(b) == 0 {
		return 0, 0, errors.New("BER 长度缺失")
	}
	n := int(b[0])
	if n < 0x80 {
		return n, 1, nil
	}
	m := n & 0x7f
	// 长度本身超过 4 字节 = 报文 >16MB, SNMP 场景不可能, 直接拒绝防死循环。
	if m == 0 || m > 4 || len(b) < 1+m {
		return 0, 0, fmt.Errorf("BER 长度格式非法: 0x%02x", b[0])
	}
	v := 0
	for i := 1; i <= m; i++ {
		v = v<<8 | int(b[i])
	}
	return v, 1 + m, nil
}

// decodeTLV 解析 b 头部一个 TLV, 返回余下字节。
func decodeTLV(b []byte) (tlv, []byte, error) {
	if len(b) < 2 {
		return tlv{}, nil, errors.New("BER TLV 过短")
	}
	tag := int(b[0])
	l, n, err := decodeLen(b[1:])
	if err != nil {
		return tlv{}, nil, err
	}
	if len(b) < 1+n+l {
		return tlv{}, nil, fmt.Errorf("BER TLV 截断: 需 %d 字节仅有 %d", 1+n+l, len(b))
	}
	return tlv{tag: tag, content: b[1+n : 1+n+l]}, b[1+n+l:], nil
}

// decodeInt 大端有符号整数(两字节补码)。SNMP 的 errStatus/reqid 都是小值,
// 但响应里的 INTEGER 值(如 ifIndex)按通用规则解码, 负值也正确处理。
func decodeInt(b []byte) (int64, error) {
	if len(b) == 0 || len(b) > 8 {
		return 0, fmt.Errorf("INTEGER 长度非法: %d", len(b))
	}
	var v int64 = -1 // 最高位为 1 时符号扩展
	if b[0]&0x80 == 0 {
		v = 0
	}
	for _, x := range b {
		v = v<<8 | int64(x)
	}
	return v, nil
}

// formatOctets 展示层格式化: 6 字节当 MAC, 可打印当字符串, 否则 hex。
func formatOctets(b []byte) string {
	if len(b) == 6 {
		return macString(b)
	}
	printable := len(b) > 0
	for _, x := range b {
		if x < 0x20 || x >= 0x7f {
			printable = false
			break
		}
	}
	if printable {
		return string(b)
	}
	return hex.EncodeToString(b)
}

// macString 手写 MAC 格式化(a:b:c:d:e:f)。
func macString(b []byte) string {
	const hexd = "0123456789abcdef"
	out := make([]byte, 0, 17)
	for i, x := range b {
		if i > 0 {
			out = append(out, ':')
		}
		out = append(out, hexd[x>>4], hexd[x&0x0f])
	}
	return string(out)
}

