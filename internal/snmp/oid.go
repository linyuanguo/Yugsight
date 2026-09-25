// oid.go OID(Object Identifier)解析、格式化、BER 编码与比较。
//
// OID 是一串弧(如 1.3.6.1.2.1.1.1)。BER 编码规则: 前两弧合并为
// 40*arc1+arc2 后按 base-128 编码, 其余弧各自 base-128(每字节高
// 位为续位)。这段编码错了整个 SNMP 互通就废, 故单测里用经典
// sysDescr 请求的完整字节序列做锚点(见 snmp_test.go)。
package snmp

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ParseOID 解析 "1.3.6.1.2.1.1.1" 为弧序列; 非法输入返回错误
// (调用方按"OID 无效"降级, 不 panic)。
func ParseOID(s string) ([]int, error) {
	parts := strings.Split(strings.TrimSpace(s), ".")
	out := make([]int, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("OID %q 非法: 弧 %q 非数字", s, p)
		}
		out[i] = v
	}
	if len(out) < 2 || out[0] > 2 {
		return nil, fmt.Errorf("OID %q 非法(弧数不足或首弧>2)", s)
	}
	return out, nil
}

// FormatOID 弧序列格式化回字符串。
func FormatOID(oid []int) string {
	parts := make([]string, len(oid))
	for i, v := range oid {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ".")
}

// EncodeOID 弧序列 → BER 内容字节(不含 tag/length)。
func EncodeOID(oid []int) []byte {
	if len(oid) < 2 {
		return nil
	}
	var b []byte
	// 首两弧合并: SNMP 的 OID 首弧∈{0,1,2}、第二弧<128, 合并恒合法。
	b = appendBase128(b, 40*oid[0]+oid[1])
	for _, v := range oid[2:] {
		b = appendBase128(b, v)
	}
	return b
}

// appendBase128 非负整数的 base-128 大端编码。
func appendBase128(b []byte, v int) []byte {
	if v == 0 {
		return append(b, 0)
	}
	var buf [10]byte
	n := 0
	for v > 0 {
		buf[n] = byte(v & 0x7f)
		n++
		v >>= 7
	}
	for i := n - 1; i >= 0; i-- {
		x := buf[i]
		if i > 0 {
			x |= 0x80
		}
		b = append(b, x)
	}
	return b
}

// DecodeOID BER 内容 → 弧序列。
func DecodeOID(b []byte) ([]int, error) {
	if len(b) < 2 {
		return nil, errors.New("OID 内容过短")
	}
	v, rest, err := readBase128(b)
	if err != nil {
		return nil, err
	}
	if v > 40*2+127 {
		return nil, fmt.Errorf("OID 首两弧非法: %d", v)
	}
	oid := []int{v / 40, v % 40}
	for len(rest) > 0 {
		var ev int
		ev, rest, err = readBase128(rest)
		if err != nil {
			return nil, err
		}
		oid = append(oid, ev)
	}
	return oid, nil
}

// readBase128 读取一个 base-128 整数(最多 5 字节, 32 位上限)。
func readBase128(b []byte) (int, []byte, error) {
	v := 0
	for i, x := range b {
		v = (v << 7) | int(x&0x7f)
		if x&0x80 == 0 {
			if i >= 5 {
				return 0, nil, errors.New("OID 弧超 32 位")
			}
			return v, b[i+1:], nil
		}
	}
	return 0, nil, errors.New("OID base-128 续位未闭合")
}

// CompareOID 逐弧字典序比较(短前缀在前), 返回 -1/0/1。
// GETBULK 走表时靠它判断"是否走出本表"。
func CompareOID(a, b []int) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

// IsExtension 判断 child 是否为 base 的扩展(base 是 child 的前缀)。
// 表 1.3.6.1.2.1.2.2.1 的实例 1.3.6.1.2.1.2.2.1.1.5 是扩展,
// 而相邻表 1.3.6.1.2.1.2.2.10(ifXTable)不是——这个区分决定
// walk 何时停, 写错会把相邻表的数据并进本表。
func IsExtension(base, child []int) bool {
	if len(child) < len(base) {
		return false
	}
	for i := 0; i < len(base); i++ {
		if base[i] != child[i] {
			return false
		}
	}
	return true
}
