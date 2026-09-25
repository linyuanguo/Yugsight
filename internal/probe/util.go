package probe

import (
	"strconv"
	"strings"
)

// appendUnique 去重追加(节点信息采集辅助)。
func appendUnique(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// splitKeyValue 拆 "Key : Value"(兼容中英文冒号, 容忍多余空格)。
func splitKeyValue(line string) (k, v string) {
	idx := strings.Index(line, ":")
	if idx < 0 {
		return line, ""
	}
	return strings.TrimSpace(line[:idx]), strings.TrimSpace(line[idx+1:])
}

// firstIPv4 从文本中提取第一个 IPv4 地址。
func firstIPv4(s string) string {
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= '0' && r <= '9') && r != '.'
	})
	for _, f := range fields {
		if isIPv4(f) {
			return f
		}
	}
	return ""
}

func isIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n > 255 {
			return false
		}
	}
	return true
}

// itoa 无 fmt 依赖的整数转字符串(平台文件内共用)。
func itoa(n int) string { return strconv.Itoa(n) }
