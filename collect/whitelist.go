// whitelist.go 采集 IP 白名单。
//
// 语义: 配置了白名单(非空)时, 只有目标 IP 落在白名单内才允许发起采集;
// 白名单为空 = 不限制。这是"采集限速"之外的第二道闸 —— 限速防"太猛",
// 白名单防"打错地方"(误配一个公网网段持续发 SNMP/ping 流量是不可接受的)。
//
// 匹配口径: 支持单 IP 与 CIDR(10.0.0.0/8), 大小写/格式容错交给 netip 解析;
// 解析失败的条目跳过并记日志(不让一条坏配置废掉整个白名单)。
package collect

import (
	"net/netip"
	"strings"
)

// Whitelist 编译后的 IP 白名单(空 = 放行一切)。
type Whitelist struct {
	addrs  []netip.Addr
	prefixes []netip.Prefix
}

// NewWhitelist 编译白名单条目; 返回 (白名单, 被忽略的坏条目)。
func NewWhitelist(entries []string) (*Whitelist, []string) {
	w := &Whitelist{}
	var bad []string
	for _, raw := range entries {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				bad = append(bad, raw)
				continue
			}
			w.prefixes = append(w.prefixes, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			bad = append(bad, raw)
			continue
		}
		w.addrs = append(w.addrs, a)
	}
	return w, bad
}

// Empty 是否无限制。
func (w *Whitelist) Empty() bool {
	return w == nil || (len(w.addrs) == 0 && len(w.prefixes) == 0)
}

// Allow 目标 IP 是否放行(无法解析的地址: 有白名单时拒绝, 无白名单时放行)。
func (w *Whitelist) Allow(ip string) bool {
	if w.Empty() {
		return true
	}
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	for _, x := range w.addrs {
		if x == a {
			return true
		}
	}
	for _, p := range w.prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
