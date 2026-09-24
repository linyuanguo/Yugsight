package weakpass

import (
	"net/netip"
	"strings"
	"time"
)

// ===== 白名单 =====

// allowIn 判定 host 是否落在 CIDR/IP 白名单内, 返回空串表示放行, 否则返回原因。
//
// 用 netip 而非 net.IP: netip.Prefix.Contains 是值比较, 无分配、无 nil 陷阱,
// 且天然区分 IPv4/IPv6(不会把 IPv4 映射进 IPv6 段导致误放行)。
func allowIn(host string, cidrs []string) string {
	addr, err := netip.ParseAddr(strings.TrimSpace(host))
	if err != nil {
		return "目标不是合法 IP: " + host
	}
	for _, c := range cidrs {
		c = strings.TrimSpace(c)
		if c == "" {
			continue
		}
		if !strings.Contains(c, "/") {
			// 单 IP 写法: 补成 /32(或 /128), 让用户不必记 CIDR 语法
			if addr.Is4() {
				c += "/32"
			} else {
				c += "/128"
			}
		}
		p, err := netip.ParsePrefix(c)
		if err != nil {
			continue // 白名单里某条写错不阻断其余条目, 但也不放行(继续看下一条)
		}
		if p.Contains(addr) {
			return ""
		}
	}
	return "目标 " + host + " 不在白名单内"
}

// ===== 令牌桶 =====

// bucket 单目标限流器: 令牌桶(速率) + 累计次数上限。
//
// 两个维度刻意分开: 只限速不限量, 长时间跑会累积成几万次失败登录;
// 只限量不限速, 会在几秒内打满上限, 触发目标侧风控。两者都要。
type bucket struct {
	tokens float64
	used   int
	last   time.Time
}

// take 取一个令牌。
//
// 返回 (需等待时长, 拒绝原因):
//
//	("", 0)          放行(已扣除令牌)
//	(wait, "rate")   令牌不足, 需等 wait
//	(0, "maxtry")    已达该目标尝试上限
func (b *bucket) take(now time.Time, rate float64, maxTry int) (time.Duration, string) {
	if maxTry > 0 && b.used >= maxTry {
		return 0, "maxtry"
	}
	if rate <= 0 {
		// 不限速(仅由 maxTry 兜底)
		b.used++
		return 0, ""
	}
	if b.last.IsZero() {
		b.last, b.tokens = now, 1
	}
	// 令牌补充: 容量固定 1(朴素令牌桶, 不做突发), 速率 rate 个/秒
	cap := 1.0
	if b.tokens < cap {
		elapsed := now.Sub(b.last).Seconds()
		b.tokens += elapsed * rate
		if b.tokens > cap {
			b.tokens = cap
		}
	}
	b.last = now
	if b.tokens < 1 {
		need := (1 - b.tokens) / rate
		if need < 0 {
			need = 0
		}
		return time.Duration(need * float64(time.Second)), "rate"
	}
	b.tokens -= 1
	b.used++
	return 0, ""
}

// take 取当前目标的令牌(并发安全; 桶按目标键懒创建)。
func (e *Engine) take(key string) (time.Duration, string) {
	now := e.timeNow()
	e.mu.Lock()
	defer e.mu.Unlock()
	b, ok := e.buckets[key]
	if !ok {
		b = &bucket{last: now, tokens: 1}
		e.buckets[key] = b
	}
	return b.take(now, e.cfg.Rate, e.cfg.MaxTry)
}
