package scheduler

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// ===== 网段发包限速 =====
//
// 目标(任务书): "限制每秒最大发包数量, 防止内网拥塞; 支持不同网段设置不同速率"。
//
// 粒度选择: **源网段**(不是目标网段)。原因:
//   - 拥塞发生在"本机出口 -> 目标网段"这条链路上, 真正被打爆的是**目标网段**
//     所在的那条链路/那台接入交换机;
//   - 但同一台中心/探针可能同时扫多个网段, 用目标网段限速更贴近"保护被扫网络"
//     这一诉求 —— 因此本实现按**目标网段**分桶(见 bucketKey), 配置项 naming 为
//     "网段"即可同时表达两侧语义, 用户按需填。
//
// 算法: 令牌桶(令牌按速率匀速补充, 桶容量 = 速率, 即允许 1 秒的突发)。
//
//	为什么不用固定窗口计数: 固定窗口在窗口边界会出现 2x 突发(前一窗口末尾
//	+ 后一窗口开头都打满), 对内网设备的瞬时压力是限速值的两倍, 与"防拥塞"
//	目标相悖。令牌桶天然平滑。
//
// 阻塞语义: 超过速率时 Wait 阻塞到下一个令牌可用, 而不是丢包 ——
// 扫描任务丢包会造成"端口被误判为关闭"这种静默错误结论, 比慢一点危险得多。
type RateLimiter struct {
	mu sync.Mutex

	// defaultRate 默认速率(包/秒); 0 表示不限速。
	defaultRate int
	// buckets 网段 -> 令牌桶。
	buckets map[string]*bucket
	// rules 用户配置的网段速率规则(按配置顺序匹配, 首个命中的生效)。
	rules []RateRule

	// now 时间源(测试注入用; 默认 time.Now)。
	now func() time.Time
}

// RateRule 一条网段限速规则。
//
// CIDR 支持三种写法:
//
//	"10.0.0.0/8"   标准网段, 按 netip 前缀包含匹配
//	"10.0.1.5"     单 IP, 视为 /32(或 /128)
//	"10.0.*"       通配前缀(`*` 只允许出现在末尾, 匹配 IP 字符串前缀)
type RateRule struct {
	CIDR string `json:"cidr"` // 网段
	Rate int    `json:"rate"` // 包/秒; <=0 表示该网段不限速(覆盖默认值)
}

type bucket struct {
	tokens float64   // 当前令牌数
	last   time.Time // 上次补充时间
	rate   int       // 速率(包/秒)
	burst  float64   // 桶容量
}

// NewRateLimiter 构造限速器。
//
//	defaultRate 全局默认速率(包/秒), 0 = 不限速;
//	rules 网段专属速率(优先于 defaultRate)。
func NewRateLimiter(defaultRate int, rules []RateRule) *RateLimiter {
	if defaultRate < 0 {
		defaultRate = 0
	}
	return &RateLimiter{
		defaultRate: defaultRate,
		buckets:     make(map[string]*bucket),
		rules:       rules,
		now:         time.Now,
	}
}

// SetTimeSource 注入时间源(仅供测试使用, 用于免等待验证令牌桶行为)。
func (l *RateLimiter) SetTimeSource(f func() time.Time) {
	if f == nil {
		return
	}
	l.mu.Lock()
	l.now = f
	l.mu.Unlock()
}

// Update 热更新限速配置(前端改配置后无需重启)。
//
// 已存在的桶只更新 rate/burst, **不重置 tokens** —— 重置等于给正在扫描的任务
// 发一波免费突发, 与"改配置是为了更平滑"的意图相反。
func (l *RateLimiter) Update(defaultRate int, rules []RateRule) {
	if defaultRate < 0 {
		defaultRate = 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.defaultRate = defaultRate
	l.rules = rules
	for k, b := range l.buckets {
		r := l.rateForLocked(k)
		b.rate = r
		b.burst = float64(r)
		if b.tokens > b.burst {
			b.tokens = b.burst
		}
	}
}

// RateFor 返回目标所属网段当前生效的速率(包/秒, 0 = 不限速)。供前端展示。
func (l *RateLimiter) RateFor(target string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.rateForLocked(bucketKey(target))
}

// rateForLocked 按规则表求某网段的速率(调用方须持锁)。
//
// 匹配优先级: 规则表按顺序首个命中 > defaultRate。
// 用户可把细网段写前面、粗网段写后面实现"例外优先"。
func (l *RateLimiter) rateForLocked(key string) int {
	for _, r := range l.rules {
		if matchCIDR(r.CIDR, key) {
			if r.Rate < 0 {
				return 0
			}
			return r.Rate
		}
	}
	return l.defaultRate
}

// Wait 在目标所属网段上申请 n 个发包令牌; 超速时阻塞直到令牌可用。
//
// ctx 取消时立即返回 context 错误 —— 任务被取消后不能还挂在这里等令牌,
// 否则取消响应会拖到令牌补充完成(大网段下可能是几秒)。
func (l *RateLimiter) Wait(ctxDone <-chan struct{}, target string, n int) error {
	if n <= 0 {
		n = 1
	}
	key := bucketKey(target)
	l.mu.Lock()
	rate := l.rateForLocked(key)
	if rate <= 0 { // 不限速: 直接放行, 不建桶(避免无意义内存增长)
		l.mu.Unlock()
		return nil
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: float64(rate), last: l.now(), rate: rate, burst: float64(rate)}
		l.buckets[key] = b
	}
	wait := l.takeLocked(b, float64(n))
	l.mu.Unlock()

	// 循环等待直到令牌真正到手。
	//
	// 为什么是循环而不是"等一次即可": 令牌是按经过时间补的, 若等待期间令牌被
	// **其它并发调用者**抢走, 定时器到点时桶里可能又是空的 —— 单次等待会让
	// 实际速率超过配置值(限速失效)。循环重取保证"拿到令牌才返回", 代价是
	// 可能多等几轮(每轮只有几十毫秒), 换来的是限速值真正被遵守。
	for wait > 0 {
		timer := time.NewTimer(wait)
		select {
		case <-timer.C:
		case <-ctxDone:
			// ctxDone 为 nil 时该分支永不触发(nil channel 阻塞语义),
			// 正是"无取消需求"时想要的行为。
			timer.Stop()
			return fmt.Errorf("scheduler: 限速等待被取消")
		}
		timer.Stop()
		l.mu.Lock()
		// 桶在配置热更新后可能被替换速率, 重新取一次(同时刷新 tokens/last)
		if b.rate <= 0 {
			l.mu.Unlock()
			return nil
		}
		wait = l.takeLocked(b, float64(n))
		l.mu.Unlock()
	}
	return nil
}

// takeLocked 尝试取 n 个令牌: 取到返回 0, 取不到返回"还需要等多久"(调用方须持锁)。
//
// 注意: 取不到时**不预扣令牌** —— 预扣会让多个并发等待者在同一时刻重复预扣,
// 令牌数变成负数, 后续突发被过度压制(表现为限速值远低于配置)。
func (l *RateLimiter) takeLocked(b *bucket, n float64) time.Duration {
	now := l.now()
	// 按经过时间补充令牌(上限 burst)
	if b.rate > 0 {
		elapsed := now.Sub(b.last).Seconds()
		if elapsed > 0 {
			b.tokens += elapsed * float64(b.rate)
			if b.tokens > b.burst {
				b.tokens = b.burst
			}
			b.last = now
		}
	}
	if b.tokens >= n {
		b.tokens -= n
		return 0
	}
	need := n - b.tokens
	if b.rate <= 0 {
		return 0
	}
	return time.Duration(need / float64(b.rate) * float64(time.Second))
}

// Stats 各网段当前速率快照(前端展示 + 排障)。
func (l *RateLimiter) Stats() []RateStat {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]RateStat, 0, len(l.buckets)+len(l.rules))
	seen := map[string]bool{}
	for _, r := range l.rules {
		out = append(out, RateStat{Net: r.CIDR, Rate: l.rateForLocked(bucketKey(r.CIDR))})
		seen[r.CIDR] = true
	}
	for k, b := range l.buckets {
		if seen[k] {
			continue
		}
		out = append(out, RateStat{Net: k, Rate: b.rate, Tokens: b.tokens})
	}
	return out
}

// RateStat 单个网段的限速快照。
type RateStat struct {
	Net    string  `json:"net"`
	Rate   int     `json:"rate"`   // 包/秒, 0 = 不限速
	Tokens float64 `json:"tokens"` // 当前可用令牌(仅活动中网段)
}

// ===== 网段归一与匹配 =====

// bucketKey 把目标(IP / CIDR / URL / host:port)归一为限速桶键(纯 IP)。
//
// 归一的意义: "10.0.0.5" / "10.0.0.5:8080" / "http://10.0.0.5/x" / "10.0.0.0/24"
// 在用户眼里是同一个网段的扫描, 若按字符串分桶会各自建桶, 每个桶都按满速率
// 放行 —— 限速形同虚设(这是限速器最常见的实现缺陷)。
func bucketKey(target string) string {
	s := strings.TrimSpace(target)
	// 剥 scheme
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// 剥路径
	if i := strings.IndexAny(s, "/?"); i >= 0 {
		// 注意: CIDR 的 "/" 要保留, 只有"斜杠后不是纯数字"才算路径
		if !isCIDRSuffix(s[i+1:]) {
			s = s[:i]
		}
	}
	// 剥端口(IPv6 带方括号的单独处理)
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i > 0 {
			s = s[1:i]
			return s
		}
	}
	if i := strings.LastIndex(s, ":"); i > 0 && !strings.Contains(s, "/") {
		if _, err := net.LookupPort("tcp", s[i+1:]); err != nil {
			if isAllDigits(s[i+1:]) {
				s = s[:i]
			}
		} else {
			s = s[:i]
		}
	}
	return s
}

// isCIDRSuffix 判断斜杠后是否为 CIDR 前缀长度(纯数字且 <=128)。
func isCIDRSuffix(s string) bool {
	if s == "" || !isAllDigits(s) {
		return false
	}
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
		if n > 128 {
			return false
		}
	}
	return true
}

func isAllDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// matchCIDR 判断 ip(纯 IP 或 CIDR 串)是否属于 rule 描述的网段。
//
// 支持标准 CIDR / 单 IP / 末尾通配前缀三种写法(见 RateRule 注释)。
func matchCIDR(rule, ip string) bool {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return false
	}
	// 通配前缀: "10.0.*" —— 只允许出现在末尾, 按字符串前缀匹配
	if strings.HasSuffix(rule, "*") {
		prefix := strings.TrimSuffix(rule, "*")
		return strings.HasPrefix(ip, prefix)
	}
	// 单 IP 精确匹配(规则写单 IP 时不该匹配整个网段)
	if !strings.Contains(rule, "/") {
		return sameIP(rule, ip)
	}
	_, ipnet, err := net.ParseCIDR(rule)
	if err != nil {
		return false
	}
	target := ip
	// 目标是 CIDR 时取其网络号参与包含判断
	if strings.Contains(target, "/") {
		_, tn, terr := net.ParseCIDR(target)
		if terr != nil {
			return false
		}
		target = tn.IP.String()
	}
	pip := net.ParseIP(target)
	if pip == nil {
		// 目标不是 IP(如域名): 退化为前缀字符串匹配, 保证"example.com" 类的
		// 规则仍可写, 但明确不做 DNS 解析(限速器不应引入网络依赖)。
		return strings.HasPrefix(target, strings.TrimSuffix(rule, "/"))
	}
	return ipnet.Contains(pip)
}

// sameIP IP 等价判断(容忍 IPv4-mapped IPv6 与大小写差异)。
func sameIP(a, b string) bool {
	pa, pb := net.ParseIP(strings.TrimSpace(a)), net.ParseIP(strings.TrimSpace(b))
	if pa == nil || pb == nil {
		return strings.EqualFold(strings.TrimSpace(a), strings.TrimSpace(b))
	}
	return pa.Equal(pb)
}
