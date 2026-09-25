// limiter.go 采集限速(全局令牌桶)。
//
// 为什么是"每秒 N 个采集动作"而不是"每目标限速": 扫描场景的限速对象是
// 目标网段(打目标), 而监控的采集动作本身就发往设备 —— 一个 SNMP walk 可能
// 是好几个 UDP 包, 再按包限速没有意义。按"采集动作"计数(每轮每任务一次)
// 是设备侧能感知的真实压力单位, 也最直观(页面上写"每秒 10 次采集")。
//
// 实现: 经典令牌桶, 容量 = rate(突发不超过每秒额度), 每毫秒线性补充。
// 取不到令牌时调用方直接跳过本轮(顺延到下个 tick), 不阻塞 —— 阻塞会让
// 一轮拖住下一轮, 与"周期采集"语义冲突。
package collect

import (
	"sync"
	"time"
)

// Limiter 全局采集限速器(并发安全)。
type Limiter struct {
	mu     sync.Mutex
	rate   float64 // 每秒补充的令牌数
	bucket float64 // 桶容量
	tokens float64
	last   time.Time
}

// NewLimiter 创建限速器(rate<=0 按 1 处理, 避免除零/全卡死)。
func NewLimiter(rate int) *Limiter {
	if rate < 1 {
		rate = 1
	}
	r := float64(rate)
	return &Limiter{rate: r, bucket: r, tokens: r, last: time.Now()}
}

// SetRate 热更新速率(配置变更后调用, 不清空已积累令牌)。
func (l *Limiter) SetRate(rate int) {
	if rate < 1 {
		rate = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	r := float64(rate)
	l.rate = r
	l.bucket = r
	if l.tokens > r {
		l.tokens = r
	}
}

// TryTake 尝试取一个令牌; 取不到立即返回 false(不阻塞)。
func (l *Limiter) TryTake() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens += elapsed * l.rate
	if l.tokens > l.bucket {
		l.tokens = l.bucket
	}
	if l.tokens < 1 {
		return false
	}
	l.tokens--
	return true
}
