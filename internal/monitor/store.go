// store.go 周期采集引擎: ticker 驱动轮次, 内存保存最新/上一轮样本(速率计算用)。
//
// 为什么不进 scheduler: scheduler 是一次性队列调度(任务终态不重排、槽位与限速
// 为扫描设计), SNMP 轮询每 N 秒重复一次, 语义完全不同 —— 独立循环最干净,
// 且轮询不会占用扫描并发槽位饿死真实任务。
//
// 包边界: 不 import db。历史落库经注入的 WriteHistory 函数(装配层给),
// 配置经注入的 ReadConfig 每轮重读 —— UI 上改目标/间隔, 一轮之内生效, 无需重启。
package monitor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// WriteHistory 一轮样本落库(装配层注入)。
type WriteHistory func(samples []*Sample)

// RoundHook 一轮结束回调(装配层接 SSE 广播)。
type RoundHook func(r *RoundResult)

// Monitor 周期采集引擎(并发安全)。
type Monitor struct {
	mu      sync.RWMutex
	cfg     Config
	latest  map[string]*Sample // targetID → 最新样本
	prev    map[string]*Sample // targetID → 上一轮(速率差分用)
	last    *RoundResult
	running bool
	stopCh  chan struct{}

	readCfg func() Config
	write   WriteHistory
	hook    RoundHook
	logf    func(string)
}

// New 创建引擎(cfg 是启动时的配置快照, 之后以 readCfg 每轮重读为准)。
func New(cfg Config, readCfg func() Config, write WriteHistory) *Monitor {
	return &Monitor{
		cfg:     cfg,
		latest:  map[string]*Sample{},
		prev:    map[string]*Sample{},
		stopCh:  make(chan struct{}),
		readCfg: readCfg,
		write:   write,
	}
}

// SetLogger 日志函数(不传则静默)。
func (m *Monitor) SetLogger(f func(string)) { m.logf = f }

// SetHook 轮次结束钩子。
func (m *Monitor) SetHook(h RoundHook) { m.hook = h }

// SetConfig 内存更新配置(装配层在写盘成功后调用, 让下一轮立即生效)。
func (m *Monitor) SetConfig(c Config) {
	m.mu.Lock()
	m.cfg = c
	m.mu.Unlock()
}

// Config 当前配置副本。
func (m *Monitor) Config() Config {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cfg
}

// Running 采集循环是否在跑。
func (m *Monitor) Running() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.running
}

// Start 启动采集循环(幂等)。
func (m *Monitor) Start() {
	m.mu.Lock()
	if m.running {
		m.mu.Unlock()
		return
	}
	m.running = true
	m.stopCh = make(chan struct{})
	ch := m.stopCh
	m.mu.Unlock()
	go m.loop(ch)
}

// Stop 停止采集循环(幂等)。
func (m *Monitor) Stop() {
	m.mu.Lock()
	if !m.running {
		m.mu.Unlock()
		return
	}
	m.running = false
	close(m.stopCh)
	m.mu.Unlock()
}

func (m *Monitor) logfLine(s string) {
	if m.logf != nil {
		m.logf(s)
	}
}

// loop 主循环: 每轮重读配置(间隔也随配置变), 无目标时静默等待。
func (m *Monitor) loop(stopCh chan struct{}) {
	for {
		cfg := m.currentCfg()
		m.runRound(cfg)
		t := time.NewTimer(EffectiveInterval(cfg.IntervalSec))
		select {
		case <-stopCh:
			t.Stop()
			return
		case <-t.C:
		}
	}
}

// currentCfg 优先走注入的读配置(反映 UI 修改), 同时刷新内存快照。
func (m *Monitor) currentCfg() Config {
	var c Config
	if m.readCfg != nil {
		c = m.readCfg()
	} else {
		m.mu.RLock()
		c = m.cfg
		m.mu.RUnlock()
	}
	m.mu.Lock()
	m.cfg = c
	m.mu.Unlock()
	return c
}

// runRound 跑一轮采集。enabled=false 或无目标 = 零动作。
func (m *Monitor) runRound(cfg Config) {
	if !cfg.Enabled || len(cfg.Targets) == 0 {
		return
	}
	// 整轮兜底时限: 单查询超时由 Target.TimeoutMs 管, 这里防止某设备
	// walk 极慢时整轮拖死(60s 轮询间隔下, 90s 内必然结束)。
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	m.runRoundCtx(cfg, ctx)
	if m.last != nil && len(m.last.Errors) > 0 {
		msg := fmt.Sprintf("监控轮次: %d/%d 成功, %dms", m.last.OKCount, m.last.Total, m.last.DurationMs)
		for id, e := range m.last.Errors {
			msg += fmt.Sprintf(" | %s: %v", id, e)
		}
		m.logfLine(msg)
	}
}

// record 更新 latest/prev(速率差分的两帧)。
func (m *Monitor) record(id string, s *Sample) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old := m.latest[id]; old != nil {
		m.prev[id] = old
	}
	m.latest[id] = s
}

// Latest 最新样本表副本(targetID → 样本)。
func (m *Monitor) Latest() map[string]*Sample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]*Sample, len(m.latest))
	for k, v := range m.latest {
		out[k] = v
	}
	return out
}

// Prev 上一轮样本表副本(与 Latest 同 key, 可能缺)。
func (m *Monitor) Prev() map[string]*Sample {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make(map[string]*Sample, len(m.prev))
	for k, v := range m.prev {
		out[k] = v
	}
	return out
}

// LastRound 最近一轮汇总(nil = 还没跑过)。
func (m *Monitor) LastRound() *RoundResult {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.last
}

// CollectNow 手动触发一轮(页面"立即采集"按钮用), 不改动周期循环。
func (m *Monitor) CollectNow(ctx context.Context) *RoundResult {
	cfg := m.currentCfg()
	if !cfg.Enabled || len(cfg.Targets) == 0 {
		return &RoundResult{At: time.Now(), Errors: map[string]any{"_": "未启用或无目标"}}
	}
	m.runRoundCtx(cfg, ctx)
	return m.LastRound()
}

// runRoundCtx 与 runRound 相同, 但接受外部 ctx(手动采集的时限由调用方管)。
func (m *Monitor) runRoundCtx(cfg Config, ctx context.Context) {
	t0 := time.Now()
	res := &RoundResult{At: t0, Errors: map[string]any{}}
	var out []*Sample
	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, 4)

	for _, t := range cfg.Targets {
		wg.Add(1)
		sem <- struct{}{}
		go func(t Target) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					mu.Lock()
					res.Errors[t.ID] = "采集异常: " + fmt.Sprint(r)
					res.Total++
					mu.Unlock()
				}
			}()
			s := CollectTarget(ctx, t)
			mu.Lock()
			out = append(out, s)
			res.Total++
			if s.OK {
				res.OKCount++
			} else {
				res.Errors[t.ID] = s.Err
			}
			m.record(t.ID, s)
			mu.Unlock()
		}(t)
	}
	wg.Wait()
	res.DurationMs = time.Since(t0).Milliseconds()
	m.mu.Lock()
	m.last = res
	m.mu.Unlock()
	if m.write != nil {
		m.write(out)
	}
	if m.hook != nil {
		m.hook(res)
	}
}

// IfaceRate 接口流量速率(B/s): 用 latest 与 prev 两帧差分。
// 计数器回绕(重启清零)时差值为负, 归 0 不报负速率。
func IfaceRate(cur, prev *IfaceSample) (inBps, outBps int64) {
	if cur == nil || prev == nil {
		return 0, 0
	}
	if cur.In < prev.In {
		return 0, 0
	}
	if cur.Out < prev.Out {
		return 0, 0
	}
	return cur.In - prev.In, cur.Out - prev.Out
}
