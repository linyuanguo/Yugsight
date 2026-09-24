// store.go 指标时序的内存存储(最新/上一轮 + 每任务历史环形)。
//
// 为什么内存环形 + 注入式落库: 与 monitor 包同一装配模式 —— 包不依赖 db,
// 历史持久化由装配层(写进 collect_samples 表)负责; 页面"当前值"走内存
// (最新一轮必在内存), "历史曲线"走 db(重启不丢), 两边各司其职。
//
// 环形容量: 每任务 keepRounds 条(默认 1440 ≈ 60s 间隔 × 24h, 与 monitor
// 的 keepSamples 同口径), 防止长驻进程内存无限增长; 磁盘侧另有
// "保留时长 + 条数"双限裁剪(见装配层)。
package collect

import (
	"sync"
)

// keepRounds 每任务内存保留的历史轮次数。
const keepRounds = 1440

// Store 内存时序存储(并发安全)。
type Store struct {
	mu     sync.RWMutex
	latest map[string]*Round // taskID → 最新一轮
	prev   map[string]*Round // taskID → 上一轮(速率差分用)
	hist   map[string][]Round // taskID → 历史(时间升序, 环形裁剪)
}

// NewStore 创建空存储。
func NewStore() *Store {
	return &Store{
		latest: map[string]*Round{},
		prev:   map[string]*Round{},
		hist:   map[string][]Round{},
	}
}

// Record 记录一轮(更新 latest/prev/hist)。
func (s *Store) Record(r *Round) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if old := s.latest[r.TaskID]; old != nil {
		s.prev[r.TaskID] = old
	}
	s.latest[r.TaskID] = r
	h := append(s.hist[r.TaskID], *r)
	if len(h) > keepRounds {
		h = h[len(h)-keepRounds:]
	}
	s.hist[r.TaskID] = h
}

// Latest 全部任务最新轮(副本)。
func (s *Store) Latest() map[string]*Round {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]*Round, len(s.latest))
	for k, v := range s.latest {
		c := *v
		out[k] = &c
	}
	return out
}

// LatestOf 单任务最新轮(nil = 还没采过)。
func (s *Store) LatestOf(taskID string) *Round {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r := s.latest[taskID]; r != nil {
		c := *r
		return &c
	}
	return nil
}

// PrevOf 单任务上一轮(nil = 没有上一轮, 首轮时速率类指标无从差分)。
func (s *Store) PrevOf(taskID string) *Round {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if r := s.prev[taskID]; r != nil {
		c := *r
		return &c
	}
	return nil
}

// History 单任务最近 n 轮(时间升序; n<=0 全部)。
func (s *Store) History(taskID string, n int) []Round {
	s.mu.RLock()
	defer s.mu.RUnlock()
	h := s.hist[taskID]
	if n > 0 && len(h) > n {
		h = h[len(h)-n:]
	}
	out := make([]Round, len(h))
	copy(out, h)
	return out
}

// Forget 删除任务的全部内存状态(任务被删除时调用, 防僵尸数据)。
func (s *Store) Forget(taskID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.latest, taskID)
	delete(s.prev, taskID)
	delete(s.hist, taskID)
}
