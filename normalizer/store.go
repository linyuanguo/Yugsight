package normalizer

import "sync"

// Store 线程安全的归一化结果存储：
// 供 Web API、报告模块、大屏查询读取最新一轮标准化结果。
type Store struct {
	mu     sync.RWMutex
	result *Result
}

// NewStore 创建结果存储。
func NewStore() *Store {
	return &Store{}
}

// Set 写入最新归一化结果。
func (s *Store) Set(r *Result) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = r
}

// Get 读取最新归一化结果，可能为空（尚未归一化过）。
func (s *Store) Get() *Result {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.result
}

// Reset 清空结果。
func (s *Store) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.result = nil
}
