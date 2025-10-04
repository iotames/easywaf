package easywaf

import (
	"sync"
)

// Statistics 统计信息
type Statistics struct {
	TotalRequests   int64
	BlockedRequests int64
	mu              sync.RWMutex
}

// 统计方法
func (s *Statistics) incTotal() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.TotalRequests++
}

func (s *Statistics) incBlocked() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.BlockedRequests++
}

// GetStats 获取统计信息
func (s *Statistics) GetStats() (total, blocked int64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.TotalRequests, s.BlockedRequests
}
