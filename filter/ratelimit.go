package filter

import (
	"sync"
	"time"
)

// RateLimiter 速率限制器
type RateLimiter struct {
	visits map[string][]time.Time
	mu     sync.RWMutex
	limit  int
	window time.Duration
}

// NewRateLimiter 创建速率限制器
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	return &RateLimiter{
		visits: make(map[string][]time.Time),
		limit:  limit,
		window: window,
	}
}

// Allow 检查是否允许请求
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()

	// 清理过期记录
	if visits, exists := rl.visits[ip]; exists {
		var validVisits []time.Time
		for _, visit := range visits {
			if now.Sub(visit) <= rl.window {
				validVisits = append(validVisits, visit)
			}
		}
		rl.visits[ip] = validVisits
	}

	// 检查是否超过限制
	if len(rl.visits[ip]) >= rl.limit {
		return false
	}

	// 记录当前请求
	rl.visits[ip] = append(rl.visits[ip], now)
	return true
}
