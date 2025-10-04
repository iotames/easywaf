package filter

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// Filter 流量过滤器
type Filter struct {
	rateLimiter      *RateLimiter
	userAgentLimiter *UserAgentLimiter
	blockedIPs       map[string]bool
	riskPaths        map[string]bool
	maxBodySize      int64
}

// NewFilter 创建新的过滤器
func NewFilter(limitPerMinute int, maxBodySize int64) *Filter {
	ft := &Filter{
		rateLimiter:      NewRateLimiter(limitPerMinute, time.Minute), // 每分钟100个请求
		userAgentLimiter: NewUserAgentLimiter(),
		blockedIPs:       make(map[string]bool),
		riskPaths:        make(map[string]bool),
		maxBodySize:      maxBodySize,
	}
	ft.SetDefaultRiskPaths()
	return ft
}

// CheckRequest 检查请求是否合法
func (f *Filter) CheckRequest(req *http.Request) (bool, string) {
	clientIP := GetClientIP(req)

	// 1. 检查IP黑名单
	if f.blockedIPs[clientIP] {
		return false, "IP在黑名单中"
	}

	// 2. 检查用户代理
	ua := req.UserAgent()
	if !f.userAgentLimiter.Allow(ua) {
		f.blockedIPs[clientIP] = true
		return false, "可疑的用户代理"
	}

	// 3. 速率限制
	if !f.rateLimiter.Allow(clientIP) {
		return false, "请求频率过高"
	}

	// 4. 检查可疑路径
	if f.isRiskPath(req.URL.Path) {
		return false, "访问可疑路径"
	}

	// 5. 检查请求体大小
	if f.maxBodySize > 0 && req.ContentLength > f.maxBodySize {
		return false, "请求体超出限制"
	}

	// 6. 检查HTTP方法
	if !f.isAllowedMethod(req.Method) {
		return false, "请求方法被禁止"
	}

	// 7. 检查路径注入攻击
	if f.hasPathInjection(req.URL.Path) {
		return false, "检测到路径注入攻击"
	}

	// 8. 检查SQL注入特征
	if containsSQLInjection(req.URL.RawQuery) || containsSQLInjection(req.URL.Path) {
		return false, "检测到SQL注入尝试"
	}

	// 9. 检查XSS攻击特征
	if containsXSS(req.URL.RawQuery) {
		return false, "检测到XSS攻击尝试"
	}

	return true, ""
}

// isAllowedMethod 检查是否允许的HTTP方法
func (f *Filter) isAllowedMethod(method string) bool {
	allowedMethods := map[string]bool{
		"GET":     true,
		"POST":    true,
		"PUT":     true,
		"DELETE":  true,
		"HEAD":    true,
		"OPTIONS": true,
	}
	return allowedMethods[method]
}

// hasPathInjection 检查路径注入攻击
func (f *Filter) hasPathInjection(path string) bool {
	injectionPatterns := []string{
		"../",
		"/./",
		"//",
		"/~",
		"/.",
	}

	for _, pattern := range injectionPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}
	return false
}

// GetClientIP 获取客户端IP
func GetClientIP(r *http.Request) string {
	// 检查X-Forwarded-For头
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		ips := strings.Split(forwarded, ",")
		return strings.TrimSpace(ips[0])
	}

	// 检查X-Real-IP头
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}

	// 使用RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

func containsSQLInjection(s string) bool {
	sqlKeywords := []string{"union", "select", "insert", "update", "delete", "drop", "exec", "sleep"}
	lower := strings.ToLower(s)
	for _, keyword := range sqlKeywords {
		if strings.Contains(lower, keyword) &&
			(strings.Contains(lower, keyword+" ") ||
				strings.Contains(lower, "("+keyword) ||
				strings.HasSuffix(lower, keyword)) {
			return true
		}
	}
	return false
}

func containsXSS(s string) bool {
	xssPatterns := []string{"<script", "javascript:", "onload=", "onerror="}
	lower := strings.ToLower(s)
	for _, pattern := range xssPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}
