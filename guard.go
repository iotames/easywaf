package easywaf

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/iotames/easywaf/filter"
)

// WebGuard 流量守护应用
type WebGuard struct {
	config        Config
	filter        *filter.Filter
	connSemaphore chan struct{} // TODO 连接数信号量。不是每个IP的最大连接数.
	stats         *Statistics
	proxy         *ReverseProxyManager
}

// acquireConnection 获取连接许可
func (g *WebGuard) acquireConnection() bool {
	select {
	case g.connSemaphore <- struct{}{}:
		return true
	default:
		return false
	}
}

// releaseConnection 释放连接许可
func (g *WebGuard) releaseConnection() {
	<-g.connSemaphore
}

// NewWebGuard 创建流量守护实例
func NewWebGuard(conf Config) *WebGuard {
	log.Println("-----NewWebGuard---MaxConnections---", conf.MaxConnections)
	return &WebGuard{
		config:        conf,
		stats:         &Statistics{},
		filter:        filter.NewFilter(conf.MinuteRateLimit, conf.MaxRequestBodySize),
		connSemaphore: make(chan struct{}, conf.MaxConnections), // 创建连接信号量
		proxy:         NewReverseProxyManager(conf.MainServer, conf.CopyServers),
	}
}

// ServeHTTP 处理HTTP请求
func (g *WebGuard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	log.Printf("Received request: %s %s from %s", r.Method, r.URL.Path, filter.GetClientIP(r))
	// 记录请求开始时间
	start := time.Now()
	// 更新统计
	g.stats.incTotal()

	// 1. 流量过滤检查拦截
	if g.config.EnableFilter {
		// 连接数控制
		if !g.acquireConnection() {
			g.stats.incBlocked()
			http.Error(w, "服务繁忙，请稍后重试", http.StatusServiceUnavailable)
			return
		}
		defer g.releaseConnection()
		if err := g.filter.CheckRequest(r); err != nil {
			g.stats.incBlocked()
			log.Printf("%s", err.Error())
			http.Error(w, err.Message, http.StatusForbidden)
			return
		}
	}

	// 2. 克隆请求，并异步抄送到分发服务器
	if g.config.EnableCopyFor {
		cachedReq, err := CloneRequest(r)
		if err != nil {
			log.Printf("Error cloning request: %v", err)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
			return
		}
		go g.proxy.CopyToExtServers(cachedReq)
	}

	// 添加处理时间头

	w.Header().Set("Easywaf-Cost-Time", fmt.Sprintf("%d ms", time.Since(start).Milliseconds()))
	// 3. 转发到主服务
	g.proxy.ServeMain(w, r)

	log.Printf("Request processed: %s %s", r.Method, r.URL.Path)
}
