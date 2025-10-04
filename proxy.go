package easywaf

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	// "time"
)

// ReverseProxyManager 反向代理管理器
type ReverseProxyManager struct {
	mainProxy    *httputil.ReverseProxy
	extProxies   []*httputil.ReverseProxy
	extServers   []string
	errorHandler func(http.ResponseWriter, *http.Request, error)
}

// NewReverseProxyManager 创建反向代理管理器
func NewReverseProxyManager(mainServer string, extServers []string) *ReverseProxyManager {
	manager := &ReverseProxyManager{
		extServers: extServers,
	}

	// 创建主服务代理
	mainURL, err := url.Parse(mainServer)
	if err != nil {
		log.Fatalf("Invalid main server URL: %v", err)
	}
	manager.mainProxy = httputil.NewSingleHostReverseProxy(mainURL)

	// 创建分发服务器代理
	for _, extServer := range extServers {
		extURL, err := url.Parse(extServer)
		if err != nil {
			log.Printf("Invalid ext server URL %s: %v", extServer, err)
			continue
		}
		proxy := httputil.NewSingleHostReverseProxy(extURL)
		manager.extProxies = append(manager.extProxies, proxy)
	}

	// 设置错误处理
	manager.errorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		log.Printf("Proxy error: %v", err)
		http.Error(w, "Service unavailable", http.StatusServiceUnavailable)
	}

	return manager
}

// ServeMain 服务主请求
func (r *ReverseProxyManager) ServeMain(w http.ResponseWriter, req *http.Request) {
	r.mainProxy.ServeHTTP(w, req)
}

// CopyToExtServers 抄送请求到分发服务器
func (r *ReverseProxyManager) CopyToExtServers(cachedReq *CachedRequest) {
	if len(r.extProxies) == 0 {
		return
	}

	var wg sync.WaitGroup
	for i, proxy := range r.extProxies {
		wg.Add(1)
		go func(idx int, p *httputil.ReverseProxy) {
			defer wg.Done()

			// 将缓存请求转换为HTTP请求
			extReq, err := cachedReq.ToHTTPRequest()
			if err != nil {
				log.Printf("Error creating ext request: %v", err)
				return
			}

			// 创建虚拟ResponseWriter
			dummyRW := &DummyResponseWriter{}

			// 使用代理处理请求
			p.ServeHTTP(dummyRW, extReq)

		}(i, proxy)
	}

	// 异步等待，不阻塞主流程
	go func() {
		wg.Wait()
	}()
}

// DummyResponseWriter 虚拟响应写入器
type DummyResponseWriter struct {
	header http.Header
}

func (d *DummyResponseWriter) Header() http.Header {
	if d.header == nil {
		d.header = make(http.Header)
	}
	return d.header
}

func (d *DummyResponseWriter) Write([]byte) (int, error) {
	return 0, nil
}

func (d *DummyResponseWriter) WriteHeader(statusCode int) {
	// 不执行任何操作
}
