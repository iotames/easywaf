package easywaf

import (
	"bytes"
	"io"
	"net/http"
)

// CachedRequest 缓存的请求结构
type CachedRequest struct {
	Method  string
	URL     string
	Headers http.Header
	Body    []byte
}

// CloneRequest 克隆HTTP请求
func CloneRequest(req *http.Request) (*CachedRequest, error) {
	cached := &CachedRequest{
		Method:  req.Method,
		URL:     req.URL.String(),
		Headers: req.Header.Clone(),
	}

	// 读取并缓存请求体
	if req.Body != nil {
		// var buf bytes.Buffer
		// var bodyReader io.Reader = r.Body
		// 	// 使用TeeReader同时读取到buffer和原始流
		// 	bodyReader = io.TeeReader(r.Body, &buf)
		// 	// 替换原始body为可以重复读取的buffer
		// 	r.Body = io.NopCloser(&buf)
		bodyBytes, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		cached.Body = bodyBytes
		// 恢复原始请求体
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}
	return cached, nil
}

// ToHTTPRequest 将缓存请求转换为HTTP请求
func (c *CachedRequest) ToHTTPRequest() (*http.Request, error) {
	var body io.Reader
	if c.Body != nil {
		body = bytes.NewBuffer(c.Body)
	}

	req, err := http.NewRequest(c.Method, c.URL, body)
	if err != nil {
		return nil, err
	}

	// 复制头部
	for key, values := range c.Headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	return req, nil
}
