package easywaf

// Config 应用配置结构
type Config struct {
	EnableFilter       bool     // 是否启用过滤
	EnableCopyFor      bool     // 是否启用抄送网络请求到服务器
	MainServer         string   // 主服务地址
	CopyServers        []string // 抄送分发的服务器列表
	MaxRequestBodySize int64    // 最大请求体大小
	MaxConnections     int      // 最大并发数
	MinuteRateLimit    int      // 速率限制(请求/分钟)
}
