## 简介

EasyWAF是一个用Go语言编写的轻量级Web应用防火墙，提供HTTP请求过滤、流量控制、HTTP请求抄送和反向代理等功能，保护您的Web应用免受常见攻击。


## 功能特性

• 🔒 请求过滤: 检测和阻止SQL注入、XSS攻击、路径遍历等常见Web攻击

• 📊 流量控制: 支持连接数限制和请求速率限制

• 📋 请求抄送: 将流量异步复制到多个后端服务器用于审计或分析

• 📈 实时统计: 记录总请求数和被阻止请求数

• ⚡ 高性能: 基于Go语言的高并发处理能力

• 🔧 易于配置: 简单的配置接口，快速部署


支持的攻击检测

• ✅ SQL注入攻击

• ✅ XSS跨站脚本攻击

• ✅ 路径遍历攻击

• ✅ 可疑User-Agent检测

• ✅ 请求频率限制

• ✅ 请求体大小限制

• ✅ HTTP方法过滤


## 快速开始

```
go get github.com/iotames/easywaf
```

基本示例
```go
package main

import (
	"log"
	"net/http"

	"github.com/iotames/easywaf"
)

func main() {
	// 配置EasyWAF
	config := easywaf.Config{
		EnableFilter:       true,           // 启用请求过滤
		MainServer:         "http://localhost:8081", // 主后端服务器
		MaxRequestBodySize: 10 * 1024 * 1024, // 10MB最大请求体
		MaxConnections:     1000,             // 最大并发连接数
		MinuteRateLimit:    100,              // 每分钟请求数限制
	}

	// 创建流量守护实例
	WebGuard := easywaf.NewWebGuard(config)

	// 启动WAF服务器
	server := &http.Server{
		Addr:    ":8080",
		Handler: WebGuard,
	}

	log.Println("EasyWAF server starting on :8080")
	log.Printf("Main server: %s", config.MainServer)
	log.Printf("Copy servers: %v", config.CopyServers)

	if err := server.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
```


## 配置选项


| 配置项 | 类型 | 默认值 | 描述 |
| --- | --- | --- | --- |
| EnableFilter | bool | true | 是否启用请求过滤 |
| EnableCopyFor | bool | false | 是否启用请求抄送 |
| MainServer | string | "" | 主后端服务器地址 |
| CopyServers | []string | [] | 抄送服务器地址列表 |
| MaxRequestBodySize | int64 | 10485760 | 最大请求体大小(字节) |
| MaxConnections | int | 1000 | 最大并发连接数 |
| MinuteRateLimit | int | 100 | 每分钟请求数限制 |