package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/iotames/easywaf"
)

func main() {
	// 加载配置
	var err error
	config := easywaf.Config{
		EnableFilter: true,
		// EnableCopyFor: true,
		MainServer: "http://localhost:1212",
		// CopyServers:    []string{"http://log-server:8082","http://audit-server:8083"},
		MaxConnections:     1000,
		MinuteRateLimit:    10,
		MaxRequestBodySize: 10 * 1024 * 1024, // 10MB最大请求体
	}

	server := &http.Server{
		Addr:    ":8080",
		Handler: easywaf.NewWebGuard(config),
	}

	// 启动服务器
	go func() {
		log.Printf("Main server: %s", config.MainServer)
		log.Printf("Copy servers: %v", config.CopyServers)

		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// 等待中断信号
	err = waitForShutdown(server)
	if err != nil {
		log.Fatalf("Failed to start traffic guard: %v", err)
	}

}

// waitForShutdown 等待关闭信号
func waitForShutdown(server *http.Server) error {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")
	return server.Close()
}
