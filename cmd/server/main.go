package main

import (
	"log"
	"net/http"
	"os"

	"runtime-java-matcher/internal/config"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/matcher"
	"runtime-java-matcher/internal/server"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	index, err := db.Load(cfg.DBPath)
	if err != nil {
		log.Fatalf("加载漏洞数据库失败: %v", err)
	}

	service := matcher.New(index, "runtime-java-matcher")
	logger := log.New(os.Stdout, "[runtime-java-matcher] ", log.LstdFlags|log.Lmicroseconds)
	mux := server.NewMux(service, cfg.DBPath, index.Size(), index.Metadata(), logger)

	metadata := index.Metadata()
	logger.Printf("服务启动成功，监听地址 %s，数据库 %s，记录数 %d，格式 %s，来源 %s", cfg.Address, cfg.DBPath, index.Size(), metadata.Format, metadata.Source)
	if err := http.ListenAndServe(cfg.Address, mux); err != nil {
		logger.Fatalf("服务退出: %v", err)
	}
}
