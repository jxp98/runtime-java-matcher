package main

import (
	"log"
	"net/http"
	"os"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/config"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/matcher"
	"runtime-java-matcher/internal/server"
	"runtime-java-matcher/internal/trivyraw"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("加载配置失败: %v", err)
	}

	logger := log.New(os.Stdout, "[runtime-java-matcher] ", log.LstdFlags|log.Lmicroseconds)

	var service server.Matcher
	var health api.HealthResponse

	switch cfg.Backend {
	case "bundle":
		index, err := db.Load(cfg.DBPath)
		if err != nil {
			log.Fatalf("加载漏洞数据库失败: %v", err)
		}
		metadata := index.Metadata()
		service = matcher.New(index, "runtime-java-matcher")
		health = api.HealthResponse{
			Status:              "ok",
			Backend:             "bundle",
			Database:            cfg.DBPath,
			PackageSize:         index.Size(),
			DatabaseFormat:      metadata.Format,
			DatabaseSource:      metadata.Source,
			DatabaseVersion:     metadata.Version,
			DatabaseGeneratedAt: metadata.GeneratedAt,
		}
	case "trivy-raw":
		rawService, err := trivyraw.New(trivyraw.Config{
			CacheDir: cfg.TrivyCacheDir,
			VulnDB:   cfg.TrivyVulnDB,
			JavaDB:   cfg.TrivyJavaDB,
		}, "runtime-java-matcher")
		if err != nil {
			log.Fatalf("加载 Trivy 原始数据库失败: %v", err)
		}
		defer func() {
			if closeErr := rawService.Close(); closeErr != nil {
				logger.Printf("关闭 Trivy 原始数据库失败: %v", closeErr)
			}
		}()
		service = rawService
		health = rawService.HealthResponse()
	default:
		log.Fatalf("不支持的后端类型: %s", cfg.Backend)
	}

	mux := server.NewMux(service, health, logger)
	logger.Printf("服务启动成功，监听地址 %s，后端 %s，数据库 %s，记录数 %d，格式 %s，来源 %s", cfg.Address, health.Backend, health.Database, health.PackageSize, health.DatabaseFormat, health.DatabaseSource)
	if err := http.ListenAndServe(cfg.Address, mux); err != nil {
		logger.Fatalf("服务退出: %v", err)
	}
}
