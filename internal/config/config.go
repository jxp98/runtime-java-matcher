package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Address       string
	Backend       string
	DBPath        string
	TrivyCacheDir string
	TrivyVulnDB   string
	TrivyJavaDB   string
}

func Load() (Config, error) {
	cfg := Config{
		Address:       getEnv("RUNTIME_JAVA_MATCHER_ADDR", ":8080"),
		Backend:       getEnv("RUNTIME_JAVA_MATCHER_BACKEND", "bundle"),
		DBPath:        getEnv("RUNTIME_JAVA_MATCHER_DB", "testdata/vulndb.json"),
		TrivyCacheDir: getEnv("RUNTIME_JAVA_MATCHER_TRIVY_CACHE_DIR", ""),
		TrivyVulnDB:   getEnv("RUNTIME_JAVA_MATCHER_TRIVY_VULN_DB", ""),
		TrivyJavaDB:   getEnv("RUNTIME_JAVA_MATCHER_TRIVY_JAVA_DB", ""),
	}

	if cfg.Address == "" {
		return Config{}, fmt.Errorf("RUNTIME_JAVA_MATCHER_ADDR 不能为空")
	}

	switch cfg.Backend {
	case "bundle":
		if cfg.DBPath == "" {
			return Config{}, fmt.Errorf("bundle 后端要求 RUNTIME_JAVA_MATCHER_DB 非空")
		}
	case "trivy-raw":
		if cfg.TrivyCacheDir == "" && cfg.TrivyVulnDB == "" && cfg.TrivyJavaDB == "" {
			return Config{}, fmt.Errorf("trivy-raw 后端要求配置 RUNTIME_JAVA_MATCHER_TRIVY_CACHE_DIR 或显式的 TRIVY DB 路径")
		}
	default:
		return Config{}, fmt.Errorf("不支持的后端类型: %s", cfg.Backend)
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func MustGetPort(address string) int {
	if address == "" || address[0] != ':' {
		return 8080
	}
	port, err := strconv.Atoi(address[1:])
	if err != nil {
		return 8080
	}
	return port
}
