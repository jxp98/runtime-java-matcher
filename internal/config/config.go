package config

import (
	"fmt"
	"os"
	"strconv"
)

type Config struct {
	Address string
	DBPath  string
}

func Load() (Config, error) {
	cfg := Config{
		Address: getEnv("RUNTIME_JAVA_MATCHER_ADDR", ":8080"),
		DBPath:  getEnv("RUNTIME_JAVA_MATCHER_DB", "testdata/vulndb.json"),
	}

	if cfg.Address == "" {
		return Config{}, fmt.Errorf("RUNTIME_JAVA_MATCHER_ADDR 不能为空")
	}

	if cfg.DBPath == "" {
		return Config{}, fmt.Errorf("RUNTIME_JAVA_MATCHER_DB 不能为空")
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
