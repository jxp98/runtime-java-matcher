package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/matcher"
)

func main() {
	var dbPath string
	var requestPath string
	flag.StringVar(&dbPath, "db", "testdata/vulndb.json", "漏洞数据库路径，支持单个 JSON 文件或 bundle 目录")
	flag.StringVar(&requestPath, "request", "testdata/request.json", "匹配请求 JSON 文件路径")
	flag.Parse()

	index, err := db.Load(dbPath)
	if err != nil {
		log.Fatalf("加载漏洞数据库失败: %v", err)
	}

	requestContent, err := os.ReadFile(requestPath)
	if err != nil {
		log.Fatalf("读取请求文件失败: %v", err)
	}

	var request api.MatchRequest
	if err := json.Unmarshal(requestContent, &request); err != nil {
		log.Fatalf("解析请求文件失败: %v", err)
	}

	service := matcher.New(index, "runtime-java-matcher-cli")
	response := service.Match(request)
	encoded, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		log.Fatalf("序列化响应失败: %v", err)
	}

	fmt.Println(string(encoded))
}
