package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"strings"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/regression"
)

func main() {
	var trivyReportPath string
	var matcherURL string
	var dbPath string
	var matcherResponsePath string
	var requestOut string
	var responseOut string
	var requestID string

	flag.StringVar(&trivyReportPath, "trivy-report", "", "Trivy 官方 JSON 报告路径")
	flag.StringVar(&matcherURL, "matcher-url", "", "matcher HTTP 接口地址，例如 http://127.0.0.1:8080/runtime-java/match")
	flag.StringVar(&dbPath, "db", "", "本地 bundle 路径；未指定 matcher-url/matcher-response 时使用")
	flag.StringVar(&matcherResponsePath, "matcher-response", "", "已有 matcher 响应 JSON 路径，优先级最高")
	flag.StringVar(&requestOut, "request-out", "", "将由 Trivy 报告合成的 matcher request 输出到此路径")
	flag.StringVar(&responseOut, "response-out", "", "将 matcher response 输出到此路径")
	flag.StringVar(&requestID, "request-id", "", "自定义 request_id")
	flag.Parse()

	if strings.TrimSpace(trivyReportPath) == "" {
		log.Fatal("必须提供 -trivy-report")
	}

	reportContent, err := os.ReadFile(trivyReportPath)
	if err != nil {
		log.Fatalf("读取 Trivy 报告失败: %v", err)
	}

	baseline, err := regression.BuildBaselineFromTrivyReport(reportContent, chooseRequestID(requestID))
	if err != nil {
		log.Fatalf("构建 Trivy 基线失败: %v", err)
	}
	if requestOut != "" {
		writeJSON(requestOut, baseline.Request)
	}

	var matcherResponse api.MatchResponse
	switch {
	case strings.TrimSpace(matcherResponsePath) != "":
		content, err := os.ReadFile(matcherResponsePath)
		if err != nil {
			log.Fatalf("读取 matcher 响应失败: %v", err)
		}
		if err := json.Unmarshal(content, &matcherResponse); err != nil {
			log.Fatalf("解析 matcher 响应失败: %v", err)
		}
	case strings.TrimSpace(matcherURL) != "":
		matcherResponse, err = regression.CallMatcherURL(matcherURL, baseline.Request)
		if err != nil {
			log.Fatalf("调用 matcher-url 失败: %v", err)
		}
	case strings.TrimSpace(dbPath) != "":
		matcherResponse, err = regression.RunLocalBundle(dbPath, baseline.Request)
		if err != nil {
			log.Fatalf("运行本地 bundle matcher 失败: %v", err)
		}
	default:
		log.Fatal("必须提供 -matcher-response、-matcher-url 或 -db 其中之一")
	}

	if responseOut != "" {
		writeJSON(responseOut, matcherResponse)
	}

	comparison := regression.Compare(baseline, matcherResponse)
	encoded, err := json.MarshalIndent(comparison, "", "  ")
	if err != nil {
		log.Fatalf("序列化对照结果失败: %v", err)
	}
	fmt.Println(string(encoded))
}

func chooseRequestID(value string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return regression.NewRequestID("trivy-compare")
}

func writeJSON(path string, value any) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		log.Fatalf("序列化 JSON 失败: %v", err)
	}
	if err := os.WriteFile(path, encoded, 0o644); err != nil {
		log.Fatalf("写入 %s 失败: %v", path, err)
	}
}
