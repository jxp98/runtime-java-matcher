package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"strings"

	"runtime-java-matcher/internal/bundlegen"
)

func main() {
	var input string
	var outputDir string
	var reportPath string
	var source string
	var version string
	var generatedAt string
	var schemaVersion string
	var advisorySource string
	var javaIdentitySource string
	var shardSize int

	flag.StringVar(&input, "input", "", "输入路径，支持 JSON 文件、目录或已有 bundle 目录；多个路径使用逗号分隔")
	flag.StringVar(&outputDir, "output", "dist/runtime-java-bundle", "输出 bundle 目录，要求为空目录或不存在")
	flag.StringVar(&reportPath, "report", "", "输出报告文件路径，默认写入 <output>/bundle-report.json")
	flag.StringVar(&source, "source", "trivy-java-export", "bundle 来源标识")
	flag.StringVar(&version, "version", "", "bundle 版本，例如 2026.05.0")
	flag.StringVar(&generatedAt, "generated-at", "", "生成时间，默认使用当前 UTC RFC3339")
	flag.StringVar(&schemaVersion, "schema-version", "1", "bundle schema 版本")
	flag.StringVar(&advisorySource, "advisory-source", "", "漏洞数据源标识，例如 trivy-db")
	flag.StringVar(&javaIdentitySource, "java-identity-source", "", "Java 身份增强源标识，例如 trivy-java-db")
	flag.IntVar(&shardSize, "shard-size", 1000, "每个 shard 的最大 package 数量")
	flag.Parse()

	paths := splitInputPaths(input)
	if len(paths) == 0 {
		log.Fatal("至少需要通过 -input 提供一个输入路径")
	}

	report, err := bundlegen.Generate(bundlegen.Config{
		InputPaths:         paths,
		OutputDir:          outputDir,
		ReportPath:         reportPath,
		Source:             source,
		Version:            version,
		GeneratedAt:        generatedAt,
		SchemaVersion:      schemaVersion,
		AdvisorySource:     advisorySource,
		JavaIdentitySource: javaIdentitySource,
		ShardSize:          shardSize,
	})
	if err != nil {
		log.Fatalf("生成 bundle 失败: %v", err)
	}

	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		log.Fatalf("序列化报告失败: %v", err)
	}
	fmt.Println(string(encoded))
}

func splitInputPaths(raw string) []string {
	parts := strings.Split(raw, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}
