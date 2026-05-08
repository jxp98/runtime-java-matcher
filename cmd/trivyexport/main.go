package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"runtime-java-matcher/internal/trivyexport"
)

func main() {
	var inputDir string
	var javaPath string
	var vulnerabilityPath string
	var dataSourcePath string
	var outputPath string
	var source string
	var generatedAt string

	flag.StringVar(&inputDir, "input-dir", "", "Trivy 导出目录，默认期待其中包含 java.yaml、vulnerability.yaml、data-source.yaml")
	flag.StringVar(&javaPath, "java", "", "java.yaml 路径，可覆盖 -input-dir 默认值")
	flag.StringVar(&vulnerabilityPath, "vulnerability", "", "vulnerability.yaml 路径，可覆盖 -input-dir 默认值")
	flag.StringVar(&dataSourcePath, "data-source", "", "data-source.yaml 路径，可覆盖 -input-dir 默认值")
	flag.StringVar(&outputPath, "output", "", "输出 trivy-advisory-export.json 路径")
	flag.StringVar(&source, "source", "trivy-db", "导出来源标识")
	flag.StringVar(&generatedAt, "generated-at", "", "导出时间，默认使用当前 UTC RFC3339")
	flag.Parse()

	summary, err := trivyexport.Export(trivyexport.Config{
		InputDir:          inputDir,
		JavaPath:          javaPath,
		VulnerabilityPath: vulnerabilityPath,
		DataSourcePath:    dataSourcePath,
		OutputPath:        outputPath,
		Source:            source,
		GeneratedAt:       generatedAt,
	})
	if err != nil {
		log.Fatalf("导出 Trivy advisory export 失败: %v", err)
	}
	encoded, err := json.MarshalIndent(summary, "", "  ")
	if err != nil {
		log.Fatalf("序列化导出摘要失败: %v", err)
	}
	fmt.Println(string(encoded))
}
