package bundlegen

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"runtime-java-matcher/internal/db"
)

type Config struct {
	InputPaths         []string
	OutputDir          string
	ReportPath         string
	Source             string
	Version            string
	GeneratedAt        string
	SchemaVersion      string
	AdvisorySource     string
	JavaIdentitySource string
	ShardSize          int
}

type Report struct {
	Format             string        `json:"format"`
	Source             string        `json:"source"`
	Version            string        `json:"version,omitempty"`
	GeneratedAt        string        `json:"generated_at"`
	SchemaVersion      string        `json:"schema_version,omitempty"`
	AdvisorySource     string        `json:"advisory_source,omitempty"`
	JavaIdentitySource string        `json:"java_identity_source,omitempty"`
	PackageCount       int           `json:"package_count"`
	VulnerabilityCount int           `json:"vulnerability_count"`
	ShardCount         int           `json:"shard_count"`
	InputFiles         []string      `json:"input_files"`
	Shards             []ShardReport `json:"shards"`
}

type ShardReport struct {
	FilePath           string `json:"file_path"`
	PackageCount       int    `json:"package_count"`
	VulnerabilityCount int    `json:"vulnerability_count"`
}

type exportFile struct {
	Metadata map[string]any     `json:"metadata,omitempty"`
	Packages []db.PackageRecord `json:"packages"`
}

func Generate(cfg Config) (Report, error) {
	cfg = normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return Report{}, err
	}

	inputFiles, err := collectInputFiles(cfg.InputPaths)
	if err != nil {
		return Report{}, err
	}
	if len(inputFiles) == 0 {
		return Report{}, fmt.Errorf("未找到可用的输入 JSON 文件")
	}

	records, err := loadRecords(inputFiles)
	if err != nil {
		return Report{}, err
	}
	merged := mergeRecords(records)
	shards := splitShards(merged, cfg.ShardSize)

	if err := ensureWritableOutputDir(cfg.OutputDir); err != nil {
		return Report{}, err
	}
	packagesDir := filepath.Join(cfg.OutputDir, "packages")
	if err := os.MkdirAll(packagesDir, 0o755); err != nil {
		return Report{}, fmt.Errorf("创建 packages 目录失败: %w", err)
	}

	report := Report{
		Format:             "runtime-java-bundle",
		Source:             cfg.Source,
		Version:            cfg.Version,
		GeneratedAt:        cfg.GeneratedAt,
		SchemaVersion:      cfg.SchemaVersion,
		AdvisorySource:     cfg.AdvisorySource,
		JavaIdentitySource: cfg.JavaIdentitySource,
		PackageCount:       len(merged),
		VulnerabilityCount: countVulnerabilities(merged),
		ShardCount:         len(shards),
		InputFiles:         inputFiles,
		Shards:             make([]ShardReport, 0, len(shards)),
	}

	for index, shard := range shards {
		fileName := fmt.Sprintf("packages-%04d.json", index+1)
		filePath := filepath.Join(packagesDir, fileName)
		payload := exportFile{Packages: shard}
		if err := writeJSON(filePath, payload); err != nil {
			return Report{}, err
		}
		report.Shards = append(report.Shards, ShardReport{
			FilePath:           filepath.ToSlash(filepath.Join("packages", fileName)),
			PackageCount:       len(shard),
			VulnerabilityCount: countVulnerabilities(shard),
		})
	}

	metadata := map[string]any{
		"format":               report.Format,
		"source":               report.Source,
		"version":              report.Version,
		"generated_at":         report.GeneratedAt,
		"schema_version":       report.SchemaVersion,
		"advisory_source":      report.AdvisorySource,
		"java_identity_source": report.JavaIdentitySource,
		"package_count":        report.PackageCount,
		"vulnerability_count":  report.VulnerabilityCount,
	}
	if err := writeJSON(filepath.Join(cfg.OutputDir, "metadata.json"), metadata); err != nil {
		return Report{}, err
	}

	if err := writeJSON(cfg.ReportPath, report); err != nil {
		return Report{}, err
	}

	return report, nil
}

func normalizeConfig(cfg Config) Config {
	if cfg.Source == "" {
		cfg.Source = "trivy-java-export"
	}
	if cfg.GeneratedAt == "" {
		cfg.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = "1"
	}
	if cfg.ShardSize <= 0 {
		cfg.ShardSize = 1000
	}
	if cfg.ReportPath == "" && cfg.OutputDir != "" {
		cfg.ReportPath = filepath.Join(cfg.OutputDir, "bundle-report.json")
	}
	return cfg
}

func validateConfig(cfg Config) error {
	if len(cfg.InputPaths) == 0 {
		return fmt.Errorf("至少需要一个输入路径")
	}
	if cfg.OutputDir == "" {
		return fmt.Errorf("输出目录不能为空")
	}
	if cfg.ReportPath == "" {
		return fmt.Errorf("报告文件路径不能为空")
	}
	return nil
}

func ensureWritableOutputDir(outputDir string) error {
	if stat, err := os.Stat(outputDir); err == nil {
		if !stat.IsDir() {
			return fmt.Errorf("输出路径不是目录: %s", outputDir)
		}
		entries, readErr := os.ReadDir(outputDir)
		if readErr != nil {
			return fmt.Errorf("读取输出目录失败: %w", readErr)
		}
		if len(entries) > 0 {
			return fmt.Errorf("输出目录不是空目录，请改用新目录或手工清理后重试: %s", outputDir)
		}
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("检查输出目录失败: %w", err)
	}

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("创建输出目录失败: %w", err)
	}
	return nil
}

func collectInputFiles(paths []string) ([]string, error) {
	seen := make(map[string]struct{})
	var files []string

	for _, rawPath := range paths {
		path := strings.TrimSpace(rawPath)
		if path == "" {
			continue
		}

		stat, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("读取输入路径失败 %s: %w", path, err)
		}

		if !stat.IsDir() {
			if isSupportedInputJSONName(filepath.Base(path)) {
				appendUniquePath(&files, seen, path)
			}
			continue
		}

		root := path
		packagesDir := filepath.Join(path, "packages")
		if packageStat, err := os.Stat(packagesDir); err == nil && packageStat.IsDir() {
			root = packagesDir
		}

		if err := filepath.WalkDir(root, func(current string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !isSupportedInputJSONName(entry.Name()) {
				return nil
			}
			appendUniquePath(&files, seen, current)
			return nil
		}); err != nil {
			return nil, fmt.Errorf("遍历输入目录失败 %s: %w", path, err)
		}
	}

	sort.Strings(files)
	return files, nil
}

func appendUniquePath(files *[]string, seen map[string]struct{}, path string) {
	clean := filepath.Clean(path)
	if _, ok := seen[clean]; ok {
		return
	}
	seen[clean] = struct{}{}
	*files = append(*files, clean)
}

func isSupportedInputJSONName(name string) bool {
	lower := strings.ToLower(strings.TrimSpace(name))
	if lower == "metadata.json" || lower == "bundle-report.json" {
		return false
	}
	return strings.HasSuffix(lower, ".json") ||
		strings.HasSuffix(lower, ".json.golden") ||
		strings.HasSuffix(lower, ".golden.json")
}

func loadRecords(files []string) ([]db.PackageRecord, error) {
	var result []db.PackageRecord
	for _, file := range files {
		content, err := os.ReadFile(file)
		if err != nil {
			return nil, fmt.Errorf("读取输入文件失败 %s: %w", file, err)
		}

		if records, ok, err := loadMaybeTrivyReport(content); ok {
			if err != nil {
				return nil, fmt.Errorf("解析 Trivy 报告失败 %s: %w", file, err)
			}
			result = append(result, records...)
			continue
		}

		if records, ok, err := loadMaybeTrivyAdvisoryExport(content); ok {
			if err != nil {
				return nil, fmt.Errorf("解析 Trivy advisory export 失败 %s: %w", file, err)
			}
			result = append(result, records...)
			continue
		}

		if records, ok := loadNativeRecords(content); ok {
			result = append(result, records...)
			continue
		}

		return nil, fmt.Errorf("无法识别输入文件格式: %s", file)
	}
	return result, nil
}

func loadNativeRecords(content []byte) ([]db.PackageRecord, bool) {
	var objectPayload exportFile
	if err := json.Unmarshal(content, &objectPayload); err == nil && len(objectPayload.Packages) > 0 {
		return objectPayload.Packages, true
	}

	var arrayPayload []db.PackageRecord
	if err := json.Unmarshal(content, &arrayPayload); err == nil && len(arrayPayload) > 0 {
		return arrayPayload, true
	}

	var singleRecord db.PackageRecord
	if err := json.Unmarshal(content, &singleRecord); err == nil && hasPackageIdentity(singleRecord) {
		return []db.PackageRecord{singleRecord}, true
	}

	return nil, false
}

func hasPackageIdentity(record db.PackageRecord) bool {
	return strings.TrimSpace(record.PURL) != "" ||
		(strings.TrimSpace(record.GroupID) != "" && strings.TrimSpace(record.ArtifactID) != "") ||
		strings.TrimSpace(record.ArtifactID) != ""
}

func mergeRecords(records []db.PackageRecord) []db.PackageRecord {
	merged := make(map[string]db.PackageRecord, len(records))
	for _, record := range records {
		key := packageKey(record)
		if existing, ok := merged[key]; ok {
			merged[key] = mergeRecord(existing, record)
		} else {
			merged[key] = normalizeRecord(record)
		}
	}

	result := make([]db.PackageRecord, 0, len(merged))
	for _, record := range merged {
		result = append(result, record)
	}
	sort.Slice(result, func(i, j int) bool {
		left := packageSortKey(result[i])
		right := packageSortKey(result[j])
		return left < right
	})
	return result
}

func mergeRecord(left, right db.PackageRecord) db.PackageRecord {
	merged := normalizeRecord(left)
	right = normalizeRecord(right)

	if merged.PackageType == "" {
		merged.PackageType = right.PackageType
	}
	if merged.PURL == "" {
		merged.PURL = right.PURL
	}
	if merged.GroupID == "" {
		merged.GroupID = right.GroupID
	}
	if merged.ArtifactID == "" {
		merged.ArtifactID = right.ArtifactID
	}
	if merged.Source == "" {
		merged.Source = right.Source
	}

	merged.SHA1 = mergeStrings(merged.SHA1, right.SHA1)
	merged.Aliases = mergeAliases(merged.Aliases, right.Aliases)
	merged.Vulns = mergeVulnerabilities(merged.Vulns, right.Vulns)
	return merged
}

func normalizeRecord(record db.PackageRecord) db.PackageRecord {
	record.PackageType = strings.TrimSpace(record.PackageType)
	record.PURL = strings.TrimSpace(record.PURL)
	record.GroupID = strings.TrimSpace(record.GroupID)
	record.ArtifactID = strings.TrimSpace(record.ArtifactID)
	record.Source = strings.TrimSpace(record.Source)
	record.SHA1 = mergeStrings(record.SHA1, nil)
	record.Aliases = mergeAliases(record.Aliases, nil)
	record.Vulns = mergeVulnerabilities(record.Vulns, nil)
	return record
}

func mergeStrings(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]string, 0, len(left)+len(right))
	for _, value := range append(append([]string{}, left...), right...) {
		normalized := strings.ToLower(strings.TrimSpace(value))
		if normalized == "" {
			continue
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		merged = append(merged, normalized)
	}
	sort.Strings(merged)
	return merged
}

func mergeAliases(left, right []db.Alias) []db.Alias {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]db.Alias, 0, len(left)+len(right))
	for _, alias := range append(append([]db.Alias{}, left...), right...) {
		normalized := db.Alias{
			GroupID:    strings.TrimSpace(alias.GroupID),
			ArtifactID: strings.TrimSpace(alias.ArtifactID),
		}
		if normalized.GroupID == "" && normalized.ArtifactID == "" {
			continue
		}
		key := strings.ToLower(normalized.GroupID) + "|" + strings.ToLower(normalized.ArtifactID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, normalized)
	}
	sort.Slice(merged, func(i, j int) bool {
		leftKey := strings.ToLower(merged[i].GroupID) + "|" + strings.ToLower(merged[i].ArtifactID)
		rightKey := strings.ToLower(merged[j].GroupID) + "|" + strings.ToLower(merged[j].ArtifactID)
		return leftKey < rightKey
	})
	return merged
}

func mergeVulnerabilities(left, right []db.VulnerabilityRecord) []db.VulnerabilityRecord {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]db.VulnerabilityRecord, 0, len(left)+len(right))
	for _, vuln := range append(append([]db.VulnerabilityRecord{}, left...), right...) {
		normalized := normalizeVulnerability(vuln)
		if normalized.ID == "" {
			continue
		}
		key := vulnerabilityKey(normalized)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, normalized)
	}
	sort.Slice(merged, func(i, j int) bool {
		return vulnerabilityKey(merged[i]) < vulnerabilityKey(merged[j])
	})
	return merged
}

func normalizeVulnerability(vuln db.VulnerabilityRecord) db.VulnerabilityRecord {
	vuln.ID = strings.TrimSpace(vuln.ID)
	vuln.Severity = strings.TrimSpace(vuln.Severity)
	vuln.Title = strings.TrimSpace(vuln.Title)
	vuln.Description = strings.TrimSpace(vuln.Description)
	vuln.AffectedRange = strings.TrimSpace(vuln.AffectedRange)
	vuln.Operation = strings.TrimSpace(vuln.Operation)
	vuln.FixedVersions = mergeStrings(vuln.FixedVersions, nil)
	vuln.References = mergeStrings(vuln.References, nil)
	return vuln
}

func vulnerabilityKey(vuln db.VulnerabilityRecord) string {
	return strings.ToLower(vuln.ID) + "|" +
		strings.ToLower(vuln.AffectedRange) + "|" +
		strings.Join(vuln.FixedVersions, ",") + "|" +
		strings.ToLower(vuln.Operation)
}

func packageKey(record db.PackageRecord) string {
	record = normalizeRecord(record)
	return strings.ToLower(record.PackageType) + "|" +
		strings.ToLower(record.GroupID) + "|" +
		strings.ToLower(record.ArtifactID) + "|" +
		strings.ToLower(record.PURL)
}

func packageSortKey(record db.PackageRecord) string {
	record = normalizeRecord(record)
	return strings.ToLower(record.GroupID) + "|" +
		strings.ToLower(record.ArtifactID) + "|" +
		strings.ToLower(record.PURL) + "|" +
		strings.ToLower(record.Source)
}

func splitShards(records []db.PackageRecord, shardSize int) [][]db.PackageRecord {
	if len(records) == 0 {
		return [][]db.PackageRecord{{}}
	}
	var shards [][]db.PackageRecord
	for start := 0; start < len(records); start += shardSize {
		end := start + shardSize
		if end > len(records) {
			end = len(records)
		}
		shards = append(shards, records[start:end])
	}
	return shards
}

func countVulnerabilities(records []db.PackageRecord) int {
	total := 0
	for _, record := range records {
		total += len(record.Vulns)
	}
	return total
}

func writeJSON(path string, value any) error {
	content, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 失败 %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(content, '\n'), 0o644); err != nil {
		return fmt.Errorf("写入文件失败 %s: %w", path, err)
	}
	return nil
}
