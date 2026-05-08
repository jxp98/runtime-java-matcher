package trivyexport

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type Config struct {
	InputDir          string
	JavaPath          string
	VulnerabilityPath string
	DataSourcePath    string
	OutputPath        string
	Source            string
	GeneratedAt       string
}

type AdvisoryExport struct {
	Schema      string            `json:"schema"`
	Source      string            `json:"source"`
	GeneratedAt string            `json:"generated_at,omitempty"`
	Packages    []AdvisoryPackage `json:"packages"`
}

type AdvisoryPackage struct {
	PackageType     string                  `json:"package_type,omitempty"`
	PURL            string                  `json:"purl,omitempty"`
	GroupID         string                  `json:"group_id,omitempty"`
	ArtifactID      string                  `json:"artifact_id,omitempty"`
	Source          string                  `json:"source,omitempty"`
	Aliases         []map[string]string     `json:"aliases,omitempty"`
	Vulnerabilities []AdvisoryVulnerability `json:"vulnerabilities,omitempty"`
}

type AdvisoryVulnerability struct {
	ID                 string   `json:"id,omitempty"`
	Severity           string   `json:"severity,omitempty"`
	Title              string   `json:"title,omitempty"`
	Description        string   `json:"description,omitempty"`
	VulnerableVersions []string `json:"vulnerable_versions,omitempty"`
	PatchedVersions    []string `json:"patched_versions,omitempty"`
	References         []string `json:"references,omitempty"`
	Source             string   `json:"source,omitempty"`
	Operation          string   `json:"operation,omitempty"`
}

type Summary struct {
	InputDir           string `json:"input_dir"`
	JavaPath           string `json:"java_path"`
	VulnerabilityPath  string `json:"vulnerability_path"`
	DataSourcePath     string `json:"data_source_path"`
	OutputPath         string `json:"output_path"`
	PackageCount       int    `json:"package_count"`
	VulnerabilityCount int    `json:"vulnerability_count"`
	SourceBucketCount  int    `json:"source_bucket_count"`
}

type dataSourceMeta struct {
	ID   string
	Name string
	URL  string
}

type vulnerabilityMeta struct {
	Title       string
	Description string
	Severity    string
	References  []string
}

type packageAggregate struct {
	PackageType string
	GroupID     string
	ArtifactID  string
	PURL        string
	Sources     []string
	Vulns       []AdvisoryVulnerability
}

func Export(cfg Config) (Summary, error) {
	cfg = normalizeConfig(cfg)
	if err := validateConfig(cfg); err != nil {
		return Summary{}, err
	}

	dataSources, err := loadDataSources(cfg.DataSourcePath)
	if err != nil {
		return Summary{}, err
	}
	vulns, err := loadVulnerabilities(cfg.VulnerabilityPath)
	if err != nil {
		return Summary{}, err
	}
	export, bucketCount, err := loadJavaExport(cfg.JavaPath, cfg.Source, cfg.GeneratedAt, dataSources, vulns)
	if err != nil {
		return Summary{}, err
	}
	if err := writeJSON(cfg.OutputPath, export); err != nil {
		return Summary{}, err
	}

	summary := Summary{
		InputDir:           cfg.InputDir,
		JavaPath:           cfg.JavaPath,
		VulnerabilityPath:  cfg.VulnerabilityPath,
		DataSourcePath:     cfg.DataSourcePath,
		OutputPath:         cfg.OutputPath,
		PackageCount:       len(export.Packages),
		VulnerabilityCount: countVulnerabilities(export.Packages),
		SourceBucketCount:  bucketCount,
	}
	return summary, nil
}

func normalizeConfig(cfg Config) Config {
	if cfg.Source == "" {
		cfg.Source = "trivy-db"
	}
	if cfg.GeneratedAt == "" {
		cfg.GeneratedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if cfg.InputDir != "" {
		if cfg.JavaPath == "" {
			cfg.JavaPath = filepath.Join(cfg.InputDir, "java.yaml")
		}
		if cfg.VulnerabilityPath == "" {
			cfg.VulnerabilityPath = filepath.Join(cfg.InputDir, "vulnerability.yaml")
		}
		if cfg.DataSourcePath == "" {
			cfg.DataSourcePath = filepath.Join(cfg.InputDir, "data-source.yaml")
		}
		if cfg.OutputPath == "" {
			cfg.OutputPath = filepath.Join(cfg.InputDir, "trivy-advisory-export.json")
		}
	}
	return cfg
}

func validateConfig(cfg Config) error {
	if cfg.JavaPath == "" {
		return fmt.Errorf("java.yaml 路径不能为空")
	}
	if cfg.VulnerabilityPath == "" {
		return fmt.Errorf("vulnerability.yaml 路径不能为空")
	}
	if cfg.DataSourcePath == "" {
		return fmt.Errorf("data-source.yaml 路径不能为空")
	}
	if cfg.OutputPath == "" {
		return fmt.Errorf("输出路径不能为空")
	}
	return nil
}

func loadDataSources(path string) (map[string]dataSourceMeta, error) {
	root, err := loadYAMLRoot(path)
	if err != nil {
		return nil, err
	}
	items := asList(root)
	result := make(map[string]dataSourceMeta)
	for _, item := range items {
		entry := asMap(item)
		if entry["bucket"] != "data-source" {
			continue
		}
		for _, pair := range asList(entry["pairs"]) {
			pairMap := asMap(pair)
			key := asString(pairMap["key"])
			value := asMap(pairMap["value"])
			if key == "" {
				continue
			}
			result[key] = dataSourceMeta{
				ID:   asString(value["ID"]),
				Name: asString(value["Name"]),
				URL:  asString(value["URL"]),
			}
		}
	}
	return result, nil
}

func loadVulnerabilities(path string) (map[string]vulnerabilityMeta, error) {
	root, err := loadYAMLRoot(path)
	if err != nil {
		return nil, err
	}
	items := asList(root)
	result := make(map[string]vulnerabilityMeta)
	for _, item := range items {
		entry := asMap(item)
		if entry["bucket"] != "vulnerability" {
			continue
		}
		for _, pair := range asList(entry["pairs"]) {
			pairMap := asMap(pair)
			key := asString(pairMap["key"])
			value := asMap(pairMap["value"])
			if key == "" {
				continue
			}
			result[key] = vulnerabilityMeta{
				Title:       asString(value["Title"]),
				Description: asString(value["Description"]),
				Severity:    strings.ToLower(asString(value["Severity"])),
				References:  asStringList(value["References"]),
			}
		}
	}
	return result, nil
}

func loadJavaExport(path string, source string, generatedAt string, dataSources map[string]dataSourceMeta, vulns map[string]vulnerabilityMeta) (AdvisoryExport, int, error) {
	root, err := loadYAMLRoot(path)
	if err != nil {
		return AdvisoryExport{}, 0, err
	}
	items := asList(root)
	aggregates := make(map[string]*packageAggregate)
	sourceBucketCount := 0
	for _, item := range items {
		entry := asMap(item)
		sourceBucket := asString(entry["bucket"])
		if !strings.HasPrefix(sourceBucket, "maven::") {
			continue
		}
		sourceBucketCount++
		sourceMeta := dataSources[sourceBucket]
		sourceID := firstNonEmpty(sourceMeta.ID, sourceBucket)
		for _, pair := range asList(entry["pairs"]) {
			pkgMap := asMap(pair)
			bucket := asString(pkgMap["bucket"])
			groupID, artifactID := splitPackageBucket(bucket)
			if artifactID == "" {
				continue
			}
			key := strings.ToLower(groupID) + ":" + strings.ToLower(artifactID)
			agg, ok := aggregates[key]
			if !ok {
				agg = &packageAggregate{
					PackageType: "maven",
					GroupID:     groupID,
					ArtifactID:  artifactID,
					PURL:        buildVersionlessPURL(groupID, artifactID),
				}
				aggregates[key] = agg
			}
			agg.Sources = mergeStrings(agg.Sources, []string{sourceID})
			for _, vulnPair := range asList(pkgMap["pairs"]) {
				vulnMap := asMap(vulnPair)
				vulnID := asString(vulnMap["key"])
				value := asMap(vulnMap["value"])
				meta := vulns[vulnID]
				agg.Vulns = mergeVulns(agg.Vulns, []AdvisoryVulnerability{{
					ID:                 vulnID,
					Severity:           meta.Severity,
					Title:              meta.Title,
					Description:        meta.Description,
					VulnerableVersions: asStringList(value["VulnerableVersions"]),
					PatchedVersions:    asStringList(value["PatchedVersions"]),
					References:         meta.References,
					Source:             sourceID,
					Operation:          "upsert",
				}})
			}
		}
	}

	packages := make([]AdvisoryPackage, 0, len(aggregates))
	for _, key := range sortedKeys(aggregates) {
		agg := aggregates[key]
		packages = append(packages, AdvisoryPackage{
			PackageType:     agg.PackageType,
			PURL:            agg.PURL,
			GroupID:         agg.GroupID,
			ArtifactID:      agg.ArtifactID,
			Source:          strings.Join(agg.Sources, ","),
			Vulnerabilities: agg.Vulns,
		})
	}

	return AdvisoryExport{
		Schema:      "trivy-advisory-export/v1",
		Source:      source,
		GeneratedAt: generatedAt,
		Packages:    packages,
	}, sourceBucketCount, nil
}

func loadYAMLRoot(path string) (any, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("读取 YAML 文件失败 %s: %w", path, err)
	}
	root, err := parseYAMLSubset(string(content))
	if err != nil {
		return nil, fmt.Errorf("解析 YAML 文件失败 %s: %w", path, err)
	}
	return root, nil
}

func splitPackageBucket(bucket string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(bucket), ":", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return parts[0], parts[1]
}

func buildVersionlessPURL(groupID, artifactID string) string {
	if groupID == "" || artifactID == "" {
		return ""
	}
	return "pkg:maven/" + groupID + "/" + artifactID
}

func countVulnerabilities(packages []AdvisoryPackage) int {
	total := 0
	for _, pkg := range packages {
		total += len(pkg.Vulnerabilities)
	}
	return total
}

func writeJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化 JSON 失败 %s: %w", path, err)
	}
	if err := os.WriteFile(path, append(encoded, '\n'), 0o644); err != nil {
		return fmt.Errorf("写入 JSON 文件失败 %s: %w", path, err)
	}
	return nil
}

func sortedKeys[T any](mapping map[string]T) []string {
	keys := make([]string, 0, len(mapping))
	for key := range mapping {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func asMap(value any) map[string]any {
	mapping, _ := value.(map[string]any)
	return mapping
}

func asList(value any) []any {
	list, _ := value.([]any)
	return list
}

func asString(value any) string {
	text, _ := value.(string)
	return strings.TrimSpace(text)
}

func asStringList(value any) []string {
	list := asList(value)
	result := make([]string, 0, len(list))
	for _, item := range list {
		text := asString(item)
		if text != "" {
			result = append(result, text)
		}
	}
	return mergeStrings(result, nil)
}

func mergeStrings(left, right []string) []string {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]string, 0, len(left)+len(right))
	for _, value := range append(append([]string{}, left...), right...) {
		normalized := strings.TrimSpace(value)
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

func mergeVulns(left, right []AdvisoryVulnerability) []AdvisoryVulnerability {
	seen := make(map[string]struct{}, len(left)+len(right))
	merged := make([]AdvisoryVulnerability, 0, len(left)+len(right))
	for _, vuln := range append(append([]AdvisoryVulnerability{}, left...), right...) {
		key := strings.ToLower(vuln.ID) + "|" + strings.Join(vuln.VulnerableVersions, ",") + "|" + strings.Join(vuln.PatchedVersions, ",")
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		merged = append(merged, vuln)
	}
	sort.Slice(merged, func(i, j int) bool {
		return merged[i].ID < merged[j].ID
	})
	return merged
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}
