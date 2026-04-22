package db

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type Metadata struct {
	Format      string `json:"format,omitempty"`
	Source      string `json:"source,omitempty"`
	Version     string `json:"version,omitempty"`
	GeneratedAt string `json:"generated_at,omitempty"`
}

type Database struct {
	Metadata Metadata        `json:"metadata,omitempty"`
	Packages []PackageRecord `json:"packages"`
}

type PackageRecord struct {
	PackageType string                `json:"package_type,omitempty"`
	PURL        string                `json:"purl,omitempty"`
	GroupID     string                `json:"group_id,omitempty"`
	ArtifactID  string                `json:"artifact_id,omitempty"`
	SHA1        []string              `json:"sha1,omitempty"`
	Source      string                `json:"source,omitempty"`
	Aliases     []Alias               `json:"aliases,omitempty"`
	Vulns       []VulnerabilityRecord `json:"vulnerabilities"`
}

type Alias struct {
	GroupID    string `json:"group_id,omitempty"`
	ArtifactID string `json:"artifact_id,omitempty"`
}

type VulnerabilityRecord struct {
	ID            string   `json:"id"`
	Severity      string   `json:"severity,omitempty"`
	Title         string   `json:"title,omitempty"`
	Description   string   `json:"description,omitempty"`
	AffectedRange string   `json:"affected_range,omitempty"`
	FixedVersions []string `json:"fixed_versions,omitempty"`
	References    []string `json:"references,omitempty"`
	Operation     string   `json:"operation,omitempty"`
}

type Index struct {
	metadata   Metadata
	byPURL     map[string][]PackageRecord
	bySHA1     map[string][]PackageRecord
	byGA       map[string][]PackageRecord
	byArtifact map[string][]PackageRecord
	all        []PackageRecord
}

func Load(path string) (*Index, error) {
	stat, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("读取漏洞数据库失败: %w", err)
	}

	if stat.IsDir() {
		return loadBundle(path)
	}

	database, err := loadDatabaseFile(path)
	if err != nil {
		return nil, err
	}

	metadata := database.Metadata
	if metadata.Format == "" {
		metadata.Format = "native-json"
	}
	if metadata.Source == "" {
		metadata.Source = filepath.Base(path)
	}

	return buildIndex(database.Packages, metadata), nil
}

func (i *Index) FindByPURL(purl string) []PackageRecord {
	if i == nil || purl == "" {
		return nil
	}
	return dedupe(i.byPURL[normalize(purl)])
}

func (i *Index) FindBySHA1(sha1 string) []PackageRecord {
	if i == nil || sha1 == "" {
		return nil
	}
	return dedupe(i.bySHA1[normalize(sha1)])
}

func (i *Index) FindByGA(groupID, artifactID string) []PackageRecord {
	if i == nil || groupID == "" || artifactID == "" {
		return nil
	}
	return dedupe(i.byGA[gaKey(groupID, artifactID)])
}

func (i *Index) FindByArtifact(artifactID string) []PackageRecord {
	if i == nil || artifactID == "" {
		return nil
	}
	return dedupe(i.byArtifact[normalize(artifactID)])
}

func (i *Index) Size() int {
	if i == nil {
		return 0
	}
	return len(i.all)
}

func (i *Index) Metadata() Metadata {
	if i == nil {
		return Metadata{}
	}
	return i.metadata
}

func loadBundle(dir string) (*Index, error) {
	metadata := Metadata{
		Format: "bundle-dir",
		Source: filepath.Base(dir),
	}
	metadataPath := filepath.Join(dir, "metadata.json")
	if _, err := os.Stat(metadataPath); err == nil {
		content, readErr := os.ReadFile(metadataPath)
		if readErr != nil {
			return nil, fmt.Errorf("读取漏洞数据库元数据失败: %w", readErr)
		}
		if err := json.Unmarshal(content, &metadata); err != nil {
			return nil, fmt.Errorf("解析漏洞数据库元数据失败: %w", err)
		}
	}

	dataDir := filepath.Join(dir, "packages")
	if stat, err := os.Stat(dataDir); err != nil || !stat.IsDir() {
		dataDir = dir
	}

	entries, err := os.ReadDir(dataDir)
	if err != nil {
		return nil, fmt.Errorf("读取漏洞数据库目录失败: %w", err)
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})

	var packages []PackageRecord
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") || entry.Name() == "metadata.json" {
			continue
		}

		database, err := loadDatabaseFile(filepath.Join(dataDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		packages = append(packages, database.Packages...)
	}

	return buildIndex(packages, metadata), nil
}

func loadDatabaseFile(path string) (Database, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return Database{}, fmt.Errorf("读取漏洞数据库失败: %w", err)
	}

	var database Database
	if err := json.Unmarshal(content, &database); err == nil && len(database.Packages) > 0 {
		return database, nil
	}

	var packages []PackageRecord
	if err := json.Unmarshal(content, &packages); err == nil {
		return Database{Packages: packages}, nil
	}

	return Database{}, fmt.Errorf("解析漏洞数据库失败: %s", path)
}

func buildIndex(records []PackageRecord, metadata Metadata) *Index {
	idx := &Index{
		metadata:   metadata,
		byPURL:     make(map[string][]PackageRecord),
		bySHA1:     make(map[string][]PackageRecord),
		byGA:       make(map[string][]PackageRecord),
		byArtifact: make(map[string][]PackageRecord),
		all:        records,
	}

	for _, record := range records {
		if record.PURL != "" {
			idx.byPURL[normalize(record.PURL)] = append(idx.byPURL[normalize(record.PURL)], record)
		}

		for _, sha1 := range record.SHA1 {
			if normalizedSHA1 := normalize(sha1); normalizedSHA1 != "" {
				idx.bySHA1[normalizedSHA1] = append(idx.bySHA1[normalizedSHA1], record)
			}
		}

		if record.GroupID != "" && record.ArtifactID != "" {
			idx.byGA[gaKey(record.GroupID, record.ArtifactID)] = append(idx.byGA[gaKey(record.GroupID, record.ArtifactID)], record)
		}

		if record.ArtifactID != "" {
			idx.byArtifact[normalize(record.ArtifactID)] = append(idx.byArtifact[normalize(record.ArtifactID)], record)
		}

		for _, alias := range record.Aliases {
			if alias.GroupID != "" && alias.ArtifactID != "" {
				idx.byGA[gaKey(alias.GroupID, alias.ArtifactID)] = append(idx.byGA[gaKey(alias.GroupID, alias.ArtifactID)], record)
			}
			if alias.ArtifactID != "" {
				idx.byArtifact[normalize(alias.ArtifactID)] = append(idx.byArtifact[normalize(alias.ArtifactID)], record)
			}
		}
	}

	return idx
}

func normalize(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func gaKey(groupID, artifactID string) string {
	return normalize(groupID) + ":" + normalize(artifactID)
}

func dedupe(records []PackageRecord) []PackageRecord {
	if len(records) < 2 {
		return records
	}
	seen := make(map[string]struct{}, len(records))
	result := make([]PackageRecord, 0, len(records))
	for _, record := range records {
		key := gaKey(record.GroupID, record.ArtifactID) + "|" + normalize(record.PURL)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, record)
	}
	return result
}
