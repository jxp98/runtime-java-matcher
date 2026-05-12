package trivyraw

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	trivyvdb "github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	trivyjdb "github.com/aquasecurity/trivy-java-db/pkg/db"
	javaTypes "github.com/aquasecurity/trivy-java-db/pkg/types"
	mavenversion "github.com/masahiro331/go-mvn-version"
	bolt "go.etcd.io/bbolt"
	_ "modernc.org/sqlite"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/identity"
	"runtime-java-matcher/internal/noise"
)

type Config struct {
	CacheDir string
	VulnDB   string
	JavaDB   string
}

type Service struct {
	vulnDir string
	javaDir string
	vulnDB  trivyvdb.Config
	javaDB  javaIndexDB
	source  string
	health  api.HealthResponse
}

type javaIndexDB interface {
	Close() error
	SelectIndexBySha1(string) (javaTypes.Index, error)
	SelectIndexesByArtifactIDAndFileType(string, string, javaTypes.ArchiveType) ([]javaTypes.Index, error)
}

type normalizedComponent struct {
	api.NormalizedComp
	InventoryID           string
	PackageName           string
	PathInArchive         string
	DiscoverySource       string
	IsDirectRuntimeTarget *bool
	IsNested              *bool
}

type componentEvaluation struct {
	normalized         normalizedComponent
	status             string
	confidence         string
	resolutionSource   string
	candidateArtifacts []identity.ArtifactCandidate
	advisoryCount      int
	vulnerabilities    []api.Vulnerability
	notes              []string
}

type trivyMetadata struct {
	Version      int    `json:"Version"`
	UpdatedAt    string `json:"UpdatedAt"`
	NextUpdate   string `json:"NextUpdate"`
	DownloadedAt string `json:"DownloadedAt"`
}

func New(cfg Config, source string) (*Service, error) {
	vulnDir, err := resolveVulnDir(cfg)
	if err != nil {
		return nil, err
	}
	javaDir, err := resolveJavaDir(cfg)
	if err != nil {
		return nil, err
	}

	if err := trivyvdb.Init(vulnDir, trivyvdb.WithBoltOptions(&bolt.Options{ReadOnly: true})); err != nil {
		return nil, fmt.Errorf("初始化 trivy-db 失败: %w", err)
	}

	javaDB, err := trivyjdb.New(javaDir)
	if err != nil {
		_ = trivyvdb.Close()
		return nil, fmt.Errorf("打开 trivy-java-db 失败: %w", err)
	}

	service := &Service{
		vulnDir: vulnDir,
		javaDir: javaDir,
		vulnDB:  trivyvdb.Config{},
		javaDB:  &javaDB,
		source:  source,
		health:  buildHealth(vulnDir, javaDir),
	}
	return service, nil
}

func (s *Service) Close() error {
	var closeErrors []string
	if s.javaDB != nil {
		if err := s.javaDB.Close(); err != nil {
			closeErrors = append(closeErrors, err.Error())
		}
	}
	if err := trivyvdb.Close(); err != nil {
		closeErrors = append(closeErrors, err.Error())
	}
	if len(closeErrors) > 0 {
		return errors.New(strings.Join(closeErrors, "; "))
	}
	return nil
}

func (s *Service) HealthResponse() api.HealthResponse {
	return s.health
}

func (s *Service) Match(request api.MatchRequest) api.MatchResponse {
	response := api.MatchResponse{
		RequestID:     request.RequestID,
		SchemaVersion: valueOrDefault(request.SchemaVersion, "1.0"),
		GeneratedAt:   api.NowISO8601(),
		Source:        valueOrDefault(s.source, "runtime-java-matcher"),
		ScanMode:      request.ScanMode,
		Matches:       make([]api.MatchEntry, 0),
	}

	for _, componentInput := range request.Components {
		evaluation := s.evaluateComponent(componentInput)
		if evaluation.status != api.MatchStatusMatched {
			continue
		}
		response.Matches = append(response.Matches, api.MatchEntry{
			InventoryID:     evaluation.normalized.InventoryID,
			ComponentRef:    evaluation.normalized.InventoryID,
			Component:       evaluation.normalized.NormalizedComp,
			MatchConfidence: evaluation.confidence,
			Vulnerabilities: evaluation.vulnerabilities,
		})
	}

	return response
}

func (s *Service) Diagnose(request api.MatchRequest) api.MatchDiagnosticsResponse {
	response := api.MatchDiagnosticsResponse{
		RequestID:     request.RequestID,
		SchemaVersion: valueOrDefault(request.SchemaVersion, "1.0"),
		GeneratedAt:   api.NowISO8601(),
		Source:        valueOrDefault(s.source, "runtime-java-matcher"),
		ScanMode:      request.ScanMode,
		Components:    make([]api.ComponentDiagnostic, 0, len(request.Components)),
	}

	for _, componentInput := range request.Components {
		evaluation := s.evaluateComponent(componentInput)
		response.Components = append(response.Components, evaluation.toDiagnostic())
		response.Summary.TotalComponents++
		switch evaluation.status {
		case api.MatchStatusMatched:
			response.Summary.MatchedComponents++
		case api.MatchStatusMissingVersion:
			response.Summary.MissingVersion++
		case api.MatchStatusMissingIdentity:
			response.Summary.MissingIdentity++
		case api.MatchStatusIdentityUnresolved:
			response.Summary.IdentityUnresolved++
		case api.MatchStatusNoAdvisory:
			response.Summary.NoAdvisory++
		case api.MatchStatusVersionNotAffected:
			response.Summary.VersionNotAffected++
		}
	}

	return response
}

func (s *Service) evaluateComponent(input api.ComponentInput) componentEvaluation {
	normalized := normalizeComponent(input)
	candidates := buildArtifactCandidates(normalized)
	evaluation := componentEvaluation{
		normalized:         normalized,
		candidateArtifacts: candidates,
		notes:              make([]string, 0, 2),
	}

	if normalized.Version == "" {
		evaluation.status = api.MatchStatusMissingVersion
		evaluation.notes = append(evaluation.notes, "缺少可比较的组件版本")
		return evaluation
	}
	if !hasIdentity(normalized) {
		evaluation.status = api.MatchStatusMissingIdentity
		evaluation.notes = append(evaluation.notes, "缺少 purl / sha1 / artifact_id 等身份字段")
		return evaluation
	}

	resolved, confidence, resolutionSource, ok := s.resolveComponent(normalized, candidates)
	evaluation.normalized = resolved
	evaluation.confidence = confidence
	evaluation.resolutionSource = resolutionSource
	if !ok {
		evaluation.status = api.MatchStatusIdentityUnresolved
		evaluation.notes = append(evaluation.notes, "候选 artifact 无法解析为可命中的组件身份")
		return evaluation
	}

	packageName := strings.TrimSpace(resolved.GroupID) + ":" + strings.TrimSpace(resolved.ArtifactID)
	advisories := s.lookupAdvisories(packageName)
	evaluation.advisoryCount = len(advisories)
	if len(advisories) == 0 {
		evaluation.status = api.MatchStatusNoAdvisory
		evaluation.notes = append(evaluation.notes, "组件身份已解析，但 Trivy 漏洞库无对应 advisory")
		return evaluation
	}

	evaluation.vulnerabilities = s.buildMatchedVulnerabilities(advisories, resolved.Version, confidence)
	if len(evaluation.vulnerabilities) == 0 {
		evaluation.status = api.MatchStatusVersionNotAffected
		evaluation.notes = append(evaluation.notes, "存在 advisory，但当前版本不在受影响区间")
		return evaluation
	}

	evaluation.status = api.MatchStatusMatched
	return evaluation
}

func (s *Service) resolveComponent(component normalizedComponent, candidates []identity.ArtifactCandidate) (normalizedComponent, string, string, bool) {
	purlProvided := strings.TrimSpace(component.PURL) != ""

	if component.PURL != "" {
		if groupID, artifactID, versionValue, ok := parseMavenPURL(component.PURL); ok {
			if component.GroupID == "" {
				component.GroupID = groupID
			}
			if component.ArtifactID == "" {
				component.ArtifactID = artifactID
			}
			if component.Version == "" {
				component.Version = versionValue
			}
		}
	}

	if component.Version == "" {
		_, inferredVersion := identity.InferArtifactAndVersion(component.PathInArchive, component.RuntimePath)
		component.Version = valueOrDefault(component.Version, inferredVersion)
	}

	if (component.GroupID == "" || component.ArtifactID == "") && component.SHA1 != "" {
		if groupID, artifactID, versionValue, ok := s.lookupBySHA1(component.SHA1); ok {
			component.GroupID = valueOrDefault(component.GroupID, groupID)
			component.ArtifactID = valueOrDefault(component.ArtifactID, artifactID)
			component.Version = valueOrDefault(component.Version, versionValue)
			if component.PURL == "" {
				component.PURL = buildMavenPURL(component.GroupID, component.ArtifactID, component.Version)
			}
			component.PackageType = valueOrDefault(component.PackageType, "jar")
			return component, "high", "sha1", component.GroupID != "" && component.ArtifactID != ""
		}
	}

	if component.Version != "" && component.GroupID != "" {
		if artifactID, source, ok := s.lookupCanonicalArtifact(component.GroupID, component.Version, candidates); ok {
			component.ArtifactID = artifactID
			component.PURL = buildMavenPURL(component.GroupID, component.ArtifactID, component.Version)
			component.PackageType = valueOrDefault(component.PackageType, "jar")
			return component, "high", source, true
		}
	}

	if component.GroupID == "" && component.Version != "" {
		for _, candidate := range candidates {
			if groupID, ok := s.lookupGroupID(candidate.Value, component.Version); ok {
				component.GroupID = groupID
				component.ArtifactID = candidate.Value
				if component.PURL == "" {
					component.PURL = buildMavenPURL(component.GroupID, component.ArtifactID, component.Version)
				}
				component.PackageType = valueOrDefault(component.PackageType, "jar")
				source := "artifact_version_lookup"
				if candidate.Source != "artifact_id" {
					source = "artifact_version_candidate"
				}
				return component, "medium", source, true
			}
		}
	}

	if component.GroupID != "" && component.ArtifactID != "" && component.Version != "" {
		if canonicalArtifactID, ok := s.lookupExactCoordinate(component.GroupID, component.ArtifactID, component.Version); ok {
			component.ArtifactID = canonicalArtifactID
			if component.PURL == "" {
				component.PURL = buildMavenPURL(component.GroupID, component.ArtifactID, component.Version)
			}
			component.PackageType = valueOrDefault(component.PackageType, "jar")
			source := "group_artifact_verified"
			if purlProvided {
				source = "purl_verified"
			}
			return component, "high", source, true
		}
	}

	if component.GroupID != "" && component.ArtifactID != "" {
		if component.PURL == "" {
			component.PURL = buildMavenPURL(component.GroupID, component.ArtifactID, component.Version)
		}
		component.PackageType = valueOrDefault(component.PackageType, "jar")
		return component, "low", "group_artifact_unverified", false
	}

	return component, "", "", false
}

func (s *Service) lookupBySHA1(sha1 string) (string, string, string, bool) {
	if s.javaDB == nil || strings.TrimSpace(sha1) == "" {
		return "", "", "", false
	}

	index, err := s.javaDB.SelectIndexBySha1(strings.ToLower(strings.TrimSpace(sha1)))
	if err != nil || strings.TrimSpace(index.ArtifactID) == "" {
		return "", "", "", false
	}

	return strings.TrimSpace(index.GroupID), strings.TrimSpace(index.ArtifactID), strings.TrimSpace(index.Version), true
}

func (s *Service) lookupGroupID(artifactID string, version string) (string, bool) {
	if s.javaDB == nil || strings.TrimSpace(artifactID) == "" || strings.TrimSpace(version) == "" {
		return "", false
	}

	indexes, err := s.javaDB.SelectIndexesByArtifactIDAndFileType(strings.TrimSpace(artifactID), strings.TrimSpace(version), javaTypes.JarType)
	if err != nil || len(indexes) == 0 {
		return "", false
	}

	sort.Slice(indexes, func(i, j int) bool {
		return indexes[i].GroupID < indexes[j].GroupID
	})

	groupCounts := make(map[string]int)
	for _, index := range indexes {
		groupID := strings.TrimSpace(index.GroupID)
		if groupID == "" {
			continue
		}
		groupCounts[groupID]++
	}

	maxCount := 0
	resolvedGroupID := ""
	for groupID, count := range groupCounts {
		if count > maxCount {
			maxCount = count
			resolvedGroupID = groupID
		}
	}

	return resolvedGroupID, resolvedGroupID != ""
}

func (s *Service) lookupCanonicalArtifact(groupID string, version string, candidates []identity.ArtifactCandidate) (string, string, bool) {
	if s.javaDB == nil || strings.TrimSpace(groupID) == "" || strings.TrimSpace(version) == "" {
		return "", "", false
	}

	normalizedGroupID := strings.TrimSpace(groupID)
	normalizedVersion := strings.TrimSpace(version)
	for _, candidate := range candidates {
		artifactID := strings.TrimSpace(candidate.Value)
		if artifactID == "" {
			continue
		}
		indexes, err := s.javaDB.SelectIndexesByArtifactIDAndFileType(artifactID, normalizedVersion, javaTypes.JarType)
		if err != nil || len(indexes) == 0 {
			continue
		}
		for _, index := range indexes {
			if !strings.EqualFold(strings.TrimSpace(index.GroupID), normalizedGroupID) {
				continue
			}
			canonicalArtifactID := strings.TrimSpace(index.ArtifactID)
			if canonicalArtifactID == "" {
				continue
			}
			source := "group_artifact_canonical"
			if candidate.Source != "artifact_id" {
				source = "group_artifact_candidate"
			}
			return canonicalArtifactID, source, true
		}
	}

	return "", "", false
}

func (s *Service) lookupExactCoordinate(groupID string, artifactID string, version string) (string, bool) {
	if s.javaDB == nil || strings.TrimSpace(groupID) == "" || strings.TrimSpace(artifactID) == "" || strings.TrimSpace(version) == "" {
		return "", false
	}

	indexes, err := s.javaDB.SelectIndexesByArtifactIDAndFileType(strings.TrimSpace(artifactID), strings.TrimSpace(version), javaTypes.JarType)
	if err != nil || len(indexes) == 0 {
		return "", false
	}

	normalizedGroupID := strings.TrimSpace(groupID)
	normalizedArtifactID := strings.TrimSpace(artifactID)
	for _, index := range indexes {
		if !strings.EqualFold(strings.TrimSpace(index.GroupID), normalizedGroupID) {
			continue
		}
		canonicalArtifactID := strings.TrimSpace(index.ArtifactID)
		if canonicalArtifactID == "" {
			continue
		}
		if !strings.EqualFold(canonicalArtifactID, normalizedArtifactID) {
			continue
		}
		return canonicalArtifactID, true
	}

	return "", false
}

func (s *Service) lookupVulnerabilities(groupID string, artifactID string, installedVersion string, confidence string) []api.Vulnerability {
	packageName := strings.TrimSpace(groupID) + ":" + strings.TrimSpace(artifactID)
	if strings.TrimSpace(groupID) == "" || strings.TrimSpace(artifactID) == "" || strings.TrimSpace(installedVersion) == "" {
		return nil
	}

	advisories := s.lookupAdvisories(packageName)
	if len(advisories) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	result := make([]api.Vulnerability, 0, len(advisories))
	for _, advisory := range advisories {
		vulnID := strings.TrimSpace(advisory.VulnerabilityID)
		if vulnID == "" {
			continue
		}
		if _, ok := seen[vulnID]; ok {
			continue
		}
		if !mavenAdvisoryMatches(installedVersion, advisory) {
			continue
		}
		seen[vulnID] = struct{}{}

		detail, _ := s.vulnDB.GetVulnerability(vulnID)
		result = append(result, api.Vulnerability{
			ID:              vulnID,
			Severity:        extractSeverity(detail),
			Title:           strings.TrimSpace(detail.Title),
			Description:     strings.TrimSpace(detail.Description),
			AffectedRange:   strings.Join(advisory.VulnerableVersions, " || "),
			FixedVersions:   trimAndDedupe(advisory.PatchedVersions),
			References:      trimAndDedupe(detail.References),
			Source:          advisorySource(advisory),
			Operation:       "upsert",
			MatchConfidence: confidence,
			MatchedAt:       api.NowISO8601(),
		})
	}

	return result
}

func (s *Service) buildMatchedVulnerabilities(advisories []dbTypes.Advisory, installedVersion string, confidence string) []api.Vulnerability {
	seen := make(map[string]struct{})
	result := make([]api.Vulnerability, 0, len(advisories))
	for _, advisory := range advisories {
		vulnID := strings.TrimSpace(advisory.VulnerabilityID)
		if vulnID == "" {
			continue
		}
		if _, ok := seen[vulnID]; ok {
			continue
		}
		if !mavenAdvisoryMatches(installedVersion, advisory) {
			continue
		}
		seen[vulnID] = struct{}{}
		detail, _ := s.vulnDB.GetVulnerability(vulnID)
		result = append(result, api.Vulnerability{
			ID:              vulnID,
			Severity:        extractSeverity(detail),
			Title:           strings.TrimSpace(detail.Title),
			Description:     strings.TrimSpace(detail.Description),
			AffectedRange:   strings.Join(advisory.VulnerableVersions, " || "),
			FixedVersions:   trimAndDedupe(advisory.PatchedVersions),
			References:      trimAndDedupe(detail.References),
			Source:          advisorySource(advisory),
			Operation:       "upsert",
			MatchConfidence: confidence,
			MatchedAt:       api.NowISO8601(),
		})
	}
	return result
}

func (s *Service) lookupAdvisories(packageName string) []dbTypes.Advisory {
	candidates := []string{strings.TrimSpace(packageName)}
	lower := strings.ToLower(strings.TrimSpace(packageName))
	if lower != "" && lower != candidates[0] {
		candidates = append(candidates, lower)
	}

	for _, candidate := range candidates {
		advisories, err := s.vulnDB.GetAdvisories("maven::", candidate)
		if err == nil && len(advisories) > 0 {
			return advisories
		}
	}

	return nil
}

func buildHealth(vulnDir string, javaDir string) api.HealthResponse {
	metadata := readMetadata(filepath.Join(vulnDir, "metadata.json"))
	databaseVersion := ""
	databaseGeneratedAt := ""
	if metadata.Version > 0 {
		databaseVersion = strconv.Itoa(metadata.Version)
	}
	if strings.TrimSpace(metadata.UpdatedAt) != "" {
		databaseGeneratedAt = strings.TrimSpace(metadata.UpdatedAt)
	}

	return api.HealthResponse{
		Status:              "ok",
		Backend:             "trivy-raw",
		Database:            vulnDir + " | " + javaDir,
		PackageSize:         0,
		DatabaseFormat:      "trivy-raw",
		DatabaseSource:      "trivy.db + trivy-java.db",
		DatabaseVersion:     databaseVersion,
		DatabaseGeneratedAt: databaseGeneratedAt,
	}
}

func readMetadata(path string) trivyMetadata {
	content, err := os.ReadFile(path)
	if err != nil {
		return trivyMetadata{}
	}
	var metadata trivyMetadata
	if err := json.Unmarshal(content, &metadata); err != nil {
		return trivyMetadata{}
	}
	return metadata
}

func resolveVulnDir(cfg Config) (string, error) {
	if cfg.VulnDB != "" {
		return normalizeDBDir(cfg.VulnDB, "trivy.db")
	}
	if cfg.CacheDir != "" {
		return normalizeDBDir(filepath.Join(cfg.CacheDir, "db"), "trivy.db")
	}
	return "", fmt.Errorf("未找到 trivy-db 路径")
}

func resolveJavaDir(cfg Config) (string, error) {
	if cfg.JavaDB != "" {
		return normalizeDBDir(cfg.JavaDB, "trivy-java.db")
	}
	if cfg.CacheDir != "" {
		return normalizeDBDir(filepath.Join(cfg.CacheDir, "java-db"), "trivy-java.db")
	}
	return "", fmt.Errorf("未找到 trivy-java-db 路径")
}

func normalizeDBDir(path string, fileName string) (string, error) {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		return "", fmt.Errorf("数据库路径不能为空")
	}

	stat, err := os.Stat(trimmed)
	if err != nil {
		return "", fmt.Errorf("数据库路径不存在: %w", err)
	}

	if !stat.IsDir() {
		if filepath.Base(trimmed) != fileName {
			return "", fmt.Errorf("数据库文件名不匹配，期望 %s: %s", fileName, trimmed)
		}
		return filepath.Dir(trimmed), nil
	}

	if _, err := os.Stat(filepath.Join(trimmed, fileName)); err == nil {
		return trimmed, nil
	}

	if _, err := os.Stat(filepath.Join(trimmed, filepath.Base(trimmed), fileName)); err == nil {
		return filepath.Join(trimmed, filepath.Base(trimmed)), nil
	}

	return "", fmt.Errorf("目录下未找到 %s: %s", fileName, trimmed)
}

func normalizeComponent(input api.ComponentInput) normalizedComponent {
	component := normalizedComponent{
		InventoryID:           input.InventoryID,
		PackageName:           strings.TrimSpace(input.PackageName),
		PathInArchive:         strings.TrimSpace(input.PathInArchive),
		DiscoverySource:       strings.TrimSpace(input.DiscoverySource),
		IsDirectRuntimeTarget: input.IsDirectRuntimeTarget,
		IsNested:              input.IsNested,
		NormalizedComp: api.NormalizedComp{
			PackageType:    valueOrDefault(input.PackageType, "jar"),
			PURL:           strings.TrimSpace(input.PURL),
			GroupID:        strings.TrimSpace(input.GroupID),
			ArtifactID:     strings.TrimSpace(input.ArtifactID),
			Version:        strings.TrimSpace(valueOrDefault(input.Version, input.VersionAlt)),
			RuntimePath:    strings.TrimSpace(input.RuntimePath),
			ArchivePath:    strings.TrimSpace(input.ArchivePath),
			EvidenceSource: strings.TrimSpace(input.EvidenceSource),
			Confidence:     strings.TrimSpace(input.Confidence),
			SHA1:           strings.TrimSpace(input.SHA1),
			SHA256:         strings.TrimSpace(input.SHA256),
		},
	}
	inferredArtifactID, inferredVersion := identity.InferArtifactAndVersion(component.PathInArchive, component.RuntimePath)
	if component.ArtifactID == "" {
		component.ArtifactID = inferredArtifactID
	}
	if component.Version == "" {
		component.Version = inferredVersion
	}
	return component
}

func (e componentEvaluation) toDiagnostic() api.ComponentDiagnostic {
	candidateArtifacts := make([]string, 0, len(e.candidateArtifacts))
	for _, candidate := range e.candidateArtifacts {
		candidateArtifacts = append(candidateArtifacts, candidate.Value)
	}
	vulnerabilityIDs := make([]string, 0, len(e.vulnerabilities))
	for _, vulnerability := range e.vulnerabilities {
		vulnerabilityIDs = append(vulnerabilityIDs, vulnerability.ID)
	}
	assessment := noise.Assess(
		e.status,
		e.normalized.ArtifactID,
		e.normalized.RuntimePath,
		e.normalized.DiscoverySource,
		e.normalized.EvidenceSource,
		e.normalized.IsDirectRuntimeTarget,
		e.normalized.IsNested,
	)
	return api.ComponentDiagnostic{
		InventoryID:           e.normalized.InventoryID,
		Component:             e.normalized.NormalizedComp,
		Status:                e.status,
		MatchConfidence:       e.confidence,
		ResolutionSource:      e.resolutionSource,
		CandidateArtifacts:    candidateArtifacts,
		SelectedGroupID:       e.normalized.GroupID,
		SelectedArtifactID:    e.normalized.ArtifactID,
		SelectedPURL:          e.normalized.PURL,
		DiscoverySource:       e.normalized.DiscoverySource,
		PathInArchive:         e.normalized.PathInArchive,
		IsDirectRuntimeTarget: e.normalized.IsDirectRuntimeTarget,
		IsNested:              e.normalized.IsNested,
		NoiseFlags:            append([]string(nil), assessment.Flags...),
		SuppressionCandidate:  assessment.SuppressionCandidate,
		SuppressionReason:     assessment.SuppressionReason,
		AdvisoryCount:         e.advisoryCount,
		VulnerabilityIDs:      vulnerabilityIDs,
		Notes:                 append([]string(nil), e.notes...),
	}
}

func buildArtifactCandidates(component normalizedComponent) []identity.ArtifactCandidate {
	return identity.BuildArtifactCandidates(
		component.ArtifactID,
		component.PackageName,
		component.PathInArchive,
		component.RuntimePath,
		component.EvidenceSource,
	)
}

func hasIdentity(component normalizedComponent) bool {
	return component.PURL != "" || component.SHA1 != "" || component.ArtifactID != ""
}

func buildMavenPURL(groupID string, artifactID string, version string) string {
	groupID = strings.TrimSpace(groupID)
	artifactID = strings.TrimSpace(artifactID)
	version = strings.TrimSpace(version)
	if groupID == "" || artifactID == "" {
		return ""
	}
	if version == "" {
		return "pkg:maven/" + groupID + "/" + artifactID
	}
	return "pkg:maven/" + groupID + "/" + artifactID + "@" + version
}

func parseMavenPURL(purl string) (string, string, string, bool) {
	const prefix = "pkg:maven/"
	trimmed := strings.TrimSpace(purl)
	if !strings.HasPrefix(trimmed, prefix) {
		return "", "", "", false
	}

	body := strings.TrimPrefix(trimmed, prefix)
	at := strings.LastIndex(body, "@")
	if at < 0 {
		return "", "", "", false
	}

	coordinatePart := body[:at]
	versionPart := body[at+1:]
	sep := strings.Index(coordinatePart, "/")
	if sep <= 0 || sep >= len(coordinatePart)-1 {
		return "", "", "", false
	}

	groupID := strings.TrimSpace(coordinatePart[:sep])
	artifactID := strings.TrimSpace(coordinatePart[sep+1:])
	versionValue := strings.TrimSpace(versionPart)
	if groupID == "" || artifactID == "" || versionValue == "" {
		return "", "", "", false
	}
	return groupID, artifactID, versionValue, true
}

func mavenAdvisoryMatches(installedVersion string, advisory dbTypes.Advisory) bool {
	if containsEmpty(advisory.VulnerableVersions) || containsEmpty(advisory.PatchedVersions) || containsEmpty(advisory.UnaffectedVersions) {
		return true
	}

	matched := false
	var err error
	if len(advisory.VulnerableVersions) > 0 {
		matched, err = matchMavenConstraint(installedVersion, strings.Join(advisory.VulnerableVersions, " || "))
		if err != nil || !matched {
			return false
		}
	}

	secureVersions := append([]string{}, advisory.PatchedVersions...)
	secureVersions = append(secureVersions, advisory.UnaffectedVersions...)
	if len(secureVersions) == 0 {
		return matched
	}

	matched, err = matchMavenConstraint(installedVersion, strings.Join(secureVersions, " || "))
	if err != nil {
		return false
	}
	return !matched
}

func matchMavenConstraint(currentVersion string, constraint string) (bool, error) {
	versionValue, err := mavenversion.NewVersion(currentVersion)
	if err != nil {
		return false, fmt.Errorf("maven 版本解析失败 (%s): %w", currentVersion, err)
	}

	comparer, err := mavenversion.NewComparer(constraint)
	if err != nil {
		return false, fmt.Errorf("maven 约束解析失败 (%s): %w", constraint, err)
	}

	return comparer.Check(versionValue), nil
}

func advisorySource(advisory dbTypes.Advisory) string {
	if advisory.DataSource == nil {
		return "trivy-db"
	}
	if sourceID := strings.TrimSpace(string(advisory.DataSource.ID)); sourceID != "" {
		return sourceID
	}
	if name := strings.TrimSpace(advisory.DataSource.Name); name != "" {
		return name
	}
	return "trivy-db"
}

func extractSeverity(vulnerability dbTypes.Vulnerability) string {
	if severity := strings.TrimSpace(vulnerability.Severity); severity != "" {
		return strings.ToUpper(severity)
	}
	for _, severity := range vulnerability.VendorSeverity {
		if value := strings.TrimSpace(severity.String()); value != "" {
			return strings.ToUpper(value)
		}
	}
	return ""
}

func containsEmpty(values []string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return true
		}
	}
	return false
}

func trimAndDedupe(values []string) []string {
	seen := make(map[string]struct{})
	result := make([]string, 0, len(values))
	for _, value := range values {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		result = append(result, trimmed)
	}
	return result
}

func valueOrDefault(value string, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return strings.TrimSpace(value)
}
