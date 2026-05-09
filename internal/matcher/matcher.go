package matcher

import (
	"fmt"
	"net/url"
	"strings"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/identity"
	"runtime-java-matcher/internal/noise"
	"runtime-java-matcher/internal/version"
)

type Service struct {
	index  *db.Index
	source string
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

type candidateResult struct {
	records            []db.PackageRecord
	confidence         string
	resolutionSource   string
	candidateArtifacts []identity.ArtifactCandidate
}

type componentEvaluation struct {
	normalized         normalizedComponent
	status             string
	confidence         string
	resolutionSource   string
	candidateArtifacts []identity.ArtifactCandidate
	records            []db.PackageRecord
	vulnerabilities    []api.Vulnerability
	notes              []string
}

func New(index *db.Index, source string) *Service {
	return &Service{index: index, source: source}
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

	candidateResult := s.findCandidates(normalized, candidates)
	evaluation.confidence = candidateResult.confidence
	evaluation.resolutionSource = candidateResult.resolutionSource
	evaluation.records = candidateResult.records
	if len(candidateResult.records) == 0 {
		if normalized.GroupID != "" && normalized.ArtifactID != "" {
			evaluation.status = api.MatchStatusNoAdvisory
			evaluation.notes = append(evaluation.notes, "组件身份已知，但漏洞库无对应记录")
		} else {
			evaluation.status = api.MatchStatusIdentityUnresolved
			evaluation.notes = append(evaluation.notes, "候选 artifact 无法解析为可命中的组件身份")
		}
		return evaluation
	}

	enrichComponentFromRecord(&normalized, candidateResult.records[0])
	evaluation.normalized = normalized
	evaluation.vulnerabilities = collectVulnerabilities(candidateResult.records, normalized.Version, candidateResult.confidence)
	if len(evaluation.vulnerabilities) == 0 {
		evaluation.status = api.MatchStatusVersionNotAffected
		evaluation.notes = append(evaluation.notes, "组件存在漏洞记录，但当前版本不在受影响区间")
		return evaluation
	}

	evaluation.status = api.MatchStatusMatched
	return evaluation
}

func (s *Service) findCandidates(component normalizedComponent, candidates []identity.ArtifactCandidate) candidateResult {
	if component.PURL != "" {
		if records := s.index.FindByPURL(component.PURL); len(records) > 0 {
			return candidateResult{records: records, confidence: "high", resolutionSource: "purl", candidateArtifacts: candidates}
		}
	}

	if component.SHA1 != "" {
		if records := s.index.FindBySHA1(component.SHA1); len(records) > 0 {
			return candidateResult{records: records, confidence: "high", resolutionSource: "sha1", candidateArtifacts: candidates}
		}
	}

	if component.GroupID != "" {
		for _, candidate := range candidates {
			if records := s.index.FindByGA(component.GroupID, candidate.Value); len(records) > 0 {
				resolutionSource := "group_artifact"
				if candidate.Source != "artifact_id" {
					resolutionSource = "group_artifact_candidate"
				}
				return candidateResult{records: records, confidence: "high", resolutionSource: resolutionSource, candidateArtifacts: candidates}
			}
		}
	}

	for _, candidate := range candidates {
		if records := s.index.FindByArtifact(candidate.Value); len(records) > 0 {
			resolutionSource := "artifact"
			if candidate.Source != "artifact_id" {
				resolutionSource = "artifact_candidate"
			}
			return candidateResult{records: records, confidence: "medium", resolutionSource: resolutionSource, candidateArtifacts: candidates}
		}
	}

	return candidateResult{candidateArtifacts: candidates}
}

func hasIdentity(component normalizedComponent) bool {
	return component.PURL != "" || component.SHA1 != "" || component.ArtifactID != ""
}

func enrichComponentFromRecord(component *normalizedComponent, record db.PackageRecord) {
	if component == nil {
		return
	}
	if groupID := strings.TrimSpace(record.GroupID); groupID != "" {
		component.GroupID = groupID
	}
	if artifactID := strings.TrimSpace(record.ArtifactID); artifactID != "" {
		component.ArtifactID = artifactID
	}
	if component.GroupID != "" && component.ArtifactID != "" {
		component.PURL = buildMavenPURL(component.GroupID, component.ArtifactID, component.Version)
	} else if component.PURL == "" {
		component.PURL = strings.TrimSpace(record.PURL)
	}
	if component.PackageType == "" || component.PackageType == "maven" {
		component.PackageType = valueOrDefault(record.PackageType, component.PackageType)
	}
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
			PackageType:    valueOrDefault(input.PackageType, "maven"),
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

	inferredArtifactID, inferredVersion := identity.InferArtifactAndVersion(component.PathInArchive, component.RuntimePath)
	if component.ArtifactID == "" {
		component.ArtifactID = inferredArtifactID
	}
	if component.Version == "" {
		component.Version = inferredVersion
	}

	return component
}

func collectVulnerabilities(records []db.PackageRecord, installedVersion, matchConfidence string) []api.Vulnerability {
	seen := make(map[string]struct{})
	result := make([]api.Vulnerability, 0)

	for _, record := range records {
		for _, vuln := range record.Vulns {
			if vuln.ID == "" {
				continue
			}
			if vuln.AffectedRange != "" && !version.Match(installedVersion, vuln.AffectedRange) {
				continue
			}
			if _, exists := seen[vuln.ID]; exists {
				continue
			}
			seen[vuln.ID] = struct{}{}
			result = append(result, api.Vulnerability{
				ID:              vuln.ID,
				Severity:        vuln.Severity,
				Title:           vuln.Title,
				Description:     vuln.Description,
				AffectedRange:   vuln.AffectedRange,
				FixedVersions:   append([]string(nil), vuln.FixedVersions...),
				References:      append([]string(nil), vuln.References...),
				Source:          valueOrDefault(record.Source, "local-vulndb"),
				Operation:       valueOrDefault(vuln.Operation, "upsert"),
				MatchConfidence: matchConfidence,
				MatchedAt:       api.NowISO8601(),
			})
		}
	}

	return result
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

func parseMavenPURL(raw string) (groupID, artifactID, versionValue string, ok bool) {
	if !strings.HasPrefix(raw, "pkg:maven/") {
		return "", "", "", false
	}
	trimmed := strings.TrimPrefix(raw, "pkg:maven/")
	pathAndVersion := strings.SplitN(trimmed, "@", 2)
	if len(pathAndVersion) != 2 {
		return "", "", "", false
	}
	pathPart := pathAndVersion[0]
	versionPart := pathAndVersion[1]
	segments := strings.Split(pathPart, "/")
	if len(segments) != 2 {
		return "", "", "", false
	}
	group, err := url.PathUnescape(segments[0])
	if err != nil {
		return "", "", "", false
	}
	artifact, err := url.PathUnescape(segments[1])
	if err != nil {
		return "", "", "", false
	}
	versionClean := versionPart
	if idx := strings.Index(versionClean, "?"); idx >= 0 {
		versionClean = versionClean[:idx]
	}
	versionDecoded, err := url.PathUnescape(versionClean)
	if err != nil {
		return "", "", "", false
	}
	return group, artifact, versionDecoded, true
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
		AdvisoryCount:         len(e.records),
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

func valueOrDefault(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func DebugDescribe(component api.ComponentInput) string {
	return fmt.Sprintf("%s:%s@%s", component.GroupID, component.ArtifactID, component.Version)
}
