package matcher

import (
	"fmt"
	"net/url"
	"strings"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/version"
)

type Service struct {
	index  *db.Index
	source string
}

type normalizedComponent struct {
	api.NormalizedComp
	InventoryID string
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
		normalized := normalizeComponent(componentInput)
		if normalized.Version == "" || !hasIdentity(normalized) {
			continue
		}

		records, confidence := s.findCandidates(normalized)
		if len(records) == 0 {
			continue
		}

		enrichComponentFromRecord(&normalized, records[0])
		vulnerabilities := collectVulnerabilities(records, normalized.Version, confidence)
		if len(vulnerabilities) == 0 {
			continue
		}

		response.Matches = append(response.Matches, api.MatchEntry{
			InventoryID:     normalized.InventoryID,
			ComponentRef:    normalized.InventoryID,
			Component:       normalized.NormalizedComp,
			MatchConfidence: confidence,
			Vulnerabilities: vulnerabilities,
		})
	}

	return response
}

func (s *Service) findCandidates(component normalizedComponent) ([]db.PackageRecord, string) {
	if component.PURL != "" {
		if records := s.index.FindByPURL(component.PURL); len(records) > 0 {
			return records, "high"
		}
	}

	if component.SHA1 != "" {
		if records := s.index.FindBySHA1(component.SHA1); len(records) > 0 {
			return records, "high"
		}
	}

	if component.GroupID != "" {
		if records := s.index.FindByGA(component.GroupID, component.ArtifactID); len(records) > 0 {
			return records, "high"
		}
	}

	if records := s.index.FindByArtifact(component.ArtifactID); len(records) > 0 {
		return records, "medium"
	}

	return nil, ""
}

func hasIdentity(component normalizedComponent) bool {
	return component.PURL != "" || component.SHA1 != "" || component.ArtifactID != ""
}

func enrichComponentFromRecord(component *normalizedComponent, record db.PackageRecord) {
	if component == nil {
		return
	}
	if component.GroupID == "" {
		component.GroupID = strings.TrimSpace(record.GroupID)
	}
	if component.ArtifactID == "" {
		component.ArtifactID = strings.TrimSpace(record.ArtifactID)
	}
	if component.PURL == "" {
		component.PURL = strings.TrimSpace(record.PURL)
	}
	if component.PackageType == "" || component.PackageType == "maven" {
		component.PackageType = valueOrDefault(record.PackageType, component.PackageType)
	}
}

func normalizeComponent(input api.ComponentInput) normalizedComponent {
	component := normalizedComponent{
		InventoryID: input.InventoryID,
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

func valueOrDefault(value, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return value
}

func DebugDescribe(component api.ComponentInput) string {
	return fmt.Sprintf("%s:%s@%s", component.GroupID, component.ArtifactID, component.Version)
}
