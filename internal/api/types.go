package api

import (
	"encoding/json"
	"strings"
	"time"
)

const (
	MatchStatusMatched            = "matched"
	MatchStatusMissingVersion     = "missing_version"
	MatchStatusMissingIdentity    = "missing_identity"
	MatchStatusIdentityUnresolved = "identity_unresolved"
	MatchStatusNoAdvisory         = "no_advisory"
	MatchStatusVersionNotAffected = "version_not_affected"
)

type MatchRequest struct {
	RequestID     string           `json:"request_id"`
	SchemaVersion string           `json:"schema_version"`
	MatcherSource string           `json:"matcher_source,omitempty"`
	ScanMode      string           `json:"scan_mode,omitempty"`
	Agent         Agent            `json:"agent"`
	Cluster       Cluster          `json:"cluster,omitempty"`
	Components    []ComponentInput `json:"components"`
}

type Agent struct {
	ID           string   `json:"id"`
	Name         string   `json:"name,omitempty"`
	Version      string   `json:"version,omitempty"`
	Hostname     string   `json:"hostname,omitempty"`
	Architecture string   `json:"architecture,omitempty"`
	Groups       []string `json:"groups,omitempty"`
	OS           OSInfo   `json:"os,omitempty"`
}

type Cluster struct {
	Name string `json:"name,omitempty"`
	Node string `json:"node,omitempty"`
}

type OSInfo struct {
	Name     string `json:"name,omitempty"`
	Platform string `json:"platform,omitempty"`
	Type     string `json:"type,omitempty"`
	Version  string `json:"version,omitempty"`
}

type ComponentInput struct {
	InventoryID           string `json:"_inventory_id,omitempty"`
	DocumentVersion       uint64 `json:"_document_version,omitempty"`
	InventoryIndex        string `json:"_inventory_index,omitempty"`
	PackageType           string `json:"package_type,omitempty"`
	PackageName           string `json:"package_name,omitempty"`
	PURL                  string `json:"purl,omitempty"`
	GroupID               string `json:"group_id,omitempty"`
	ArtifactID            string `json:"artifact_id,omitempty"`
	Version               string `json:"version,omitempty"`
	VersionAlt            string `json:"version_,omitempty"`
	RuntimePath           string `json:"runtime_path,omitempty"`
	ArchivePath           string `json:"archive_path,omitempty"`
	PathInArchive         string `json:"path_in_archive,omitempty"`
	DiscoverySource       string `json:"discovery_source,omitempty"`
	EvidenceSource        string `json:"evidence_source,omitempty"`
	Confidence            string `json:"confidence,omitempty"`
	IsDirectRuntimeTarget *bool  `json:"is_direct_runtime_target,omitempty"`
	IsNested              *bool  `json:"is_nested,omitempty"`
	SHA1                  string `json:"sha1,omitempty"`
	SHA256                string `json:"sha256,omitempty"`
	DiscoveredAt          string `json:"discovered_at,omitempty"`
}

func (c *ComponentInput) UnmarshalJSON(data []byte) error {
	type wireComponent struct {
		InventoryID           string `json:"_inventory_id,omitempty"`
		DocumentVersion       uint64 `json:"_document_version,omitempty"`
		InventoryIndex        string `json:"_inventory_index,omitempty"`
		PackageType           string `json:"package_type,omitempty"`
		PackageName           string `json:"package_name,omitempty"`
		PURL                  string `json:"purl,omitempty"`
		GroupID               string `json:"group_id,omitempty"`
		ArtifactID            string `json:"artifact_id,omitempty"`
		Version               string `json:"version,omitempty"`
		VersionAlt            string `json:"version_,omitempty"`
		RuntimePath           string `json:"runtime_path,omitempty"`
		ArchivePath           string `json:"archive_path,omitempty"`
		PathInArchive         string `json:"path_in_archive,omitempty"`
		DiscoverySource       string `json:"discovery_source,omitempty"`
		EvidenceSource        string `json:"evidence_source,omitempty"`
		Confidence            string `json:"confidence,omitempty"`
		IsDirectRuntimeTarget *bool  `json:"is_direct_runtime_target,omitempty"`
		IsNested              *bool  `json:"is_nested,omitempty"`
		SHA1                  string `json:"sha1,omitempty"`
		SHA256                string `json:"sha256,omitempty"`
		DiscoveredAt          string `json:"discovered_at,omitempty"`
		Package               struct {
			Type    string `json:"type,omitempty"`
			Name    string `json:"name,omitempty"`
			Version string `json:"version,omitempty"`
		} `json:"package,omitempty"`
		File struct {
			Path string `json:"path,omitempty"`
			Hash struct {
				SHA1 string `json:"sha1,omitempty"`
			} `json:"hash,omitempty"`
		} `json:"file,omitempty"`
		Checksum struct {
			Hash struct {
				SHA1 string `json:"sha1,omitempty"`
			} `json:"hash,omitempty"`
		} `json:"checksum,omitempty"`
		Wazuh struct {
			RuntimeJava struct {
				PURL                  string `json:"purl,omitempty"`
				GroupID               string `json:"group_id,omitempty"`
				DiscoverySource       string `json:"discovery_source,omitempty"`
				EvidenceSource        string `json:"evidence_source,omitempty"`
				Confidence            string `json:"confidence,omitempty"`
				ArchivePath           string `json:"archive_path,omitempty"`
				PathInArchive         string `json:"path_in_archive,omitempty"`
				IsDirectRuntimeTarget *bool  `json:"is_direct_runtime_target,omitempty"`
				IsNested              *bool  `json:"is_nested,omitempty"`
				DiscoveredAt          string `json:"discovered_at,omitempty"`
			} `json:"runtime_java,omitempty"`
		} `json:"wazuh,omitempty"`
	}

	var value wireComponent
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	*c = ComponentInput{
		InventoryID:           strings.TrimSpace(value.InventoryID),
		DocumentVersion:       value.DocumentVersion,
		InventoryIndex:        strings.TrimSpace(value.InventoryIndex),
		PackageType:           firstNonEmpty(value.PackageType, value.Package.Type),
		PackageName:           firstNonEmpty(value.PackageName, value.Package.Name),
		PURL:                  firstNonEmpty(value.PURL, value.Wazuh.RuntimeJava.PURL),
		GroupID:               firstNonEmpty(value.GroupID, value.Wazuh.RuntimeJava.GroupID),
		ArtifactID:            firstNonEmpty(value.ArtifactID, value.Package.Name),
		Version:               firstNonEmpty(value.Version, value.VersionAlt, value.Package.Version),
		VersionAlt:            strings.TrimSpace(value.VersionAlt),
		RuntimePath:           firstNonEmpty(value.RuntimePath, value.File.Path),
		ArchivePath:           firstNonEmpty(value.ArchivePath, value.Wazuh.RuntimeJava.ArchivePath),
		PathInArchive:         firstNonEmpty(value.PathInArchive, value.Wazuh.RuntimeJava.PathInArchive),
		DiscoverySource:       firstNonEmpty(value.DiscoverySource, value.Wazuh.RuntimeJava.DiscoverySource),
		EvidenceSource:        firstNonEmpty(value.EvidenceSource, value.Wazuh.RuntimeJava.EvidenceSource),
		Confidence:            firstNonEmpty(value.Confidence, value.Wazuh.RuntimeJava.Confidence),
		IsDirectRuntimeTarget: firstNonNilBool(value.IsDirectRuntimeTarget, value.Wazuh.RuntimeJava.IsDirectRuntimeTarget),
		IsNested:              firstNonNilBool(value.IsNested, value.Wazuh.RuntimeJava.IsNested),
		SHA1:                  firstNonEmpty(value.SHA1, value.File.Hash.SHA1, value.Checksum.Hash.SHA1),
		SHA256:                strings.TrimSpace(value.SHA256),
		DiscoveredAt:          firstNonEmpty(value.DiscoveredAt, value.Wazuh.RuntimeJava.DiscoveredAt),
	}

	return nil
}

type MatchResponse struct {
	RequestID     string       `json:"request_id"`
	SchemaVersion string       `json:"schema_version"`
	GeneratedAt   string       `json:"generated_at"`
	Source        string       `json:"source"`
	ScanMode      string       `json:"scan_mode,omitempty"`
	Matches       []MatchEntry `json:"matches"`
}

type MatchEntry struct {
	InventoryID     string          `json:"inventory_id,omitempty"`
	ComponentRef    string          `json:"component_ref,omitempty"`
	Component       NormalizedComp  `json:"component"`
	MatchConfidence string          `json:"match_confidence"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type MatchDiagnosticsResponse struct {
	RequestID     string                  `json:"request_id"`
	SchemaVersion string                  `json:"schema_version"`
	GeneratedAt   string                  `json:"generated_at"`
	Source        string                  `json:"source"`
	ScanMode      string                  `json:"scan_mode,omitempty"`
	Summary       MatchDiagnosticsSummary `json:"summary"`
	Components    []ComponentDiagnostic   `json:"components"`
}

type MatchDiagnosticsSummary struct {
	TotalComponents    int `json:"total_components"`
	MatchedComponents  int `json:"matched_components"`
	MissingVersion     int `json:"missing_version"`
	MissingIdentity    int `json:"missing_identity"`
	IdentityUnresolved int `json:"identity_unresolved"`
	NoAdvisory         int `json:"no_advisory"`
	VersionNotAffected int `json:"version_not_affected"`
}

type ComponentDiagnostic struct {
	InventoryID           string         `json:"inventory_id,omitempty"`
	Component             NormalizedComp `json:"component"`
	Status                string         `json:"status"`
	MatchConfidence       string         `json:"match_confidence,omitempty"`
	ResolutionSource      string         `json:"resolution_source,omitempty"`
	CandidateArtifacts    []string       `json:"candidate_artifacts,omitempty"`
	SelectedGroupID       string         `json:"selected_group_id,omitempty"`
	SelectedArtifactID    string         `json:"selected_artifact_id,omitempty"`
	SelectedPURL          string         `json:"selected_purl,omitempty"`
	DiscoverySource       string         `json:"discovery_source,omitempty"`
	PathInArchive         string         `json:"path_in_archive,omitempty"`
	IsDirectRuntimeTarget *bool          `json:"is_direct_runtime_target,omitempty"`
	IsNested              *bool          `json:"is_nested,omitempty"`
	NoiseFlags            []string       `json:"noise_flags,omitempty"`
	SuppressionCandidate  bool           `json:"suppression_candidate"`
	SuppressionReason     string         `json:"suppression_reason,omitempty"`
	AdvisoryCount         int            `json:"advisory_count,omitempty"`
	VulnerabilityIDs      []string       `json:"vulnerability_ids,omitempty"`
	Notes                 []string       `json:"notes,omitempty"`
}

type NormalizedComp struct {
	PackageType    string `json:"package_type,omitempty"`
	PURL           string `json:"purl,omitempty"`
	GroupID        string `json:"group_id,omitempty"`
	ArtifactID     string `json:"artifact_id,omitempty"`
	Version        string `json:"version,omitempty"`
	RuntimePath    string `json:"runtime_path,omitempty"`
	ArchivePath    string `json:"archive_path,omitempty"`
	EvidenceSource string `json:"evidence_source,omitempty"`
	Confidence     string `json:"confidence,omitempty"`
	SHA1           string `json:"sha1,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
}

type Vulnerability struct {
	ID              string   `json:"id"`
	Severity        string   `json:"severity,omitempty"`
	Title           string   `json:"title,omitempty"`
	Description     string   `json:"description,omitempty"`
	AffectedRange   string   `json:"affected_range,omitempty"`
	FixedVersions   []string `json:"fixed_versions,omitempty"`
	References      []string `json:"references,omitempty"`
	Source          string   `json:"source,omitempty"`
	Operation       string   `json:"operation,omitempty"`
	MatchConfidence string   `json:"match_confidence,omitempty"`
	MatchedAt       string   `json:"matched_at,omitempty"`
}

type HealthResponse struct {
	Status              string `json:"status"`
	Backend             string `json:"backend,omitempty"`
	Database            string `json:"database"`
	PackageSize         int    `json:"package_size"`
	DatabaseFormat      string `json:"database_format,omitempty"`
	DatabaseSource      string `json:"database_source,omitempty"`
	DatabaseVersion     string `json:"database_version,omitempty"`
	DatabaseGeneratedAt string `json:"database_generated_at,omitempty"`
}

func NowISO8601() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if trimmed := strings.TrimSpace(value); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func firstNonNilBool(values ...*bool) *bool {
	for _, value := range values {
		if value != nil {
			resolved := *value
			return &resolved
		}
	}
	return nil
}
