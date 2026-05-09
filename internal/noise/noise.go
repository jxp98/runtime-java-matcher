package noise

import "strings"

type Assessment struct {
	Flags                []string `json:"flags,omitempty"`
	SuppressionCandidate bool     `json:"suppression_candidate,omitempty"`
	SuppressionReason    string   `json:"suppression_reason,omitempty"`
}

func Assess(status string, artifactID string, runtimePath string, discoverySource string, evidenceSource string, isDirectRuntimeTarget *bool, isNested *bool) Assessment {
	flags := make([]string, 0, 4)
	appendFlag := func(flag string) {
		if strings.TrimSpace(flag) == "" {
			return
		}
		for _, existing := range flags {
			if existing == flag {
				return
			}
		}
		flags = append(flags, flag)
	}

	trimmedArtifactID := strings.ToLower(strings.TrimSpace(artifactID))
	normalizedRuntimePath := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(runtimePath), "\\", "/"))
	trimmedDiscoverySource := strings.ToLower(strings.TrimSpace(discoverySource))
	trimmedEvidenceSource := strings.ToLower(strings.TrimSpace(evidenceSource))

	if strings.Contains(normalizedRuntimePath, "/bin/") {
		appendFlag("bin_directory_archive")
	}
	if isDirectRuntimeTarget != nil && !*isDirectRuntimeTarget {
		appendFlag("non_direct_runtime_target")
	}
	if isNested != nil && *isNested {
		appendFlag("nested_archive_component")
	}
	if trimmedEvidenceSource == "filename" {
		appendFlag("filename_only_identity")
	}
	if strings.Contains(trimmedDiscoverySource, "classpath") {
		appendFlag("classpath_discovered")
	}
	if trimmedArtifactID == "bootstrap" {
		appendFlag("launcher_like_archive")
	}

	assessment := Assessment{Flags: flags}
	if status == "identity_unresolved" &&
		trimmedArtifactID == "bootstrap" &&
		strings.Contains(normalizedRuntimePath, "/bin/") &&
		isDirectRuntimeTarget != nil && !*isDirectRuntimeTarget {
		assessment.SuppressionCandidate = true
		assessment.SuppressionReason = "launcher_bin_archive_identity_unresolved"
	}
	return assessment
}
