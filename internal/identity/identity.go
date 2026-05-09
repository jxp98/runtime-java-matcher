package identity

import (
	"path"
	"regexp"
	"sort"
	"strings"
)

var artifactVersionPattern = regexp.MustCompile(`^(.+)-([0-9][A-Za-z0-9._-]*)$`)

var archiveExtensions = map[string]struct{}{
	".jar": {},
	".war": {},
	".ear": {},
	".par": {},
	".zip": {},
}

type ArtifactCandidate struct {
	Value    string `json:"value"`
	Source   string `json:"source,omitempty"`
	Priority int    `json:"priority,omitempty"`
}

func InferArtifactAndVersion(paths ...string) (string, string) {
	fallbackArtifact := ""
	for _, rawPath := range paths {
		artifactID, version := inferFromPath(rawPath)
		if artifactID == "" {
			continue
		}
		if fallbackArtifact == "" {
			fallbackArtifact = artifactID
		}
		if version != "" {
			return artifactID, version
		}
	}
	return fallbackArtifact, ""
}

func BuildArtifactCandidates(explicitArtifact string, packageName string, pathInArchive string, runtimePath string, evidenceSource string) []ArtifactCandidate {
	candidates := make([]ArtifactCandidate, 0, 4)
	appendCandidate := func(source, value string, priority int) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		candidates = append(candidates, ArtifactCandidate{
			Value:    trimmed,
			Source:   source,
			Priority: priority,
		})
	}

	pathArtifact, pathVersion := inferFromPath(pathInArchive)
	runtimeArtifact, runtimeVersion := inferFromPath(runtimePath)
	trimmedEvidenceSource := strings.TrimSpace(strings.ToLower(evidenceSource))
	trimmedExplicitArtifact := strings.TrimSpace(explicitArtifact)
	trimmedPackageName := strings.TrimSpace(packageName)

	explicitPriority := 85
	if looksDisplayName(trimmedExplicitArtifact) && strings.Contains(trimmedEvidenceSource, "manifest") {
		explicitPriority = 45
	}
	if strings.Contains(trimmedEvidenceSource, "filename") {
		explicitPriority = 92
	}
	appendCandidate("artifact_id", trimmedExplicitArtifact, explicitPriority)

	pathPriority := 90
	if pathVersion == "" {
		pathPriority = 78
	}
	appendCandidate("path_in_archive", pathArtifact, pathPriority)

	runtimePriority := 82
	if runtimeVersion == "" {
		runtimePriority = 70
	}
	appendCandidate("runtime_path", runtimeArtifact, runtimePriority)

	packagePriority := 55
	if looksDisplayName(trimmedPackageName) {
		packagePriority = 35
	}
	appendCandidate("package_name", trimmedPackageName, packagePriority)

	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].Priority == candidates[j].Priority {
			return candidates[i].Source < candidates[j].Source
		}
		return candidates[i].Priority > candidates[j].Priority
	})

	seen := make(map[string]struct{}, len(candidates))
	result := make([]ArtifactCandidate, 0, len(candidates))
	for _, candidate := range candidates {
		key := strings.ToLower(candidate.Value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		result = append(result, candidate)
	}
	return result
}

func CandidateArtifacts(explicitArtifact string, packageName string, paths ...string) []string {
	pathInArchive := ""
	runtimePath := ""
	if len(paths) > 0 {
		pathInArchive = paths[0]
	}
	if len(paths) > 1 {
		runtimePath = paths[1]
	}
	candidates := BuildArtifactCandidates(explicitArtifact, packageName, pathInArchive, runtimePath, "")
	result := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		result = append(result, candidate.Value)
	}
	return result
}

func inferFromPath(rawPath string) (string, string) {
	trimmed := strings.TrimSpace(rawPath)
	if trimmed == "" {
		return "", ""
	}

	normalizedPath := strings.ReplaceAll(trimmed, "\\", "/")
	base := path.Base(normalizedPath)
	if base == "" || base == "." || base == "/" {
		return "", ""
	}

	stem := base
	if ext := strings.ToLower(path.Ext(base)); ext != "" {
		if _, ok := archiveExtensions[ext]; ok {
			stem = strings.TrimSuffix(base, path.Ext(base))
		}
	}
	if stem == "" {
		return "", ""
	}

	matches := artifactVersionPattern.FindStringSubmatch(stem)
	if len(matches) == 3 {
		return matches[1], matches[2]
	}

	return stem, ""
}

func looksDisplayName(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	if strings.Contains(trimmed, " ") {
		return true
	}
	for _, runeValue := range trimmed {
		if runeValue >= 'A' && runeValue <= 'Z' {
			return true
		}
	}
	return false
}
