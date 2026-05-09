package identity

import (
	"path"
	"regexp"
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

func CandidateArtifacts(explicitArtifact string, packageName string, paths ...string) []string {
	seen := make(map[string]struct{})
	candidates := make([]string, 0, 2+len(paths))
	appendCandidate := func(value string) {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			return
		}
		key := strings.ToLower(trimmed)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		candidates = append(candidates, trimmed)
	}

	appendCandidate(explicitArtifact)
	appendCandidate(packageName)
	for _, rawPath := range paths {
		artifactID, _ := inferFromPath(rawPath)
		appendCandidate(artifactID)
	}

	return candidates
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
