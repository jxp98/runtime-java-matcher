package regression

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/matcher"
)

type Baseline struct {
	Request  api.MatchRequest `json:"request"`
	Findings []Finding        `json:"findings"`
}

type Finding struct {
	ComponentKey    string `json:"component_key"`
	PackageType     string `json:"package_type,omitempty"`
	GroupID         string `json:"group_id,omitempty"`
	ArtifactID      string `json:"artifact_id,omitempty"`
	Version         string `json:"version,omitempty"`
	PURL            string `json:"purl,omitempty"`
	RuntimePath     string `json:"runtime_path,omitempty"`
	InventoryID     string `json:"inventory_id,omitempty"`
	VulnerabilityID string `json:"vulnerability_id"`
	Source          string `json:"source,omitempty"`
}

type Summary struct {
	BaselineComponents      int `json:"baseline_components"`
	BaselineVulnerabilities int `json:"baseline_vulnerabilities"`
	MatcherComponents       int `json:"matcher_components"`
	MatcherVulnerabilities  int `json:"matcher_vulnerabilities"`
	SharedVulnerabilities   int `json:"shared_vulnerabilities"`
	MissingInMatcher        int `json:"missing_in_matcher"`
	ExtraInMatcher          int `json:"extra_in_matcher"`
}

type Report struct {
	GeneratedAt      string    `json:"generated_at"`
	RequestID        string    `json:"request_id,omitempty"`
	Summary          Summary   `json:"summary"`
	MissingInMatcher []Finding `json:"missing_in_matcher,omitempty"`
	ExtraInMatcher   []Finding `json:"extra_in_matcher,omitempty"`
}

type trivyJSONReport struct {
	Results []trivyJSONResult `json:"Results,omitempty"`
}

type trivyJSONResult struct {
	Target          string                    `json:"Target,omitempty"`
	Type            string                    `json:"Type,omitempty"`
	Vulnerabilities []trivyDetectedVulnReport `json:"Vulnerabilities,omitempty"`
}

type trivyDetectedVulnReport struct {
	VulnerabilityID  string             `json:"VulnerabilityID,omitempty"`
	PkgName          string             `json:"PkgName,omitempty"`
	PkgPath          string             `json:"PkgPath,omitempty"`
	InstalledVersion string             `json:"InstalledVersion,omitempty"`
	PkgIdentifier    trivyPkgIdentifier `json:"PkgIdentifier,omitempty"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL,omitempty"`
}

type baselineAccumulator struct {
	component api.ComponentInput
	findings  map[string]Finding
}

func BuildBaselineFromTrivyReport(reportContent []byte, requestID string) (Baseline, error) {
	var report trivyJSONReport
	if err := json.Unmarshal(reportContent, &report); err != nil {
		return Baseline{}, fmt.Errorf("解析 Trivy JSON 报告失败: %w", err)
	}
	if len(report.Results) == 0 {
		return Baseline{}, fmt.Errorf("Trivy JSON 报告为空或不包含 Results")
	}

	request := api.MatchRequest{
		RequestID:     valueOrDefault(requestID, "trivy-compare"),
		SchemaVersion: "1.0",
		MatcherSource: "trivy-compare",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "trivy-compare"},
		Components:    make([]api.ComponentInput, 0),
	}

	components := make(map[string]*baselineAccumulator)
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			component, finding, ok := buildComponentAndFinding(result, vuln)
			if !ok {
				continue
			}
			acc, exists := components[finding.ComponentKey]
			if !exists {
				acc = &baselineAccumulator{
					component: component,
					findings:  make(map[string]Finding),
				}
				components[finding.ComponentKey] = acc
			}
			acc.findings[finding.VulnerabilityID] = finding
		}
	}

	keys := make([]string, 0, len(components))
	for key := range components {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	findings := make([]Finding, 0)
	for _, key := range keys {
		acc := components[key]
		request.Components = append(request.Components, acc.component)
		vulnIDs := make([]string, 0, len(acc.findings))
		for vulnID := range acc.findings {
			vulnIDs = append(vulnIDs, vulnID)
		}
		sort.Strings(vulnIDs)
		for _, vulnID := range vulnIDs {
			findings = append(findings, acc.findings[vulnID])
		}
	}

	return Baseline{Request: request, Findings: findings}, nil
}

func RunLocalBundle(dbPath string, request api.MatchRequest) (api.MatchResponse, error) {
	index, err := db.Load(dbPath)
	if err != nil {
		return api.MatchResponse{}, fmt.Errorf("加载 matcher bundle 失败: %w", err)
	}
	service := matcher.New(index, "runtime-java-trivy-compare")
	return service.Match(request), nil
}

func CallMatcherURL(matcherURL string, request api.MatchRequest) (api.MatchResponse, error) {
	payload, err := json.Marshal(request)
	if err != nil {
		return api.MatchResponse{}, fmt.Errorf("序列化 matcher 请求失败: %w", err)
	}
	resp, err := http.Post(strings.TrimSpace(matcherURL), "application/json", bytes.NewReader(payload))
	if err != nil {
		return api.MatchResponse{}, fmt.Errorf("调用 matcher 失败: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return api.MatchResponse{}, fmt.Errorf("matcher 返回异常状态码: %d", resp.StatusCode)
	}
	var matchResponse api.MatchResponse
	if err := json.NewDecoder(resp.Body).Decode(&matchResponse); err != nil {
		return api.MatchResponse{}, fmt.Errorf("解析 matcher 响应失败: %w", err)
	}
	return matchResponse, nil
}

func Compare(baseline Baseline, response api.MatchResponse) Report {
	baselineSet := make(map[string]Finding, len(baseline.Findings))
	for _, finding := range baseline.Findings {
		baselineSet[findingSignature(finding)] = finding
	}
	matcherFindings := flattenMatcherResponse(response)
	matcherSet := make(map[string]Finding, len(matcherFindings))
	for _, finding := range matcherFindings {
		matcherSet[findingSignature(finding)] = finding
	}

	missing := make([]Finding, 0)
	for signature, finding := range baselineSet {
		if _, ok := matcherSet[signature]; !ok {
			missing = append(missing, finding)
		}
	}
	extra := make([]Finding, 0)
	for signature, finding := range matcherSet {
		if _, ok := baselineSet[signature]; !ok {
			extra = append(extra, finding)
		}
	}
	sortFindings(missing)
	sortFindings(extra)

	matcherComponents := make(map[string]struct{})
	for _, finding := range matcherFindings {
		matcherComponents[finding.ComponentKey] = struct{}{}
	}
	baselineComponents := make(map[string]struct{})
	for _, finding := range baseline.Findings {
		baselineComponents[finding.ComponentKey] = struct{}{}
	}

	sharedCount := 0
	for signature := range baselineSet {
		if _, ok := matcherSet[signature]; ok {
			sharedCount++
		}
	}

	return Report{
		GeneratedAt: api.NowISO8601(),
		RequestID:   valueOrDefault(response.RequestID, baseline.Request.RequestID),
		Summary: Summary{
			BaselineComponents:      len(baselineComponents),
			BaselineVulnerabilities: len(baselineSet),
			MatcherComponents:       len(matcherComponents),
			MatcherVulnerabilities:  len(matcherSet),
			SharedVulnerabilities:   sharedCount,
			MissingInMatcher:        len(missing),
			ExtraInMatcher:          len(extra),
		},
		MissingInMatcher: missing,
		ExtraInMatcher:   extra,
	}
}

func buildComponentAndFinding(result trivyJSONResult, vuln trivyDetectedVulnReport) (api.ComponentInput, Finding, bool) {
	vulnID := strings.TrimSpace(vuln.VulnerabilityID)
	installedVersion := strings.TrimSpace(vuln.InstalledVersion)
	if vulnID == "" || installedVersion == "" {
		return api.ComponentInput{}, Finding{}, false
	}

	packageType, groupID, artifactID, purl := deriveIdentityFromTrivy(result, vuln)
	componentKey := buildComponentKey(groupID, artifactID, purl, installedVersion)
	if componentKey == "" {
		return api.ComponentInput{}, Finding{}, false
	}

	runtimePath := strings.TrimSpace(vuln.PkgPath)
	if runtimePath == "" {
		runtimePath = strings.TrimSpace(result.Target)
	}

	inventoryID := "trivy-report:" + componentKey
	component := api.ComponentInput{
		InventoryID:    inventoryID,
		PackageType:    valueOrDefault(packageType, "jar"),
		PackageName:    strings.TrimSpace(vuln.PkgName),
		PURL:           purl,
		GroupID:        groupID,
		ArtifactID:     artifactID,
		Version:        installedVersion,
		RuntimePath:    runtimePath,
		EvidenceSource: "trivy_report",
		Confidence:     "high",
	}
	finding := Finding{
		ComponentKey:    componentKey,
		PackageType:     component.PackageType,
		GroupID:         component.GroupID,
		ArtifactID:      component.ArtifactID,
		Version:         component.Version,
		PURL:            component.PURL,
		RuntimePath:     component.RuntimePath,
		InventoryID:     inventoryID,
		VulnerabilityID: vulnID,
		Source:          "trivy",
	}
	return component, finding, true
}

func deriveIdentityFromTrivy(result trivyJSONResult, vuln trivyDetectedVulnReport) (packageType, groupID, artifactID, purl string) {
	purl = strings.TrimSpace(vuln.PkgIdentifier.PURL)
	if purl != "" {
		if parsedGroupID, parsedArtifactID, _, ok := parseMavenPURL(purl); ok {
			return "maven", parsedGroupID, parsedArtifactID, purl
		}
	}

	pkgName := strings.TrimSpace(vuln.PkgName)
	if parts := strings.SplitN(pkgName, ":", 2); len(parts) == 2 {
		groupID = strings.TrimSpace(parts[0])
		artifactID = strings.TrimSpace(parts[1])
		return "maven", groupID, artifactID, buildVersionedMavenPURL(groupID, artifactID, strings.TrimSpace(vuln.InstalledVersion))
	}

	artifactID = pkgName
	if artifactID == "" {
		artifactID = strings.TrimSpace(result.Target)
	}
	packageType = inferPackageType(result.Type)
	return packageType, "", artifactID, ""
}

func flattenMatcherResponse(response api.MatchResponse) []Finding {
	findings := make([]Finding, 0)
	for _, match := range response.Matches {
		componentKey := buildComponentKey(match.Component.GroupID, match.Component.ArtifactID, match.Component.PURL, match.Component.Version)
		for _, vulnerability := range match.Vulnerabilities {
			findings = append(findings, Finding{
				ComponentKey:    componentKey,
				PackageType:     match.Component.PackageType,
				GroupID:         strings.TrimSpace(match.Component.GroupID),
				ArtifactID:      strings.TrimSpace(match.Component.ArtifactID),
				Version:         strings.TrimSpace(match.Component.Version),
				PURL:            strings.TrimSpace(match.Component.PURL),
				RuntimePath:     strings.TrimSpace(match.Component.RuntimePath),
				InventoryID:     strings.TrimSpace(match.InventoryID),
				VulnerabilityID: strings.TrimSpace(vulnerability.ID),
				Source:          "matcher",
			})
		}
	}
	sortFindings(findings)
	return findings
}

func findingSignature(finding Finding) string {
	return finding.ComponentKey + "#" + finding.VulnerabilityID
}

func sortFindings(findings []Finding) {
	sort.Slice(findings, func(i, j int) bool {
		left := findingSignature(findings[i])
		right := findingSignature(findings[j])
		if left == right {
			return findings[i].InventoryID < findings[j].InventoryID
		}
		return left < right
	})
}

func buildComponentKey(groupID string, artifactID string, purl string, version string) string {
	groupID = strings.TrimSpace(groupID)
	artifactID = strings.TrimSpace(artifactID)
	version = strings.TrimSpace(version)
	if parsedGroupID, parsedArtifactID, parsedVersion, ok := parseMavenPURL(strings.TrimSpace(purl)); ok {
		groupID = valueOrDefault(groupID, parsedGroupID)
		artifactID = valueOrDefault(artifactID, parsedArtifactID)
		version = valueOrDefault(version, parsedVersion)
	}
	if artifactID == "" {
		return ""
	}
	if groupID != "" {
		if version != "" {
			return groupID + ":" + artifactID + "@" + version
		}
		return groupID + ":" + artifactID
	}
	if version != "" {
		return artifactID + "@" + version
	}
	return artifactID
}

func buildVersionedMavenPURL(groupID string, artifactID string, version string) string {
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
	trimmed := strings.TrimSpace(purl)
	if !strings.HasPrefix(trimmed, "pkg:maven/") {
		return "", "", "", false
	}
	body := strings.TrimPrefix(trimmed, "pkg:maven/")
	version := ""
	if at := strings.Index(body, "@"); at >= 0 {
		version = body[at+1:]
		body = body[:at]
	}
	parts := strings.Split(body, "/")
	if len(parts) != 2 {
		return "", "", "", false
	}
	groupID, err := url.PathUnescape(parts[0])
	if err != nil {
		return "", "", "", false
	}
	artifactID, err := url.PathUnescape(parts[1])
	if err != nil {
		return "", "", "", false
	}
	if idx := strings.Index(version, "?"); idx >= 0 {
		version = version[:idx]
	}
	if version != "" {
		decodedVersion, err := url.PathUnescape(version)
		if err == nil {
			version = decodedVersion
		}
	}
	return strings.TrimSpace(groupID), strings.TrimSpace(artifactID), strings.TrimSpace(version), true
}

func inferPackageType(resultType string) string {
	switch strings.ToLower(strings.TrimSpace(resultType)) {
	case "jar", "war", "ear", "par":
		return "maven"
	default:
		return valueOrDefault(strings.ToLower(strings.TrimSpace(resultType)), "jar")
	}
}

func valueOrDefault(value string, defaultValue string) string {
	if strings.TrimSpace(value) == "" {
		return defaultValue
	}
	return strings.TrimSpace(value)
}

func NewRequestID(prefix string) string {
	return valueOrDefault(prefix, "trivy-compare") + "-" + time.Now().UTC().Format("20060102T150405Z")
}
