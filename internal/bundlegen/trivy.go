package bundlegen

import (
	"encoding/json"
	"net/url"
	"sort"
	"strings"

	"runtime-java-matcher/internal/db"
)

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
	FixedVersion     string             `json:"FixedVersion,omitempty"`
	Severity         string             `json:"Severity,omitempty"`
	Title            string             `json:"Title,omitempty"`
	Description      string             `json:"Description,omitempty"`
	PrimaryURL       string             `json:"PrimaryURL,omitempty"`
	References       []string           `json:"References,omitempty"`
	PkgIdentifier    trivyPkgIdentifier `json:"PkgIdentifier,omitempty"`
	DataSource       *trivyDataSource   `json:"DataSource,omitempty"`
}

type trivyPkgIdentifier struct {
	PURL string `json:"PURL,omitempty"`
}

type trivyDataSource struct {
	ID   string `json:"ID,omitempty"`
	Name string `json:"Name,omitempty"`
	URL  string `json:"URL,omitempty"`
}

type trivyAdvisoryExport struct {
	Schema   string                 `json:"schema,omitempty"`
	Source   string                 `json:"source,omitempty"`
	Packages []trivyAdvisoryPackage `json:"packages,omitempty"`
}

type trivyAdvisoryPackage struct {
	PackageType     string                       `json:"package_type,omitempty"`
	PURL            string                       `json:"purl,omitempty"`
	GroupID         string                       `json:"group_id,omitempty"`
	ArtifactID      string                       `json:"artifact_id,omitempty"`
	SHA1            []string                     `json:"sha1,omitempty"`
	Source          string                       `json:"source,omitempty"`
	Aliases         []db.Alias                   `json:"aliases,omitempty"`
	Vulnerabilities []trivyAdvisoryVulnerability `json:"vulnerabilities,omitempty"`
}

type trivyAdvisoryVulnerability struct {
	ID                 string   `json:"id,omitempty"`
	VulnerabilityID    string   `json:"vulnerability_id,omitempty"`
	Severity           string   `json:"severity,omitempty"`
	Title              string   `json:"title,omitempty"`
	Description        string   `json:"description,omitempty"`
	VulnerableVersions []string `json:"vulnerable_versions,omitempty"`
	PatchedVersions    []string `json:"patched_versions,omitempty"`
	FixedVersions      []string `json:"fixed_versions,omitempty"`
	References         []string `json:"references,omitempty"`
	Source             string   `json:"source,omitempty"`
	Operation          string   `json:"operation,omitempty"`
}

func loadMaybeTrivyReport(content []byte) ([]db.PackageRecord, bool, error) {
	var report trivyJSONReport
	if err := json.Unmarshal(content, &report); err != nil || len(report.Results) == 0 {
		return nil, false, nil
	}

	var records []db.PackageRecord
	for _, result := range report.Results {
		for _, vuln := range result.Vulnerabilities {
			record, ok := trivyReportVulnToRecord(result, vuln)
			if !ok {
				continue
			}
			records = append(records, record)
		}
	}

	if len(records) == 0 {
		return nil, true, nil
	}
	return records, true, nil
}

func trivyReportVulnToRecord(result trivyJSONResult, vuln trivyDetectedVulnReport) (db.PackageRecord, bool) {
	installedVersion := strings.TrimSpace(vuln.InstalledVersion)
	if strings.TrimSpace(vuln.VulnerabilityID) == "" || installedVersion == "" {
		return db.PackageRecord{}, false
	}

	packageType, groupID, artifactID, purl := deriveIdentityFromTrivyReport(result, vuln)
	if strings.TrimSpace(artifactID) == "" && strings.TrimSpace(purl) == "" {
		return db.PackageRecord{}, false
	}

	alias := buildDisplayAlias(groupID, artifactID, vuln.PkgName)
	references := mergeStrings(append([]string{vuln.PrimaryURL}, vuln.References...), nil)
	source := strings.TrimSpace(vulnSourceFromReport(vuln))
	if source == "" {
		source = "trivy-report"
	}

	record := db.PackageRecord{
		PackageType: packageType,
		PURL:        purl,
		GroupID:     groupID,
		ArtifactID:  artifactID,
		Source:      source,
		Aliases:     alias,
		Vulns: []db.VulnerabilityRecord{
			{
				ID:            strings.TrimSpace(vuln.VulnerabilityID),
				Severity:      normalizeSeverity(vuln.Severity),
				Title:         strings.TrimSpace(vuln.Title),
				Description:   strings.TrimSpace(vuln.Description),
				AffectedRange: installedVersion,
				FixedVersions: splitList(vuln.FixedVersion),
				References:    references,
				Operation:     "upsert",
			},
		},
	}
	return normalizeRecord(record), true
}

func deriveIdentityFromTrivyReport(result trivyJSONResult, vuln trivyDetectedVulnReport) (packageType, groupID, artifactID, purl string) {
	purl = strings.TrimSpace(vuln.PkgIdentifier.PURL)
	if purl != "" {
		if parsed, ok := parseMavenPURL(purl); ok {
			return "maven", parsed.GroupID, parsed.ArtifactID, parsed.VersionlessPURL
		}
	}

	pkgName := strings.TrimSpace(vuln.PkgName)
	if parts := strings.SplitN(pkgName, ":", 2); len(parts) == 2 {
		groupID = strings.TrimSpace(parts[0])
		artifactID = strings.TrimSpace(parts[1])
		return "maven", groupID, artifactID, buildVersionlessMavenPURL(groupID, artifactID)
	}

	artifactID = pkgName
	if artifactID == "" {
		artifactID = strings.TrimSpace(result.Target)
	}
	packageType = inferPackageTypeFromResultType(result.Type)
	return packageType, "", artifactID, ""
}

func vulnSourceFromReport(vuln trivyDetectedVulnReport) string {
	if vuln.DataSource == nil {
		return ""
	}
	if strings.TrimSpace(vuln.DataSource.ID) != "" {
		return vuln.DataSource.ID
	}
	if strings.TrimSpace(vuln.DataSource.Name) != "" {
		return vuln.DataSource.Name
	}
	return ""
}

func loadMaybeTrivyAdvisoryExport(content []byte) ([]db.PackageRecord, bool, error) {
	var payload trivyAdvisoryExport
	if err := json.Unmarshal(content, &payload); err == nil && len(payload.Packages) > 0 {
		if looksLikeTrivyAdvisoryExport(payload.Schema, payload.Packages) {
			return convertTrivyAdvisoryPackages(payload.Packages, payload.Source), true, nil
		}
	}

	var packages []trivyAdvisoryPackage
	if err := json.Unmarshal(content, &packages); err == nil && len(packages) > 0 && looksLikeTrivyAdvisoryExport("", packages) {
		return convertTrivyAdvisoryPackages(packages, ""), true, nil
	}

	return nil, false, nil
}

func looksLikeTrivyAdvisoryExport(schema string, packages []trivyAdvisoryPackage) bool {
	if strings.Contains(strings.ToLower(schema), "trivy-advisory-export") {
		return true
	}
	for _, pkg := range packages {
		for _, vuln := range pkg.Vulnerabilities {
			if len(vuln.VulnerableVersions) > 0 || len(vuln.PatchedVersions) > 0 || strings.TrimSpace(vuln.VulnerabilityID) != "" {
				return true
			}
		}
	}
	return false
}

func convertTrivyAdvisoryPackages(packages []trivyAdvisoryPackage, sourceFallback string) []db.PackageRecord {
	records := make([]db.PackageRecord, 0, len(packages))
	for _, pkg := range packages {
		record := trivyAdvisoryPackageToRecord(pkg, sourceFallback)
		if hasPackageIdentity(record) && len(record.Vulns) > 0 {
			records = append(records, record)
		}
	}
	return records
}

func trivyAdvisoryPackageToRecord(pkg trivyAdvisoryPackage, sourceFallback string) db.PackageRecord {
	groupID := strings.TrimSpace(pkg.GroupID)
	artifactID := strings.TrimSpace(pkg.ArtifactID)
	purl := strings.TrimSpace(pkg.PURL)
	packageType := strings.TrimSpace(pkg.PackageType)
	if parsed, ok := parseMavenPURL(purl); ok {
		if groupID == "" {
			groupID = parsed.GroupID
		}
		if artifactID == "" {
			artifactID = parsed.ArtifactID
		}
		if packageType == "" {
			packageType = "maven"
		}
		purl = parsed.VersionlessPURL
	}
	if packageType == "" {
		if purl != "" || groupID != "" {
			packageType = "maven"
		} else {
			packageType = "jar"
		}
	}

	recordSource := strings.TrimSpace(pkg.Source)
	vulns := make([]db.VulnerabilityRecord, 0, len(pkg.Vulnerabilities))
	for _, vuln := range pkg.Vulnerabilities {
		converted, source := convertTrivyAdvisoryVulnerability(vuln)
		if converted.ID == "" {
			continue
		}
		if recordSource == "" && source != "" {
			recordSource = source
		}
		vulns = append(vulns, converted)
	}
	if recordSource == "" {
		recordSource = strings.TrimSpace(sourceFallback)
	}

	return normalizeRecord(db.PackageRecord{
		PackageType: packageType,
		PURL:        purl,
		GroupID:     groupID,
		ArtifactID:  artifactID,
		SHA1:        pkg.SHA1,
		Source:      recordSource,
		Aliases:     pkg.Aliases,
		Vulns:       vulns,
	})
}

func convertTrivyAdvisoryVulnerability(vuln trivyAdvisoryVulnerability) (db.VulnerabilityRecord, string) {
	id := strings.TrimSpace(vuln.ID)
	if id == "" {
		id = strings.TrimSpace(vuln.VulnerabilityID)
	}
	affectedRange := joinConstraintSets(vuln.VulnerableVersions)
	fixedVersions := vuln.PatchedVersions
	if len(fixedVersions) == 0 {
		fixedVersions = vuln.FixedVersions
	}
	source := strings.TrimSpace(vuln.Source)
	return db.VulnerabilityRecord{
		ID:            id,
		Severity:      normalizeSeverity(vuln.Severity),
		Title:         strings.TrimSpace(vuln.Title),
		Description:   strings.TrimSpace(vuln.Description),
		AffectedRange: affectedRange,
		FixedVersions: splitList(strings.Join(fixedVersions, ",")),
		References:    mergeStrings(vuln.References, nil),
		Operation:     firstNonEmpty(strings.TrimSpace(vuln.Operation), "upsert"),
	}, source
}

func joinConstraintSets(constraints []string) string {
	parts := make([]string, 0, len(constraints))
	for _, constraint := range constraints {
		normalized := normalizeConstraint(constraint)
		if normalized != "" {
			parts = append(parts, normalized)
		}
	}
	return strings.Join(parts, " || ")
}

func normalizeConstraint(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	replacer := strings.NewReplacer(" ", "", "\t", "", "\n", "")
	return replacer.Replace(raw)
}

func splitList(raw string) []string {
	parts := strings.Split(raw, ",")
	items := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return mergeStrings(items, nil)
}

func normalizeSeverity(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

func buildDisplayAlias(groupID, artifactID, displayName string) []db.Alias {
	displayName = strings.TrimSpace(displayName)
	if displayName == "" || strings.EqualFold(displayName, artifactID) {
		return nil
	}
	return []db.Alias{{GroupID: groupID, ArtifactID: displayName}}
}

type parsedMavenPURL struct {
	GroupID         string
	ArtifactID      string
	Version         string
	VersionlessPURL string
}

func parseMavenPURL(raw string) (parsedMavenPURL, bool) {
	if !strings.HasPrefix(raw, "pkg:maven/") {
		return parsedMavenPURL{}, false
	}
	trimmed := strings.TrimPrefix(raw, "pkg:maven/")
	if index := strings.Index(trimmed, "#"); index >= 0 {
		trimmed = trimmed[:index]
	}
	if index := strings.Index(trimmed, "?"); index >= 0 {
		trimmed = trimmed[:index]
	}
	pathPart := trimmed
	version := ""
	if parts := strings.SplitN(trimmed, "@", 2); len(parts) == 2 {
		pathPart = parts[0]
		version = parts[1]
	}
	segments := strings.Split(pathPart, "/")
	if len(segments) != 2 {
		return parsedMavenPURL{}, false
	}
	groupID, err := url.PathUnescape(segments[0])
	if err != nil {
		return parsedMavenPURL{}, false
	}
	artifactID, err := url.PathUnescape(segments[1])
	if err != nil {
		return parsedMavenPURL{}, false
	}
	decodedVersion, err := url.PathUnescape(version)
	if err != nil {
		decodedVersion = version
	}
	return parsedMavenPURL{
		GroupID:         groupID,
		ArtifactID:      artifactID,
		Version:         decodedVersion,
		VersionlessPURL: buildVersionlessMavenPURL(groupID, artifactID),
	}, true
}

func buildVersionlessMavenPURL(groupID, artifactID string) string {
	if strings.TrimSpace(groupID) == "" || strings.TrimSpace(artifactID) == "" {
		return ""
	}
	return "pkg:maven/" + url.PathEscape(groupID) + "/" + url.PathEscape(artifactID)
}

func inferPackageTypeFromResultType(resultType string) string {
	switch strings.ToLower(strings.TrimSpace(resultType)) {
	case "jar", "war", "ear", "par", "maven":
		return "maven"
	default:
		return "jar"
	}
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func sortRecordsForStableDebug(records []db.PackageRecord) {
	sort.Slice(records, func(i, j int) bool {
		return packageSortKey(records[i]) < packageSortKey(records[j])
	})
}
