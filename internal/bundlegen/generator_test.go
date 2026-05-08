package bundlegen

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/matcher"
	"runtime-java-matcher/internal/trivyexport"
)

func TestGenerateBundleFromNormalizedExports(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "bundle-out")
	report, err := Generate(Config{
		InputPaths:  []string{"../../testdata/bundlegen/input"},
		OutputDir:   outputDir,
		Source:      "trivy-java-export",
		Version:     "2026.05.0",
		GeneratedAt: "2026-05-08T00:00:00Z",
		ShardSize:   2,
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if report.PackageCount != 3 {
		t.Fatalf("expected 3 merged packages, got %d", report.PackageCount)
	}
	if report.VulnerabilityCount != 3 {
		t.Fatalf("expected 3 vulnerabilities, got %d", report.VulnerabilityCount)
	}
	if report.ShardCount != 2 {
		t.Fatalf("expected 2 shards, got %d", report.ShardCount)
	}

	index, err := db.Load(outputDir)
	if err != nil {
		t.Fatalf("db.Load on generated bundle failed: %v", err)
	}
	if index.Size() != 3 {
		t.Fatalf("expected loader to see 3 package records, got %d", index.Size())
	}

	log4j := index.FindByGA("org.apache.logging.log4j", "log4j-core")
	if len(log4j) != 1 {
		t.Fatalf("expected one merged log4j record, got %d", len(log4j))
	}
	if len(log4j[0].SHA1) != 2 {
		t.Fatalf("expected two merged sha1 values, got %d", len(log4j[0].SHA1))
	}
	if len(log4j[0].Vulns) != 1 {
		t.Fatalf("expected one deduped vulnerability, got %d", len(log4j[0].Vulns))
	}

	reportPath := filepath.Join(outputDir, "bundle-report.json")
	content, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatalf("read report failed: %v", err)
	}
	var decoded Report
	if err := json.Unmarshal(content, &decoded); err != nil {
		t.Fatalf("decode report failed: %v", err)
	}
	if decoded.Source != "trivy-java-export" {
		t.Fatalf("expected report source trivy-java-export, got %s", decoded.Source)
	}
}

func TestGenerateBundleFromTrivyReport(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "trivy-report-out")
	report, err := Generate(Config{
		InputPaths:  []string{"../../testdata/bundlegen/trivy-report.json"},
		OutputDir:   outputDir,
		Source:      "trivy-report-import",
		GeneratedAt: "2026-05-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if report.PackageCount != 2 {
		t.Fatalf("expected 2 packages from trivy report, got %d", report.PackageCount)
	}

	index, err := db.Load(outputDir)
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}
	tomcat := index.FindByGA("org.apache.tomcat", "tomcat-jdbc")
	if len(tomcat) != 1 {
		t.Fatalf("expected one tomcat-jdbc record, got %d", len(tomcat))
	}
	if len(tomcat[0].Aliases) != 1 || tomcat[0].Aliases[0].ArtifactID != "Apache Tomcat JDBC Connection Pool" {
		t.Fatalf("expected tomcat display alias to be preserved")
	}
	if len(tomcat[0].Vulns) != 1 || tomcat[0].Vulns[0].AffectedRange != "8.5.82" {
		t.Fatalf("expected exact-version affected range from trivy report")
	}
	if len(tomcat[0].Vulns[0].FixedVersions) != 2 {
		t.Fatalf("expected two fixed versions parsed from trivy report")
	}
	if tomcat[0].Source != "ghsa" {
		t.Fatalf("expected ghsa source, got %s", tomcat[0].Source)
	}
}

func TestGenerateBundleFromJSONGoldenDir(t *testing.T) {
	reportDir := filepath.Join(t.TempDir(), "trivy-golden")
	if err := os.MkdirAll(reportDir, 0o755); err != nil {
		t.Fatalf("mkdir report dir failed: %v", err)
	}
	content, err := os.ReadFile("../../testdata/bundlegen/trivy-report.json")
	if err != nil {
		t.Fatalf("read trivy report fixture failed: %v", err)
	}
	goldenPath := filepath.Join(reportDir, "runtime-java.json.golden")
	if err := os.WriteFile(goldenPath, content, 0o644); err != nil {
		t.Fatalf("write json.golden fixture failed: %v", err)
	}

	outputDir := filepath.Join(t.TempDir(), "trivy-golden-out")
	report, err := Generate(Config{
		InputPaths:  []string{reportDir},
		OutputDir:   outputDir,
		Source:      "trivy-report-import",
		GeneratedAt: "2026-05-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate from json.golden dir failed: %v", err)
	}
	if report.PackageCount != 2 {
		t.Fatalf("expected 2 packages from json.golden dir, got %d", report.PackageCount)
	}

	index, err := db.Load(outputDir)
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}
	if len(index.FindByGA("org.apache.tomcat", "tomcat-jdbc")) != 1 {
		t.Fatalf("expected tomcat-jdbc to be imported from json.golden dir")
	}
}

func TestGenerateBundleFromTrivyAdvisoryExport(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "trivy-advisory-out")
	report, err := Generate(Config{
		InputPaths:  []string{"../../testdata/bundlegen/trivy-advisory-export.json"},
		OutputDir:   outputDir,
		Source:      "trivy-java-export",
		GeneratedAt: "2026-05-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if report.PackageCount != 2 {
		t.Fatalf("expected 2 packages from advisory export, got %d", report.PackageCount)
	}

	index, err := db.Load(outputDir)
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}
	log4j := index.FindByGA("org.apache.logging.log4j", "log4j-core")
	if len(log4j) != 1 {
		t.Fatalf("expected one log4j record, got %d", len(log4j))
	}
	if len(log4j[0].Vulns) != 1 {
		t.Fatalf("expected one log4j vulnerability, got %d", len(log4j[0].Vulns))
	}
	if log4j[0].Vulns[0].AffectedRange != ">=2.0,<2.15.0 || >=2.16.0,<2.17.0" {
		t.Fatalf("unexpected advisory affected range: %s", log4j[0].Vulns[0].AffectedRange)
	}
	if log4j[0].Source != "ghsa" {
		t.Fatalf("expected ghsa source, got %s", log4j[0].Source)
	}
}

func TestExportThenGenerateBundleEndToEnd(t *testing.T) {
	exportPath := filepath.Join(t.TempDir(), "trivy-advisory-export.json")
	_, err := trivyexport.Export(trivyexport.Config{
		InputDir:    "../../testdata/trivyexport/db",
		OutputPath:  exportPath,
		GeneratedAt: "2026-05-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("trivyexport.Export failed: %v", err)
	}

	bundleDir := filepath.Join(t.TempDir(), "runtime-java-bundle")
	_, err = Generate(Config{
		InputPaths:     []string{exportPath},
		OutputDir:      bundleDir,
		Source:         "trivy-java-export",
		AdvisorySource: "trivy-db",
		GeneratedAt:    "2026-05-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate from exported advisory failed: %v", err)
	}

	index, err := db.Load(bundleDir)
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := matcher.New(index, "runtime-java-matcher-test")
	response := service.Match(api.MatchRequest{
		RequestID:     "trivyexport-e2e",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Components: []api.ComponentInput{
			{
				InventoryID: "runtime-java:jackson-1",
				PackageType: "maven",
				GroupID:     "com.fasterxml.jackson.core",
				ArtifactID:  "jackson-databind",
				Version:     "2.9.10.3",
			},
			{
				InventoryID: "runtime-java:spring-1",
				PackageType: "maven",
				GroupID:     "org.springframework",
				ArtifactID:  "spring-beans",
				Version:     "5.3.17",
			},
		},
	})

	if len(response.Matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(response.Matches))
	}
	if len(response.Matches[0].Vulnerabilities) != 1 {
		t.Fatalf("expected jackson to have 1 vulnerability, got %d", len(response.Matches[0].Vulnerabilities))
	}
	if response.Matches[0].Vulnerabilities[0].ID != "CVE-2020-9548" {
		t.Fatalf("unexpected jackson vulnerability: %s", response.Matches[0].Vulnerabilities[0].ID)
	}
	if len(response.Matches[1].Vulnerabilities) != 1 {
		t.Fatalf("expected spring to have 1 vulnerability, got %d", len(response.Matches[1].Vulnerabilities))
	}
	if response.Matches[1].Vulnerabilities[0].ID != "CVE-2022-22965" {
		t.Fatalf("unexpected spring vulnerability: %s", response.Matches[1].Vulnerabilities[0].ID)
	}
}

func TestGenerateRejectsNonEmptyOutputDir(t *testing.T) {
	outputDir := filepath.Join(t.TempDir(), "bundle-out")
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(outputDir, "keep.txt"), []byte("x"), 0o644); err != nil {
		t.Fatalf("write keep.txt failed: %v", err)
	}

	_, err := Generate(Config{
		InputPaths: []string{"../../testdata/bundlegen/input"},
		OutputDir:  outputDir,
	})
	if err == nil {
		t.Fatalf("expected non-empty output dir error")
	}
}
