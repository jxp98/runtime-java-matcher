package regression

import (
	"os"
	"path/filepath"
	"testing"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/bundlegen"
)

func TestBuildBaselineFromTrivyReport(t *testing.T) {
	content, err := os.ReadFile("../../testdata/bundlegen/trivy-report.json")
	if err != nil {
		t.Fatalf("read fixture failed: %v", err)
	}

	baseline, err := BuildBaselineFromTrivyReport(content, "compare-fixture-1")
	if err != nil {
		t.Fatalf("BuildBaselineFromTrivyReport failed: %v", err)
	}
	if len(baseline.Request.Components) != 2 {
		t.Fatalf("expected 2 baseline components, got %d", len(baseline.Request.Components))
	}
	if len(baseline.Findings) != 2 {
		t.Fatalf("expected 2 baseline findings, got %d", len(baseline.Findings))
	}
	if baseline.Request.Components[0].InventoryID == "" {
		t.Fatal("expected synthetic inventory id to be populated")
	}
	if baseline.Request.Components[0].EvidenceSource != "trivy_report" {
		t.Fatalf("unexpected evidence source: %s", baseline.Request.Components[0].EvidenceSource)
	}
}

func TestCompareAgainstGeneratedBundleHasNoDrift(t *testing.T) {
	content, err := os.ReadFile("../../testdata/bundlegen/trivy-report.json")
	if err != nil {
		t.Fatalf("read fixture failed: %v", err)
	}
	baseline, err := BuildBaselineFromTrivyReport(content, "compare-fixture-2")
	if err != nil {
		t.Fatalf("BuildBaselineFromTrivyReport failed: %v", err)
	}

	bundleDir := filepath.Join(t.TempDir(), "bundle-out")
	_, err = bundlegen.Generate(bundlegen.Config{
		InputPaths:  []string{"../../testdata/bundlegen/trivy-report.json"},
		OutputDir:   bundleDir,
		Source:      "trivy-report-import",
		GeneratedAt: "2026-05-09T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	response, err := RunLocalBundle(bundleDir, baseline.Request)
	if err != nil {
		t.Fatalf("RunLocalBundle failed: %v", err)
	}
	report := Compare(baseline, response)
	if report.Summary.MissingInMatcher != 0 {
		t.Fatalf("expected no missing findings, got %d", report.Summary.MissingInMatcher)
	}
	if report.Summary.ExtraInMatcher != 0 {
		t.Fatalf("expected no extra findings, got %d", report.Summary.ExtraInMatcher)
	}
	if report.Summary.SharedVulnerabilities != 2 {
		t.Fatalf("expected 2 shared vulnerabilities, got %d", report.Summary.SharedVulnerabilities)
	}
}

func TestCompareDetectsMissingMatcherFinding(t *testing.T) {
	baseline := Baseline{
		Request: api.MatchRequest{RequestID: "compare-drift-1"},
		Findings: []Finding{
			{ComponentKey: "org.apache.tomcat:tomcat-jdbc@8.5.82", VulnerabilityID: "CVE-2024-56337"},
			{ComponentKey: "org.eclipse.jdt.core.compiler:ecj@3.12.3.v20170228-1205", VulnerabilityID: "CVE-2024-00001"},
		},
	}
	response := api.MatchResponse{
		RequestID: "compare-drift-1",
		Matches: []api.MatchEntry{
			{
				InventoryID: "trivy-report:org.apache.tomcat:tomcat-jdbc@8.5.82",
				Component: api.NormalizedComp{
					PackageType: "maven",
					GroupID:     "org.apache.tomcat",
					ArtifactID:  "tomcat-jdbc",
					Version:     "8.5.82",
				},
				Vulnerabilities: []api.Vulnerability{{ID: "CVE-2024-56337"}},
			},
		},
	}

	report := Compare(baseline, response)
	if report.Summary.MissingInMatcher != 1 {
		t.Fatalf("expected 1 missing finding, got %d", report.Summary.MissingInMatcher)
	}
	if len(report.MissingInMatcher) != 1 {
		t.Fatalf("expected 1 missing finding entry, got %d", len(report.MissingInMatcher))
	}
	if report.MissingInMatcher[0].VulnerabilityID != "CVE-2024-00001" {
		t.Fatalf("unexpected missing vulnerability: %s", report.MissingInMatcher[0].VulnerabilityID)
	}
}
