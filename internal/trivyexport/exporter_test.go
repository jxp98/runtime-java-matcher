package trivyexport

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestExportFromTrivyFixtureDir(t *testing.T) {
	outputPath := filepath.Join(t.TempDir(), "trivy-advisory-export.json")
	summary, err := Export(Config{
		InputDir:    "../../testdata/trivyexport/db",
		OutputPath:  outputPath,
		GeneratedAt: "2026-05-08T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("Export failed: %v", err)
	}
	if summary.PackageCount != 2 {
		t.Fatalf("expected 2 packages, got %d", summary.PackageCount)
	}
	if summary.VulnerabilityCount != 3 {
		t.Fatalf("expected 3 vulnerabilities, got %d", summary.VulnerabilityCount)
	}
	if summary.SourceBucketCount != 2 {
		t.Fatalf("expected 2 source buckets, got %d", summary.SourceBucketCount)
	}

	content, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read output failed: %v", err)
	}
	var export AdvisoryExport
	if err := json.Unmarshal(content, &export); err != nil {
		t.Fatalf("decode output failed: %v", err)
	}
	if export.Schema != "trivy-advisory-export/v1" {
		t.Fatalf("unexpected schema: %s", export.Schema)
	}
	if len(export.Packages) != 2 {
		t.Fatalf("expected 2 packages in export, got %d", len(export.Packages))
	}
	if export.Packages[0].Source == "" {
		t.Fatalf("expected source to be filled")
	}

	var jackson AdvisoryPackage
	for _, pkg := range export.Packages {
		if pkg.GroupID == "com.fasterxml.jackson.core" && pkg.ArtifactID == "jackson-databind" {
			jackson = pkg
		}
	}
	if len(jackson.Vulnerabilities) != 2 {
		t.Fatalf("expected 2 jackson vulnerabilities, got %d", len(jackson.Vulnerabilities))
	}
	if jackson.Source != "ghsa,glad" {
		t.Fatalf("expected merged jackson source ghsa,glad, got %s", jackson.Source)
	}
}
