package identity

import (
	"reflect"
	"testing"
)

func TestInferArtifactAndVersionPrefersPathInArchive(t *testing.T) {
	artifactID, version := InferArtifactAndVersion(
		"BOOT-INF/lib/spring-core-5.3.17.jar",
		"/srv/app/demo-app.jar",
	)
	if artifactID != "spring-core" {
		t.Fatalf("unexpected artifact id: %s", artifactID)
	}
	if version != "5.3.17" {
		t.Fatalf("unexpected version: %s", version)
	}
}

func TestCandidateArtifactsDeduplicatesAndPrioritizesFilenameEvidence(t *testing.T) {
	candidates := CandidateArtifacts(
		"Apache Tomcat JDBC Connection Pool",
		"Apache Tomcat JDBC Connection Pool",
		"BOOT-INF/lib/tomcat-jdbc-8.5.82.jar",
		"/opt/apache-tomcat-8.5.82/lib/tomcat-jdbc.jar",
	)

	expected := []string{
		"tomcat-jdbc",
		"Apache Tomcat JDBC Connection Pool",
	}
	if !reflect.DeepEqual(candidates, expected) {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}

func TestBuildArtifactCandidatesMarksDisplayNameAsWeaker(t *testing.T) {
	candidates := BuildArtifactCandidates(
		"Apache Tomcat JDBC Connection Pool",
		"Apache Tomcat JDBC Connection Pool",
		"BOOT-INF/lib/tomcat-jdbc-8.5.82.jar",
		"/opt/apache-tomcat-8.5.82/lib/tomcat-jdbc.jar",
		"manifest",
	)
	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(candidates))
	}
	if candidates[0].Value != "tomcat-jdbc" || candidates[0].Source != "path_in_archive" {
		t.Fatalf("unexpected first candidate: %#v", candidates[0])
	}
	if candidates[1].Value != "Apache Tomcat JDBC Connection Pool" {
		t.Fatalf("unexpected second candidate: %#v", candidates[1])
	}
	if candidates[0].Priority <= candidates[1].Priority {
		t.Fatalf("expected filename candidate to outrank display name: %#v", candidates)
	}
}
