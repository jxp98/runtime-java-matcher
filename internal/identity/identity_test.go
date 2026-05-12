package identity

import (
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

	if len(candidates) < 2 {
		t.Fatalf("expected at least 2 candidates, got %d", len(candidates))
	}
	if candidates[0] != "tomcat-jdbc" {
		t.Fatalf("unexpected first candidate: %#v", candidates)
	}
	if !containsValue(candidates, "Apache Tomcat JDBC Connection Pool") {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
	if containsValue(candidates, "tomcat-tomcat-jdbc") {
		t.Fatalf("did not expect duplicated family prefix candidate: %#v", candidates)
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
	if candidates[len(candidates)-1].Value != "Apache Tomcat JDBC Connection Pool" {
		t.Fatalf("unexpected last candidate: %#v", candidates[len(candidates)-1])
	}
	if candidates[0].Priority <= candidates[len(candidates)-1].Priority {
		t.Fatalf("expected filename candidate to outrank display name: %#v", candidates)
	}
}

func TestBuildArtifactCandidatesAddsRuntimeFamilyCandidates(t *testing.T) {
	candidates := BuildArtifactCandidates(
		"Apache Tomcat",
		"Apache Tomcat",
		"",
		"/opt/apache-tomcat-8.5.82/lib/catalina-tribes.jar",
		"manifest",
	)

	values := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		values = append(values, candidate.Value)
	}

	expected := []string{"catalina-tribes", "apache-tomcat-catalina-tribes", "tomcat-catalina-tribes", "apache-tomcat-tribes", "tomcat-tribes"}
	for _, value := range expected {
		if !containsValue(values, value) {
			t.Fatalf("expected candidate %q in %#v", value, values)
		}
	}

	if containsValue(values, "apache-tomcat-Apache Tomcat") {
		t.Fatalf("did not expect display-name family candidate in %#v", values)
	}
}

func containsValue(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
