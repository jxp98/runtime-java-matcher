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

func TestCandidateArtifactsDeduplicatesAndKeepsOrder(t *testing.T) {
	candidates := CandidateArtifacts(
		"Apache Tomcat JDBC Connection Pool",
		"Apache Tomcat JDBC Connection Pool",
		"/opt/apache-tomcat-8.5.82/lib/tomcat-jdbc.jar",
		"BOOT-INF/lib/tomcat-jdbc-8.5.82.jar",
	)

	expected := []string{
		"Apache Tomcat JDBC Connection Pool",
		"tomcat-jdbc",
	}
	if !reflect.DeepEqual(candidates, expected) {
		t.Fatalf("unexpected candidates: %#v", candidates)
	}
}
