package matcher

import (
	"testing"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
)

func TestServiceMatch(t *testing.T) {
	index, err := db.Load("../../testdata/vulndb.json")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Match(api.MatchRequest{
		RequestID:     "session-1",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{
			{
				InventoryID:    "runtime-java:1",
				GroupID:        "org.apache.logging.log4j",
				ArtifactID:     "log4j-core",
				Version:        "2.14.1",
				RuntimePath:    "/srv/app/lib/log4j-core-2.14.1.jar",
				PackageType:    "maven",
				Confidence:     "high",
				EvidenceSource: "pom.properties",
			},
		},
	})

	if len(response.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(response.Matches))
	}
	if len(response.Matches[0].Vulnerabilities) == 0 {
		t.Fatalf("expected vulnerabilities, got none")
	}
	if response.Matches[0].Vulnerabilities[0].ID != "CVE-2021-44228" {
		t.Fatalf("unexpected vulnerability id: %s", response.Matches[0].Vulnerabilities[0].ID)
	}
}

func TestParseMavenPURL(t *testing.T) {
	groupID, artifactID, versionValue, ok := parseMavenPURL("pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1")
	if !ok {
		t.Fatal("expected purl to parse")
	}
	if groupID != "org.apache.logging.log4j" || artifactID != "log4j-core" || versionValue != "2.14.1" {
		t.Fatalf("unexpected parse result: %s %s %s", groupID, artifactID, versionValue)
	}
}

func TestServiceMatchAcceptsVersionAltField(t *testing.T) {
	index, err := db.Load("../../testdata/vulndb.json")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Match(api.MatchRequest{
		RequestID:     "session-2",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{
			{
				InventoryID:    "runtime-java:2",
				GroupID:        "org.springframework",
				ArtifactID:     "spring-core",
				VersionAlt:     "5.3.17",
				RuntimePath:    "/srv/app/demo-app.jar",
				ArchivePath:    "/srv/app/demo-app.jar",
				EvidenceSource: "pom.properties",
				Confidence:     "high",
			},
		},
	})

	if len(response.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(response.Matches))
	}
	if response.Matches[0].Component.Version != "5.3.17" {
		t.Fatalf("unexpected normalized version: %s", response.Matches[0].Component.Version)
	}
	if len(response.Matches[0].Vulnerabilities) == 0 {
		t.Fatal("expected vulnerabilities, got none")
	}
}

func TestServiceMatchWithFormalDBAliasArtifact(t *testing.T) {
	index, err := db.Load("../../testdata/formal-db")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Match(api.MatchRequest{
		RequestID:     "session-formal-alias-1",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{
			{
				InventoryID:    "runtime-java:alias-1",
				GroupID:        "org.apache.tomcat",
				ArtifactID:     "Apache Tomcat JDBC Connection Pool",
				Version:        "8.5.82",
				RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/tomcat-jdbc.jar",
				EvidenceSource: "manifest",
				Confidence:     "medium",
			},
		},
	})

	if len(response.Matches) != 1 {
		t.Fatalf("expected 1 alias match, got %d", len(response.Matches))
	}
	if len(response.Matches[0].Vulnerabilities) == 0 {
		t.Fatal("expected alias vulnerability match, got none")
	}
	if response.Matches[0].Vulnerabilities[0].ID != "CVE-2024-56337" {
		t.Fatalf("unexpected alias vulnerability id: %s", response.Matches[0].Vulnerabilities[0].ID)
	}
}

func TestServiceMatchBySHA1(t *testing.T) {
	index, err := db.Load("../../testdata/vulndb.json")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Match(api.MatchRequest{
		RequestID:     "session-3",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{
			{
				InventoryID:    "runtime-java:3",
				VersionAlt:     "2.14.1",
				RuntimePath:    "/srv/app/demo-app.jar",
				ArchivePath:    "/srv/app/demo-app.jar",
				SHA1:           "c5a52d75b03c4d197b35446d5cd0e7f85a8e986b",
				EvidenceSource: "pom.properties",
				Confidence:     "high",
			},
		},
	})

	if len(response.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(response.Matches))
	}
	if response.Matches[0].Component.GroupID != "org.apache.logging.log4j" {
		t.Fatalf("unexpected group id: %s", response.Matches[0].Component.GroupID)
	}
	if response.Matches[0].Component.ArtifactID != "log4j-core" {
		t.Fatalf("unexpected artifact id: %s", response.Matches[0].Component.ArtifactID)
	}
	if len(response.Matches[0].Vulnerabilities) == 0 {
		t.Fatal("expected vulnerabilities, got none")
	}
}
