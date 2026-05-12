package matcher

import (
	"os"
	"path/filepath"
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
		Components: []api.ComponentInput{{
			InventoryID:    "runtime-java:1",
			GroupID:        "org.apache.logging.log4j",
			ArtifactID:     "log4j-core",
			Version:        "2.14.1",
			RuntimePath:    "/srv/app/lib/log4j-core-2.14.1.jar",
			PackageType:    "maven",
			Confidence:     "high",
			EvidenceSource: "pom.properties",
		}},
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
		Components: []api.ComponentInput{{
			InventoryID:    "runtime-java:2",
			GroupID:        "org.springframework",
			ArtifactID:     "spring-core",
			VersionAlt:     "5.3.17",
			RuntimePath:    "/srv/app/demo-app.jar",
			ArchivePath:    "/srv/app/demo-app.jar",
			EvidenceSource: "pom.properties",
			Confidence:     "high",
		}},
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
		Components: []api.ComponentInput{{
			InventoryID:    "runtime-java:alias-1",
			GroupID:        "org.apache.tomcat",
			ArtifactID:     "Apache Tomcat JDBC Connection Pool",
			PackageName:    "Apache Tomcat JDBC Connection Pool",
			Version:        "8.5.82",
			RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/tomcat-jdbc.jar",
			EvidenceSource: "manifest",
			Confidence:     "medium",
		}},
	})

	if len(response.Matches) != 1 {
		t.Fatalf("expected 1 alias match, got %d", len(response.Matches))
	}
	if response.Matches[0].Component.ArtifactID != "tomcat-jdbc" {
		t.Fatalf("expected canonical artifact id, got %s", response.Matches[0].Component.ArtifactID)
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
		Components: []api.ComponentInput{{
			InventoryID:    "runtime-java:3",
			VersionAlt:     "2.14.1",
			RuntimePath:    "/srv/app/demo-app.jar",
			ArchivePath:    "/srv/app/demo-app.jar",
			SHA1:           "c5a52d75b03c4d197b35446d5cd0e7f85a8e986b",
			EvidenceSource: "pom.properties",
			Confidence:     "high",
		}},
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

func TestServiceMatchWithPathInArchiveFallback(t *testing.T) {
	index, err := db.Load("../../testdata/formal-db")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Match(api.MatchRequest{
		RequestID:     "session-formal-path-1",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{{
			InventoryID:    "runtime-java:path-1",
			Version:        "8.5.82",
			RuntimePath:    "/srv/app/demo-app.jar",
			ArchivePath:    "/srv/app/demo-app.jar",
			PathInArchive:  "BOOT-INF/lib/tomcat-jdbc-8.5.82.jar",
			EvidenceSource: "filename",
			Confidence:     "low",
		}},
	})

	if len(response.Matches) != 1 {
		t.Fatalf("expected 1 path fallback match, got %d", len(response.Matches))
	}
	if response.Matches[0].Component.ArtifactID != "tomcat-jdbc" {
		t.Fatalf("unexpected artifact id: %s", response.Matches[0].Component.ArtifactID)
	}
	if response.Matches[0].Component.GroupID != "org.apache.tomcat" {
		t.Fatalf("unexpected group id: %s", response.Matches[0].Component.GroupID)
	}
	if len(response.Matches[0].Vulnerabilities) == 0 {
		t.Fatal("expected vulnerabilities, got none")
	}
	if response.Matches[0].Vulnerabilities[0].ID != "CVE-2024-56337" {
		t.Fatalf("unexpected vulnerability id: %s", response.Matches[0].Vulnerabilities[0].ID)
	}
}

func TestServiceMatchWithRuntimeFamilyCandidate(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "family-db.json")
	content := []byte(`[
	  {
	    "package_type": "maven",
	    "group_id": "org.apache.tomcat",
	    "artifact_id": "tomcat-catalina",
	    "source": "test-family-db",
	    "vulnerabilities": [
	      {
	        "id": "CVE-TEST-TOMCAT-CATALINA",
	        "severity": "high",
	        "affected_range": ">=8.0,<9.0",
	        "operation": "upsert"
	      }
	    ]
	  },
	  {
	    "package_type": "maven",
	    "group_id": "org.apache.tomcat",
	    "artifact_id": "tomcat-tribes",
	    "source": "test-family-db",
	    "vulnerabilities": [
	      {
	        "id": "CVE-TEST-TOMCAT-TRIBES",
	        "severity": "medium",
	        "affected_range": ">=8.0,<9.0",
	        "operation": "upsert"
	      }
	    ]
	  }
	]`)
	if err := os.WriteFile(dbPath, content, 0o644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	index, err := db.Load(dbPath)
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Match(api.MatchRequest{
		RequestID:     "session-family-1",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{
			{
				InventoryID:    "runtime-java:family-1",
				GroupID:        "org.apache.tomcat",
				PackageName:    "Apache Tomcat",
				Version:        "8.5.82",
				RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/catalina.jar",
				EvidenceSource: "manifest",
				Confidence:     "medium",
			},
			{
				InventoryID:    "runtime-java:family-2",
				PackageName:    "Apache Tomcat",
				Version:        "8.5.82",
				RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/catalina-tribes.jar",
				EvidenceSource: "manifest",
				Confidence:     "medium",
			},
		},
	})

	if len(response.Matches) != 2 {
		t.Fatalf("expected 2 family-candidate matches, got %d", len(response.Matches))
	}
	if response.Matches[0].Component.ArtifactID != "tomcat-catalina" {
		t.Fatalf("unexpected first artifact id: %s", response.Matches[0].Component.ArtifactID)
	}
	if response.Matches[1].Component.ArtifactID != "tomcat-tribes" {
		t.Fatalf("unexpected second artifact id: %s", response.Matches[1].Component.ArtifactID)
	}
	if response.Matches[0].Vulnerabilities[0].ID != "CVE-TEST-TOMCAT-CATALINA" {
		t.Fatalf("unexpected first vulnerability id: %s", response.Matches[0].Vulnerabilities[0].ID)
	}
	if response.Matches[1].Vulnerabilities[0].ID != "CVE-TEST-TOMCAT-TRIBES" {
		t.Fatalf("unexpected second vulnerability id: %s", response.Matches[1].Vulnerabilities[0].ID)
	}
}

func TestServiceDiagnoseClassifiesComponents(t *testing.T) {
	index, err := db.Load("../../testdata/formal-db")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Diagnose(api.MatchRequest{
		RequestID:     "diagnose-1",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{
			{
				InventoryID:    "runtime-java:matched-1",
				GroupID:        "org.apache.tomcat",
				ArtifactID:     "Apache Tomcat JDBC Connection Pool",
				PackageName:    "Apache Tomcat JDBC Connection Pool",
				Version:        "8.5.82",
				RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/tomcat-jdbc.jar",
				EvidenceSource: "manifest",
			},
			{
				InventoryID:    "runtime-java:no-adv-1",
				GroupID:        "org.apache.tomcat",
				ArtifactID:     "tomcat-juli",
				Version:        "8.5.82",
				RuntimePath:    "/opt/apache-tomcat-8.5.82/lib/tomcat-juli.jar",
				EvidenceSource: "filename",
			},
			{
				InventoryID:    "runtime-java:no-ver-1",
				ArtifactID:     "bootstrap",
				RuntimePath:    "/opt/apache-tomcat-8.5.82/bin/bootstrap.jar",
				EvidenceSource: "filename",
			},
		},
	})

	if response.Summary.TotalComponents != 3 {
		t.Fatalf("unexpected total components: %d", response.Summary.TotalComponents)
	}
	if response.Summary.MatchedComponents != 1 {
		t.Fatalf("unexpected matched components: %d", response.Summary.MatchedComponents)
	}
	if response.Summary.NoAdvisory != 1 {
		t.Fatalf("unexpected no advisory count: %d", response.Summary.NoAdvisory)
	}
	if response.Summary.MissingVersion != 1 {
		t.Fatalf("unexpected missing version count: %d", response.Summary.MissingVersion)
	}
	if response.Components[0].Status != api.MatchStatusMatched {
		t.Fatalf("unexpected first status: %s", response.Components[0].Status)
	}
	if response.Components[0].SelectedArtifactID != "tomcat-jdbc" {
		t.Fatalf("unexpected canonical artifact id: %s", response.Components[0].SelectedArtifactID)
	}
	if response.Components[1].Status != api.MatchStatusNoAdvisory {
		t.Fatalf("unexpected second status: %s", response.Components[1].Status)
	}
	if response.Components[2].Status != api.MatchStatusMissingVersion {
		t.Fatalf("unexpected third status: %s", response.Components[2].Status)
	}
}

func TestServiceDiagnoseAddsConservativeNoiseHints(t *testing.T) {
	index, err := db.Load("../../testdata/formal-db")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}

	service := New(index, "test-matcher")
	response := service.Diagnose(api.MatchRequest{
		RequestID:     "diagnose-noise-1",
		SchemaVersion: "1.0",
		ScanMode:      "full",
		Agent:         api.Agent{ID: "001"},
		Components: []api.ComponentInput{
			{
				InventoryID:           "runtime-java:bootstrap-1",
				ArtifactID:            "bootstrap",
				Version:               "8.5.82",
				RuntimePath:           "/opt/apache-tomcat-8.5.82/bin/bootstrap.jar",
				DiscoverySource:       "classpath",
				EvidenceSource:        "filename",
				IsDirectRuntimeTarget: boolPtr(false),
				IsNested:              boolPtr(false),
			},
			{
				InventoryID:           "runtime-java:juli-1",
				GroupID:               "org.apache.tomcat",
				ArtifactID:            "tomcat-juli",
				Version:               "8.5.82",
				RuntimePath:           "/opt/apache-tomcat-8.5.82/bin/tomcat-juli.jar",
				DiscoverySource:       "fd",
				EvidenceSource:        "filename",
				IsDirectRuntimeTarget: boolPtr(false),
				IsNested:              boolPtr(false),
			},
		},
	})

	if len(response.Components) != 2 {
		t.Fatalf("unexpected component count: %d", len(response.Components))
	}

	bootstrap := response.Components[0]
	if bootstrap.Status != api.MatchStatusIdentityUnresolved {
		t.Fatalf("unexpected bootstrap status: %s", bootstrap.Status)
	}
	if !bootstrap.SuppressionCandidate {
		t.Fatal("expected bootstrap to be marked as suppression candidate")
	}
	if bootstrap.SuppressionReason != "launcher_bin_archive_identity_unresolved" {
		t.Fatalf("unexpected bootstrap suppression reason: %s", bootstrap.SuppressionReason)
	}
	if !containsString(bootstrap.NoiseFlags, "bin_directory_archive") {
		t.Fatalf("expected bootstrap noise flags to include bin_directory_archive: %#v", bootstrap.NoiseFlags)
	}
	if !containsString(bootstrap.NoiseFlags, "launcher_like_archive") {
		t.Fatalf("expected bootstrap noise flags to include launcher_like_archive: %#v", bootstrap.NoiseFlags)
	}
	if bootstrap.IsDirectRuntimeTarget == nil || *bootstrap.IsDirectRuntimeTarget {
		t.Fatalf("unexpected bootstrap direct target flag: %#v", bootstrap.IsDirectRuntimeTarget)
	}

	juli := response.Components[1]
	if juli.Status != api.MatchStatusNoAdvisory {
		t.Fatalf("unexpected tomcat-juli status: %s", juli.Status)
	}
	if juli.SuppressionCandidate {
		t.Fatal("did not expect tomcat-juli to be marked as suppression candidate")
	}
	if !containsString(juli.NoiseFlags, "filename_only_identity") {
		t.Fatalf("expected tomcat-juli noise flags to include filename_only_identity: %#v", juli.NoiseFlags)
	}
}

func boolPtr(value bool) *bool {
	return &value
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
