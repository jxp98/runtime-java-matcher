package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/matcher"
)

func TestHealthz(t *testing.T) {
	index, err := db.Load("../../testdata/formal-db")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}
	metadata := index.Metadata()
	mux := NewMux(matcher.New(index, "test-matcher"), api.HealthResponse{
		Status:              "ok",
		Backend:             "bundle",
		Database:            "../../testdata/formal-db",
		PackageSize:         index.Size(),
		DatabaseFormat:      metadata.Format,
		DatabaseSource:      metadata.Source,
		DatabaseVersion:     metadata.Version,
		DatabaseGeneratedAt: metadata.GeneratedAt,
	}, nil)
	request := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}

	var health api.HealthResponse
	if err := json.Unmarshal(response.Body.Bytes(), &health); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if health.DatabaseFormat != "runtime-java-bundle" {
		t.Fatalf("expected runtime-java-bundle format, got %s", health.DatabaseFormat)
	}
	if health.DatabaseSource != "trivy-java-export" {
		t.Fatalf("expected trivy-java-export source, got %s", health.DatabaseSource)
	}
}

func TestMatchEndpoint(t *testing.T) {
	index, err := db.Load("../../testdata/vulndb.json")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}
	mux := NewMux(matcher.New(index, "test-matcher"), api.HealthResponse{
		Status:      "ok",
		Backend:     "bundle",
		Database:    "../../testdata/vulndb.json",
		PackageSize: index.Size(),
	}, nil)
	body, err := os.ReadFile("../../testdata/request.json")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	request := httptest.NewRequest(http.MethodPost, "/runtime-java/match", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}

	var matchResponse api.MatchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &matchResponse); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if len(matchResponse.Matches) != 2 {
		t.Fatalf("expected 2 matches, got %d", len(matchResponse.Matches))
	}
}

func TestMatchEndpointWithRawInventoryComponent(t *testing.T) {
	index, err := db.Load("../../testdata/vulndb.json")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}
	mux := NewMux(matcher.New(index, "test-matcher"), api.HealthResponse{
		Status:      "ok",
		Backend:     "bundle",
		Database:    "../../testdata/vulndb.json",
		PackageSize: index.Size(),
	}, nil)

	body := []byte(`{
	  "request_id": "raw-session-001",
	  "schema_version": "1.0",
	  "scan_mode": "full",
	  "agent": {"id": "001"},
	  "components": [
	    {
	      "_inventory_id": "runtime-java:raw-1",
	      "_document_version": 1,
	      "_inventory_index": "wazuh-states-inventory-runtime-java-components",
	      "package": {
	        "name": "log4j-core",
	        "type": "jar",
	        "version": "2.14.1"
	      },
	      "file": {
	        "path": "/srv/app/lib/log4j-core-2.14.1.jar",
	        "hash": {
	          "sha1": "c5a52d75b03c4d197b35446d5cd0e7f85a8e986b"
	        }
	      },
	      "wazuh": {
	        "runtime_java": {
	          "group_id": "org.apache.logging.log4j",
	          "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1",
	          "evidence_source": "pom.properties",
	          "confidence": "high",
	          "archive_path": "/srv/app/demo-app.jar"
	        }
	      }
	    }
	  ]
	}`)
	request := httptest.NewRequest(http.MethodPost, "/runtime-java/match", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}

	var matchResponse api.MatchResponse
	if err := json.Unmarshal(response.Body.Bytes(), &matchResponse); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if len(matchResponse.Matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matchResponse.Matches))
	}
	if len(matchResponse.Matches[0].Vulnerabilities) == 0 {
		t.Fatal("expected vulnerabilities for raw inventory input")
	}
}

func TestDiagnoseEndpoint(t *testing.T) {
	index, err := db.Load("../../testdata/formal-db")
	if err != nil {
		t.Fatalf("db.Load failed: %v", err)
	}
	mux := NewMux(matcher.New(index, "test-matcher"), api.HealthResponse{
		Status:      "ok",
		Backend:     "bundle",
		Database:    "../../testdata/formal-db",
		PackageSize: index.Size(),
	}, nil)

	body := []byte(`{
	  "request_id": "diagnose-http-1",
	  "schema_version": "1.0",
	  "scan_mode": "full",
	  "agent": {"id": "001"},
	  "components": [
	    {
	      "_inventory_id": "runtime-java:matched-1",
	      "group_id": "org.apache.tomcat",
	      "artifact_id": "Apache Tomcat JDBC Connection Pool",
	      "package_name": "Apache Tomcat JDBC Connection Pool",
	      "version": "8.5.82",
	      "runtime_path": "/opt/apache-tomcat-8.5.82/lib/tomcat-jdbc.jar",
	      "evidence_source": "manifest"
	    },
	    {
	      "_inventory_id": "runtime-java:no-adv-1",
	      "group_id": "org.apache.tomcat",
	      "artifact_id": "tomcat-juli",
	      "version": "8.5.82",
	      "runtime_path": "/opt/apache-tomcat-8.5.82/lib/tomcat-juli.jar",
	      "evidence_source": "filename"
	    }
	  ]
	}`)
	request := httptest.NewRequest(http.MethodPost, "/runtime-java/diagnose", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	mux.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", response.Code)
	}

	var diagnoseResponse api.MatchDiagnosticsResponse
	if err := json.Unmarshal(response.Body.Bytes(), &diagnoseResponse); err != nil {
		t.Fatalf("json.Unmarshal failed: %v", err)
	}
	if diagnoseResponse.Summary.TotalComponents != 2 {
		t.Fatalf("unexpected total components: %d", diagnoseResponse.Summary.TotalComponents)
	}
	if diagnoseResponse.Summary.MatchedComponents != 1 {
		t.Fatalf("unexpected matched components: %d", diagnoseResponse.Summary.MatchedComponents)
	}
	if diagnoseResponse.Summary.NoAdvisory != 1 {
		t.Fatalf("unexpected no advisory count: %d", diagnoseResponse.Summary.NoAdvisory)
	}
	if diagnoseResponse.Components[0].SelectedArtifactID != "tomcat-jdbc" {
		t.Fatalf("unexpected canonical artifact id: %s", diagnoseResponse.Components[0].SelectedArtifactID)
	}
}
