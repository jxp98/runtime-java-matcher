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
	mux := NewMux(matcher.New(index, "test-matcher"), "../../testdata/formal-db", index.Size(), index.Metadata(), nil)
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
	mux := NewMux(matcher.New(index, "test-matcher"), "../../testdata/vulndb.json", index.Size(), index.Metadata(), nil)
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
