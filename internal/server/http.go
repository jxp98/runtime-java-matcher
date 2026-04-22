package server

import (
	"encoding/json"
	"log"
	"net/http"

	"runtime-java-matcher/internal/api"
	"runtime-java-matcher/internal/db"
	"runtime-java-matcher/internal/matcher"
)

func NewMux(service *matcher.Service, dbPath string, packageSize int, metadata db.Metadata, logger *log.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
			return
		}
		writeJSON(w, http.StatusOK, api.HealthResponse{
			Status:              "ok",
			Database:            dbPath,
			PackageSize:         packageSize,
			DatabaseFormat:      metadata.Format,
			DatabaseSource:      metadata.Source,
			DatabaseVersion:     metadata.Version,
			DatabaseGeneratedAt: metadata.GeneratedAt,
		})
	})
	mux.HandleFunc("/runtime-java/match", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
			return
		}

		defer r.Body.Close()
		var request api.MatchRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
			return
		}

		response := service.Match(request)
		if logger != nil {
			logger.Printf("match request_id=%s agent=%s components=%d matches=%d", request.RequestID, request.Agent.ID, len(request.Components), len(response.Matches))
		}
		writeJSON(w, http.StatusOK, response)
	})
	return mux
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]any{
		"error":       message,
		"status_code": status,
	})
}
