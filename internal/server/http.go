package server

import (
	"encoding/json"
	"log"
	"net/http"

	"runtime-java-matcher/internal/api"
)

type Matcher interface {
	Match(request api.MatchRequest) api.MatchResponse
}

type Diagnoser interface {
	Diagnose(request api.MatchRequest) api.MatchDiagnosticsResponse
}

func NewMux(service Matcher, health api.HealthResponse, logger *log.Logger) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "仅支持 GET")
			return
		}
		writeJSON(w, http.StatusOK, health)
	})
	mux.HandleFunc("/runtime-java/match", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
			return
		}

		request, ok := decodeMatchRequest(w, r)
		if !ok {
			return
		}

		response := service.Match(request)
		if logger != nil {
			logger.Printf("match request_id=%s agent=%s components=%d matches=%d", request.RequestID, request.Agent.ID, len(request.Components), len(response.Matches))
		}
		writeJSON(w, http.StatusOK, response)
	})
	mux.HandleFunc("/runtime-java/diagnose", func(w http.ResponseWriter, r *http.Request) {
		diagnoser, ok := service.(Diagnoser)
		if !ok {
			writeError(w, http.StatusNotImplemented, "当前后端不支持诊断接口")
			return
		}
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "仅支持 POST")
			return
		}

		request, ok := decodeMatchRequest(w, r)
		if !ok {
			return
		}

		response := diagnoser.Diagnose(request)
		if logger != nil {
			logger.Printf(
				"diagnose request_id=%s agent=%s components=%d matched=%d unresolved=%d no_advisory=%d version_not_affected=%d",
				request.RequestID,
				request.Agent.ID,
				response.Summary.TotalComponents,
				response.Summary.MatchedComponents,
				response.Summary.IdentityUnresolved,
				response.Summary.NoAdvisory,
				response.Summary.VersionNotAffected,
			)
		}
		writeJSON(w, http.StatusOK, response)
	})
	return mux
}

func decodeMatchRequest(w http.ResponseWriter, r *http.Request) (api.MatchRequest, bool) {
	defer r.Body.Close()
	var request api.MatchRequest
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		writeError(w, http.StatusBadRequest, "请求体不是合法 JSON: "+err.Error())
		return api.MatchRequest{}, false
	}
	return request, true
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
