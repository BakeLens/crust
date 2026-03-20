//go:build !libcrust

package api

import (
	"encoding/json"
	"net/http"
)

// Success sends a JSON success response.
func Success(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data) //nolint:errcheck // best-effort JSON response
}

// Error sends a JSON error response.
func Error(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": message}) //nolint:errcheck
}
