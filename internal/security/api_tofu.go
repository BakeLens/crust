//go:build !libcrust

package security

import (
	"encoding/json"
	"net/http"

	"github.com/BakeLens/crust/internal/api"
	"github.com/BakeLens/crust/internal/mcpgateway"
)

// SetTOFUTracker attaches a TOFU tracker for MCP server pinning endpoints.
// Must be called before the server starts handling requests.
func (s *APIServer) SetTOFUTracker(t *mcpgateway.TOFUTracker) {
	s.tofuTracker = t
	s.mux.HandleFunc("GET /api/security/tofu/pins", s.handleTOFUListPins)
	s.mux.HandleFunc("GET /api/security/tofu/pending", s.handleTOFUPending)
	s.mux.HandleFunc("POST /api/security/tofu/approve", s.handleTOFUApprove)
	s.mux.HandleFunc("POST /api/security/tofu/reject", s.handleTOFUReject)
	s.mux.HandleFunc("DELETE /api/security/tofu/pins/{name}", s.handleTOFUDeletePin)
}

// handleTOFUListPins handles GET /api/security/tofu/pins.
func (s *APIServer) handleTOFUListPins(w http.ResponseWriter, _ *http.Request) {
	if s.tofuTracker == nil {
		api.Success(w, []any{})
		return
	}
	pins, err := s.tofuTracker.Store().ListPins()
	if err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to list TOFU pins")
		return
	}
	if pins == nil {
		pins = []mcpgateway.TOFUPin{}
	}
	api.Success(w, pins)
}

// handleTOFUPending handles GET /api/security/tofu/pending.
func (s *APIServer) handleTOFUPending(w http.ResponseWriter, _ *http.Request) {
	if s.tofuTracker == nil {
		api.Success(w, []any{})
		return
	}
	pending := s.tofuTracker.PendingApprovals()
	if pending == nil {
		pending = []mcpgateway.PendingApproval{}
	}
	api.Success(w, pending)
}

// handleTOFUApprove handles POST /api/security/tofu/approve.
func (s *APIServer) handleTOFUApprove(w http.ResponseWriter, r *http.Request) {
	if s.tofuTracker == nil {
		api.Error(w, http.StatusServiceUnavailable, "TOFU is disabled")
		return
	}
	var req struct {
		ServerName string `json:"server_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.ServerName == "" {
		api.Error(w, http.StatusBadRequest, "server_name is required")
		return
	}
	if err := s.tofuTracker.Approve(req.ServerName); err != nil {
		api.Error(w, http.StatusNotFound, err.Error())
		return
	}
	api.Success(w, map[string]any{"status": "approved", "server_name": req.ServerName})
}

// handleTOFUReject handles POST /api/security/tofu/reject.
func (s *APIServer) handleTOFUReject(w http.ResponseWriter, r *http.Request) {
	if s.tofuTracker == nil {
		api.Error(w, http.StatusServiceUnavailable, "TOFU is disabled")
		return
	}
	var req struct {
		ServerName string `json:"server_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.Error(w, http.StatusBadRequest, "Invalid request body")
		return
	}
	if req.ServerName == "" {
		api.Error(w, http.StatusBadRequest, "server_name is required")
		return
	}
	s.tofuTracker.Reject(req.ServerName)
	api.Success(w, map[string]any{"status": "rejected", "server_name": req.ServerName})
}

// handleTOFUDeletePin handles DELETE /api/security/tofu/pins/{name}.
func (s *APIServer) handleTOFUDeletePin(w http.ResponseWriter, r *http.Request) {
	if s.tofuTracker == nil {
		api.Error(w, http.StatusServiceUnavailable, "TOFU is disabled")
		return
	}
	name := r.PathValue("name")
	if name == "" {
		api.Error(w, http.StatusBadRequest, "Pin name is required")
		return
	}
	if err := s.tofuTracker.Store().DeletePin(name); err != nil {
		api.Error(w, http.StatusInternalServerError, "Failed to delete pin")
		return
	}
	api.Success(w, map[string]any{"status": "deleted", "server_name": name})
}
