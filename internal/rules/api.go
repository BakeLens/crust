//go:build !libcrust

package rules

import (
	"io"
	"net/http"
	"path/filepath"

	"github.com/BakeLens/crust/internal/api"
	"github.com/BakeLens/crust/internal/fileutil"
)

// APIHandler provides HTTP handlers for rules management.
type APIHandler struct {
	engine *Engine
}

// NewAPIHandler creates a new API handler.
func NewAPIHandler(engine *Engine) *APIHandler {
	return &APIHandler{engine: engine}
}

// HandleRules returns all active rules.
func (h *APIHandler) HandleRules(w http.ResponseWriter, _ *http.Request) {
	rules := h.engine.GetRules()
	api.Success(w, map[string]any{
		"total": len(rules),
		"rules": rules,
	})
}

// HandleBuiltinRules returns only builtin rules.
func (h *APIHandler) HandleBuiltinRules(w http.ResponseWriter, _ *http.Request) {
	rules := h.engine.GetBuiltinRules()
	api.Success(w, map[string]any{
		"total": len(rules),
		"rules": rules,
	})
}

// HandleUserRules returns only user rules.
func (h *APIHandler) HandleUserRules(w http.ResponseWriter, _ *http.Request) {
	rules := h.engine.GetUserRules()
	api.Success(w, map[string]any{
		"total": len(rules),
		"rules": rules,
	})
}

// HandleDeleteUserRuleFile handles DELETE /api/crust/rules/user/{filename}.
func (h *APIHandler) HandleDeleteUserRuleFile(w http.ResponseWriter, r *http.Request) {
	filename := r.PathValue("filename")
	if filename == "" {
		api.Error(w, http.StatusBadRequest, "Filename required")
		return
	}

	if err := h.engine.GetLoader().RemoveRuleFile(filename); err != nil {
		log.Error("Failed to remove rule file %s: %v", filename, err)
		api.Error(w, http.StatusInternalServerError, "Failed to remove rule file")
		return
	}

	if err := h.engine.ReloadUserRules(); err != nil {
		log.Warn("Failed to reload rules after delete: %v", err)
	}
	api.Success(w, map[string]any{"status": "deleted", "filename": filename})
}

// HandleReload triggers hot reload of user rules.
func (h *APIHandler) HandleReload(w http.ResponseWriter, _ *http.Request) {
	if err := h.engine.ReloadUserRules(); err != nil {
		api.Success(w, map[string]any{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	api.Success(w, map[string]any{
		"status":     "reloaded",
		"rule_count": h.engine.RuleCount(),
	})
}

// HandleValidate validates rule YAML without loading.
func (h *APIHandler) HandleValidate(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "Failed to read body")
		return
	}

	results, err := h.engine.ValidateYAMLFull(body)
	if err != nil {
		api.Success(w, map[string]any{
			"valid": false,
			"error": err.Error(),
		})
		return
	}

	allValid := true
	for _, r := range results {
		if !r.Valid {
			allValid = false
			break
		}
	}

	api.Success(w, map[string]any{
		"valid": allValid,
		"rules": results,
	})
}

// HandleListFiles returns list of user rule files.
func (h *APIHandler) HandleListFiles(w http.ResponseWriter, _ *http.Request) {
	files, err := h.engine.GetLoader().ListUserRuleFiles()
	if err != nil {
		log.Error("Failed to list rule files: %v", err)
		api.Error(w, http.StatusInternalServerError, "Failed to list rule files")
		return
	}
	api.Success(w, map[string]any{
		"files": files,
	})
}

// MaxRuleFileSize is the maximum allowed rule file size (1MB).
const MaxRuleFileSize = 1 << 20 // 1MB

// HandleAddFile adds a new rule file from request body.
func (h *APIHandler) HandleAddFile(w http.ResponseWriter, r *http.Request) {
	if r.ContentLength > MaxRuleFileSize {
		api.Error(w, http.StatusRequestEntityTooLarge, "Rule file too large (max 1MB)")
		return
	}

	filename := r.URL.Query().Get("filename")

	body, err := io.ReadAll(r.Body)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "Failed to read body")
		return
	}

	if len(body) > MaxRuleFileSize {
		api.Error(w, http.StatusRequestEntityTooLarge, "Rule file too large (max 1MB)")
		return
	}

	if err := h.engine.GetLoader().ValidateYAML(body); err != nil {
		api.Success(w, map[string]any{
			"status": "error",
			"error":  "Validation failed: " + err.Error(),
		})
		return
	}

	if filename == "" {
		filename = "custom.yaml"
	}
	if !isYAMLFile(filename) {
		filename += ".yaml"
	}

	destPath, err := h.engine.GetLoader().ValidatePathInDirectory(filename)
	if err != nil {
		api.Error(w, http.StatusBadRequest, "Invalid filename")
		return
	}

	userDir := h.engine.GetLoader().GetUserDir()
	if err := fileutil.SecureMkdirAll(userDir); err != nil {
		log.Error("Failed to create rules directory: %v", err)
		api.Error(w, http.StatusInternalServerError, "Failed to create rules directory")
		return
	}

	if err := fileutil.SecureWriteFile(destPath, body); err != nil {
		log.Error("Failed to write rule file: %v", err)
		api.Error(w, http.StatusInternalServerError, "Failed to write rule file")
		return
	}

	if err := h.engine.ReloadUserRules(); err != nil {
		log.Warn("Failed to reload after adding file: %v", err)
	}

	api.Success(w, map[string]any{
		"status":     "added",
		"filename":   filepath.Base(destPath),
		"rule_count": h.engine.RuleCount(),
	})
}
