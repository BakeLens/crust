//go:build !libcrust

package rules

import (
	"net/http"
	"path/filepath"

	"github.com/gin-gonic/gin"

	"github.com/BakeLens/crust/internal/api"
	"github.com/BakeLens/crust/internal/fileutil"
)

// APIHandler provides HTTP handlers for rules management
type APIHandler struct {
	engine *Engine
}

// NewAPIHandler creates a new API handler
func NewAPIHandler(engine *Engine) *APIHandler {
	return &APIHandler{engine: engine}
}

// HandleRules returns all active rules
func (h *APIHandler) HandleRules(c *gin.Context) {
	rules := h.engine.GetRules()
	api.Success(c, gin.H{
		"total": len(rules),
		"rules": rules,
	})
}

// HandleBuiltinRules returns only builtin rules
func (h *APIHandler) HandleBuiltinRules(c *gin.Context) {
	rules := h.engine.GetBuiltinRules()
	api.Success(c, gin.H{
		"total": len(rules),
		"rules": rules,
	})
}

// HandleUserRules returns only user rules
func (h *APIHandler) HandleUserRules(c *gin.Context) {
	rules := h.engine.GetUserRules()
	api.Success(c, gin.H{
		"total": len(rules),
		"rules": rules,
	})
}

// HandleDeleteUserRuleFile handles DELETE /api/crust/rules/user/:filename
func (h *APIHandler) HandleDeleteUserRuleFile(c *gin.Context) {
	filename := c.Param("filename")
	if filename == "" {
		api.Error(c, http.StatusBadRequest, "Filename required")
		return
	}

	if err := h.engine.GetLoader().RemoveRuleFile(filename); err != nil {
		// SECURITY FIX: Don't expose internal error details
		log.Error("Failed to remove rule file %s: %v", filename, err)
		api.Error(c, http.StatusInternalServerError, "Failed to remove rule file")
		return
	}

	// Reload after delete
	if err := h.engine.ReloadUserRules(); err != nil {
		log.Warn("Failed to reload rules after delete: %v", err)
	}
	api.Success(c, gin.H{"status": "deleted", "filename": filename})
}

// HandleReload triggers hot reload of user rules
func (h *APIHandler) HandleReload(c *gin.Context) {
	if err := h.engine.ReloadUserRules(); err != nil {
		api.Success(c, gin.H{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	api.Success(c, gin.H{
		"status":     "reloaded",
		"rule_count": h.engine.RuleCount(),
	})
}

// HandleValidate validates rule YAML without loading.
// Performs full validation including pattern compilation (regex, glob, sanitization).
func (h *APIHandler) HandleValidate(c *gin.Context) {
	body, err := c.GetRawData()
	if err != nil {
		api.Error(c, http.StatusBadRequest, "Failed to read body")
		return
	}

	results, err := h.engine.ValidateYAMLFull(body)
	if err != nil {
		// YAML parse or structural validation error
		api.Success(c, gin.H{
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

	api.Success(c, gin.H{
		"valid": allValid,
		"rules": results,
	})
}

// HandleListFiles returns list of user rule files
func (h *APIHandler) HandleListFiles(c *gin.Context) {
	files, err := h.engine.GetLoader().ListUserRuleFiles()
	if err != nil {
		// SECURITY FIX: Don't expose internal error details
		log.Error("Failed to list rule files: %v", err)
		api.Error(c, http.StatusInternalServerError, "Failed to list rule files")
		return
	}
	api.Success(c, gin.H{
		"files": files,
	})
}

// AddFileQuery represents query parameters for adding a file
type AddFileQuery struct {
	Filename string `form:"filename"`
}

// MaxRuleFileSize is the maximum allowed rule file size (1MB)
const MaxRuleFileSize = 1 << 20 // 1MB

// HandleAddFile adds a new rule file from request body
func (h *APIHandler) HandleAddFile(c *gin.Context) {
	// SECURITY FIX: Check content length before reading
	if c.Request.ContentLength > MaxRuleFileSize {
		api.Error(c, http.StatusRequestEntityTooLarge, "Rule file too large (max 1MB)")
		return
	}

	var query AddFileQuery
	if err := c.ShouldBindQuery(&query); err != nil {
		log.Debug("Failed to bind query: %v", err)
	}

	body, err := c.GetRawData()
	if err != nil {
		api.Error(c, http.StatusBadRequest, "Failed to read body")
		return
	}

	// SECURITY FIX: Double-check body size after reading
	if len(body) > MaxRuleFileSize {
		api.Error(c, http.StatusRequestEntityTooLarge, "Rule file too large (max 1MB)")
		return
	}

	// Validate YAML content first
	if err := h.engine.GetLoader().ValidateYAML(body); err != nil {
		api.Success(c, gin.H{
			"status": "error",
			"error":  "Validation failed: " + err.Error(),
		})
		return
	}

	// Get filename from query param or use default
	filename := query.Filename
	if filename == "" {
		filename = "custom.yaml"
	}
	if !isYAMLFile(filename) {
		filename += ".yaml"
	}

	// SECURITY: Validate filename to prevent path traversal
	destPath, err := h.engine.GetLoader().ValidatePathInDirectory(filename)
	if err != nil {
		api.Error(c, http.StatusBadRequest, "Invalid filename")
		return
	}

	// Ensure directory exists
	userDir := h.engine.GetLoader().GetUserDir()
	if err := fileutil.SecureMkdirAll(userDir); err != nil {
		log.Error("Failed to create rules directory: %v", err)
		api.Error(c, http.StatusInternalServerError, "Failed to create rules directory")
		return
	}

	// Write file
	if err := fileutil.SecureWriteFile(destPath, body); err != nil {
		log.Error("Failed to write rule file: %v", err)
		api.Error(c, http.StatusInternalServerError, "Failed to write rule file")
		return
	}

	// Reload
	if err := h.engine.ReloadUserRules(); err != nil {
		log.Warn("Failed to reload after adding file: %v", err)
	}

	api.Success(c, gin.H{
		"status":     "added",
		"filename":   filepath.Base(destPath),
		"rule_count": h.engine.RuleCount(),
	})
}
