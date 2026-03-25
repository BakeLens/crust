//go:build libcrust

package libcrust

import (
	"encoding/json"

	"github.com/BakeLens/crust/internal/mcpgateway"
)

var (
	tofuTracker *mcpgateway.TOFUTracker
)

// initTOFU sets up the TOFU tracker using the storage DB.
// Called from InitStorage after the DB is ready.
func initTOFU() {
	s := getStorage()
	if s == nil {
		return
	}
	store := mcpgateway.NewTOFUStore(s.DB())
	if err := store.InitSchema(); err != nil {
		plog.Warn("TOFU schema init: %v", err)
		return
	}
	tofuTracker = mcpgateway.NewTOFUTracker(store, "")
}

// GetTOFUTracker returns the TOFU tracker for use by the MCP gateway.
// Returns nil if storage is not initialized.
func GetTOFUTracker() *mcpgateway.TOFUTracker {
	return tofuTracker
}

// TOFUCheckToolsList validates a tools/list response for a given server.
// serverName: the MCP server name (from initialize response).
// toolsListResultJSON: the raw JSON result from tools/list response.
// Returns JSON: {"status":"pinned"}, {"status":"ok"}, or {"status":"blocked","message":"..."}.
func TOFUCheckToolsList(serverName string, toolsListResultJSON string) string {
	if tofuTracker == nil {
		return `{"status":"error","message":"TOFU not initialized"}`
	}

	hash, err := mcpgateway.CanonicalToolsHash(json.RawMessage(toolsListResultJSON))
	if err != nil {
		return `{"status":"error","message":"failed to hash tools"}`
	}

	store := tofuTracker.Store()
	pin, err := store.GetPin(serverName)
	if err != nil {
		return `{"status":"error","message":"failed to read pin"}`
	}

	if pin == nil {
		// First use — auto-pin.
		_ = store.UpsertPin(mcpgateway.TOFUPin{ServerName: serverName, ToolsHash: hash})
		return `{"status":"pinned"}`
	}

	if pin.ToolsHash == hash {
		return `{"status":"ok"}`
	}

	out, _ := json.Marshal(map[string]string{
		"status":   "blocked",
		"message":  "Tool definitions changed",
		"old_hash": pin.ToolsHash,
		"new_hash": hash,
	})
	return string(out)
}

// TOFUApprove approves a pending hash change for a server.
// Returns empty string on success, or an error message.
func TOFUApprove(serverName string, newToolsListResultJSON string) string {
	if tofuTracker == nil {
		return "TOFU not initialized"
	}

	hash, err := mcpgateway.CanonicalToolsHash(json.RawMessage(newToolsListResultJSON))
	if err != nil {
		return "failed to hash tools"
	}

	store := tofuTracker.Store()
	if err := store.UpsertPin(mcpgateway.TOFUPin{ServerName: serverName, ToolsHash: hash}); err != nil {
		return err.Error()
	}
	return ""
}

// TOFUListPins returns all stored pins as a JSON array.
func TOFUListPins() string {
	if tofuTracker == nil {
		return "[]"
	}
	pins, err := tofuTracker.Store().ListPins()
	if err != nil {
		return "[]"
	}
	if pins == nil {
		pins = []mcpgateway.TOFUPin{}
	}
	j, _ := json.Marshal(pins)
	return string(j)
}

// TOFUDeletePin removes a pin for a server. Next connection is treated as first use.
func TOFUDeletePin(serverName string) string {
	if tofuTracker == nil {
		return "TOFU not initialized"
	}
	if err := tofuTracker.Store().DeletePin(serverName); err != nil {
		return err.Error()
	}
	return ""
}
