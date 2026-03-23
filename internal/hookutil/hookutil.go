// Package hookutil manages agent tool-call evaluation hooks.
// Shared by daemon (CLI) and libcrust (GUI).
//
// Currently supports Claude Code PreToolUse hooks in ~/.claude/settings.json.
//
//	Install: called during protect.Start(). Idempotent.
//	Uninstall: called during protect.Stop() and daemon.stopCleanup()
//	           (SIGKILL recovery). Preserves user-defined hooks.
package hookutil

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BakeLens/crust/internal/fileutil"
)

// HookMarker is the string that identifies crust hook entries in settings files.
const HookMarker = "evaluate-hook"

type hookConfig struct {
	Type    string `json:"type"`
	Command string `json:"command"`
	Timeout int    `json:"timeout,omitempty"`
}

type hookGroup struct {
	Matcher string       `json:"matcher,omitempty"`
	Hooks   []hookConfig `json:"hooks"`
}

// SettingsPath returns ~/.claude/settings.json.
func SettingsPath() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".claude", "settings.json")
}

// Install adds a PreToolUse hook in ~/.claude/settings.json that routes
// tool call evaluation through the crust binary.
// Idempotent: skips if a crust hook is already installed.
func Install(crustBin string) error {
	if crustBin == "" {
		return errors.New("crust binary path is empty")
	}

	path := SettingsPath()
	if path == "" {
		return errors.New("cannot determine Claude settings path")
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create settings dir: %w", err)
	}

	settings := make(map[string]json.RawMessage)
	data, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read settings: %w", err)
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parse settings: %w", err)
		}
	}

	var hooks map[string][]hookGroup
	if raw, ok := settings["hooks"]; ok {
		if err := json.Unmarshal(raw, &hooks); err != nil {
			return fmt.Errorf("parse hooks: %w", err)
		}
	}
	if hooks == nil {
		hooks = make(map[string][]hookGroup)
	}

	for _, group := range hooks["PreToolUse"] {
		for _, h := range group.Hooks {
			if strings.Contains(h.Command, HookMarker) {
				return nil // already installed
			}
		}
	}

	cmd := fmt.Sprintf("%q evaluate-hook", crustBin)
	hooks["PreToolUse"] = append(hooks["PreToolUse"], hookGroup{
		Hooks: []hookConfig{{
			Type:    "command",
			Command: cmd,
			Timeout: 5000,
		}},
	})

	hooksRaw, err := json.Marshal(hooks)
	if err != nil {
		return fmt.Errorf("marshal hooks: %w", err)
	}
	settings["hooks"] = hooksRaw

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return fileutil.SecureWriteFile(path, append(out, '\n'))
}

// Uninstall removes crust hook entries from ~/.claude/settings.json.
// No-op if the file doesn't exist or has no crust hooks.
func Uninstall() error {
	path := SettingsPath()
	if path == "" {
		return nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read settings: %w", err)
	}

	settings := make(map[string]json.RawMessage)
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse settings: %w", err)
	}

	raw, ok := settings["hooks"]
	if !ok {
		return nil
	}

	var hooks map[string][]hookGroup
	if err := json.Unmarshal(raw, &hooks); err != nil {
		return fmt.Errorf("parse hooks: %w", err)
	}
	if hooks == nil {
		return nil
	}

	groups := hooks["PreToolUse"]
	var filtered []hookGroup
	for _, group := range groups {
		var clean []hookConfig
		for _, h := range group.Hooks {
			if !strings.Contains(h.Command, HookMarker) {
				clean = append(clean, h)
			}
		}
		if len(clean) > 0 {
			group.Hooks = clean
			filtered = append(filtered, group)
		}
	}

	if len(filtered) == len(groups) {
		return nil // nothing to remove
	}

	if len(filtered) == 0 {
		delete(hooks, "PreToolUse")
	} else {
		hooks["PreToolUse"] = filtered
	}

	if len(hooks) == 0 {
		delete(settings, "hooks")
	} else {
		hooksRaw, err := json.Marshal(hooks)
		if err != nil {
			return fmt.Errorf("marshal hooks: %w", err)
		}
		settings["hooks"] = hooksRaw
	}

	out, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal settings: %w", err)
	}
	return fileutil.SecureWriteFile(path, append(out, '\n'))
}

// hookResponse is the Claude Code PreToolUse hook output format.
type hookResponse struct {
	HookSpecificOutput hookSpecificOutput `json:"hookSpecificOutput"`
}

type hookSpecificOutput struct {
	HookEventName            string `json:"hookEventName"`
	PermissionDecision       string `json:"permissionDecision"`
	PermissionDecisionReason string `json:"permissionDecisionReason"`
}

// FormatResponse formats a raw eval result JSON into the PreToolUse hook
// response. Returns "" if the tool call is allowed (fail-open).
func FormatResponse(evalResult string) string {
	var result struct {
		Matched  bool   `json:"matched"`
		RuleName string `json:"rule_name"`
		Action   string `json:"action"`
		Message  string `json:"message"`
	}
	if err := json.Unmarshal([]byte(evalResult), &result); err != nil {
		return "" // fail-open on malformed input
	}
	if !result.Matched || result.Action != "block" {
		return ""
	}

	reason := "Blocked by Crust rule '" + result.RuleName + "': " + result.Message
	resp := hookResponse{
		HookSpecificOutput: hookSpecificOutput{
			HookEventName:            "PreToolUse",
			PermissionDecision:       "deny",
			PermissionDecisionReason: reason,
		},
	}
	out, err := json.Marshal(resp)
	if err != nil {
		return ""
	}
	return string(out)
}

// IsInstalled checks if ~/.claude/settings.json contains a crust hook.
func IsInstalled() bool {
	path := SettingsPath()
	if path == "" {
		return false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	return strings.Contains(string(data), HookMarker)
}

// CleanupStaleFile removes the old ~/.claude/hooks.json if it only contains
// crust hooks. Cleans up after the bug where hooks were written to the wrong file.
func CleanupStaleFile() {
	home, err := os.UserHomeDir()
	if err != nil {
		return
	}
	stale := filepath.Join(home, ".claude", "hooks.json")
	data, err := os.ReadFile(stale)
	if err != nil {
		return
	}

	var hf struct {
		Hooks map[string][]struct {
			Command string `json:"command"`
		} `json:"hooks"`
	}
	if json.Unmarshal(data, &hf) != nil {
		return
	}
	for _, entries := range hf.Hooks {
		for _, e := range entries {
			if !strings.Contains(e.Command, HookMarker) {
				return // has non-crust hooks, don't delete
			}
		}
	}
	_ = os.Remove(stale)
}
