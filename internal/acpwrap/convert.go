// Package acpwrap implements a transparent stdio proxy for ACP (Agent Client Protocol)
// agents, intercepting security-relevant JSON-RPC messages using Crust's rule engine.
package acpwrap

import (
	"encoding/json"
	"fmt"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/shellutil"
)

// ACP parameter types

type fsReadParams struct {
	SessionID string `json:"sessionId"`
	Path      string `json:"path"`
}

type fsWriteParams struct {
	SessionID string `json:"sessionId"`
	Path      string `json:"path"`
	Content   string `json:"content"`
}

type terminalCreateParams struct {
	SessionID string            `json:"sessionId"`
	Command   string            `json:"command"`
	Args      []string          `json:"args,omitempty"`
	Env       map[string]string `json:"env,omitempty"`
	Cwd       string            `json:"cwd,omitempty"`
}

// ACPMethodToToolCall converts an ACP JSON-RPC method + params into a rules.ToolCall.
//
// Returns:
//   - (*ToolCall, nil) for successfully parsed security-relevant methods
//   - (nil, nil) for non-security methods (caller should pass through)
//   - (nil, error) for security-relevant methods with malformed params (caller should block)
func ACPMethodToToolCall(method string, params json.RawMessage) (*rules.ToolCall, error) {
	// Reject nil/null params on security-relevant methods (json.Unmarshal silently
	// zero-initializes the struct, which would produce an empty path and bypass rules).
	switch method {
	case "fs/read_text_file", "fs/write_text_file", "terminal/create":
		if len(params) == 0 || string(params) == "null" {
			return nil, fmt.Errorf("nil params for security method %s", method)
		}
	default:
		return nil, nil // not security-relevant
	}

	switch method {
	case "fs/read_text_file":
		var p fsReadParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		args, err := json.Marshal(map[string]string{"path": p.Path})
		if err != nil {
			return nil, fmt.Errorf("marshal error: %w", err)
		}
		return &rules.ToolCall{Name: "read_file", Arguments: args}, nil

	case "fs/write_text_file":
		var p fsWriteParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		args, err := json.Marshal(map[string]any{
			"path":    p.Path,
			"content": p.Content,
		})
		if err != nil {
			return nil, fmt.Errorf("marshal error: %w", err)
		}
		return &rules.ToolCall{Name: "write_file", Arguments: args}, nil

	case "terminal/create":
		var p terminalCreateParams
		if err := json.Unmarshal(params, &p); err != nil {
			return nil, fmt.Errorf("malformed %s params: %w", method, err)
		}
		if p.Command == "" {
			return nil, fmt.Errorf("empty command in %s params", method)
		}
		fullCmd, err := shellutil.Command(append([]string{p.Command}, p.Args...)...)
		if err != nil {
			return nil, fmt.Errorf("cannot construct command: %w", err)
		}
		args, err := json.Marshal(map[string]string{"command": fullCmd})
		if err != nil {
			return nil, fmt.Errorf("marshal error: %w", err)
		}
		return &rules.ToolCall{Name: "bash", Arguments: args}, nil

	default:
		return nil, nil
	}
}
