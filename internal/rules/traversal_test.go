package rules

import (
	"context"
	"encoding/json"
	"testing"
)

// TestPathTraversal_BlocksProtectedTargets verifies that ../ traversal
// targeting protected files is caught by existing rules via suffix stripping.
func TestPathTraversal_BlocksProtectedTargets(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	attacks := []struct {
		name string
		tool string
		args map[string]any
	}{
		{
			"traversal to .env",
			"Read", map[string]any{"file_path": "../../.env"},
		},
		{
			"traversal to .ssh/id_rsa",
			"Read", map[string]any{"file_path": "../../../.ssh/id_rsa"},
		},
		{
			"deep traversal to .env",
			"Read", map[string]any{"file_path": "../../../../../../../../.env"},
		},
		{
			"traversal to .git/hooks/pre-commit",
			"Write", map[string]any{
				"file_path": "../../.git/hooks/pre-commit",
				"content":   "malicious",
			},
		},
		{
			"traversal to .crust/config.yaml",
			"Read", map[string]any{"file_path": "../../../.crust/config.yaml"},
		},
		{
			"traversal to .claude/settings.json",
			"Write", map[string]any{
				"file_path": "../../.claude/settings.json",
				"content":   "malicious",
			},
		},
		{
			"traversal to .cursor/mcp.json",
			"Write", map[string]any{
				"file_path": "../../.cursor/mcp.json",
				"content":   "malicious",
			},
		},
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(tc.args)
			result := engine.Evaluate(ToolCall{Name: tc.tool, Arguments: args})
			if !result.Matched {
				t.Errorf("traversal to protected target should be blocked: %v", tc.args)
			}
		})
	}
}

// TestPathTraversal_AllowsLegitimateRelativePaths verifies that normal
// relative paths in dev workflows are NOT blocked.
func TestPathTraversal_AllowsLegitimateRelativePaths(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	safe := []struct {
		name string
		tool string
		args map[string]any
	}{
		{
			"../src/main.go",
			"Read", map[string]any{"file_path": "../src/main.go"},
		},
		{
			"../../package.json",
			"Read", map[string]any{"file_path": "../../package.json"},
		},
		{
			"../tests/test.py",
			"Read", map[string]any{"file_path": "../tests/test.py"},
		},
		{
			"../README.md",
			"Read", map[string]any{"file_path": "../README.md"},
		},
	}

	for _, tc := range safe {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(tc.args)
			result := engine.Evaluate(ToolCall{Name: tc.tool, Arguments: args})
			if result.Matched {
				t.Errorf("legitimate relative path should NOT be blocked: %s (rule: %s)", tc.name, result.RuleName)
			}
		})
	}
}

// TestPathTraversal_URLEncoded verifies URL-encoded traversal is caught.
func TestPathTraversal_URLEncoded(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	attacks := []struct {
		name string
		path string
	}{
		{"percent-encoded dots", "%2e%2e/%2e%2e/.env"},
		{"mixed encoding", "../%2e%2e/.ssh/id_rsa"},
		{"uppercase encoding", "%2E%2E/%2E%2E/.env"},
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(map[string]any{"file_path": tc.path})
			result := engine.Evaluate(ToolCall{Name: "Read", Arguments: args})
			if !result.Matched {
				t.Errorf("URL-encoded traversal should be blocked: %s", tc.path)
			}
		})
	}
}

// TestStripLeadingTraversal verifies the helper function directly.
func TestStripLeadingTraversal(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"../../.ssh/id_rsa", ".ssh/id_rsa"},
		{"../../../.env", ".env"},
		{"../.aws/credentials", ".aws/credentials"},
		{"..", ""},
		{"../", ""},
		{"no-traversal/file.txt", "no-traversal/file.txt"},
		{"/absolute/path", "/absolute/path"},
		{"", ""},
		{"..\\..\\../.ssh/id_rsa", ".ssh/id_rsa"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := stripLeadingTraversal(tc.input)
			if got != tc.want {
				t.Errorf("stripLeadingTraversal(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// TestURLDecodeDots verifies URL decoding of traversal patterns.
func TestURLDecodeDots(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"%2e%2e/%2e%2e/.env", "../../.env"},
		{"%2E%2E/%2F", "..//"},
		{"no-encoding", "no-encoding"},
		{"%2e%2e%5c%2e%2e%5c.ssh", "..\\..\\.ssh"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := urlDecodeDots(tc.input)
			if got != tc.want {
				t.Errorf("urlDecodeDots(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}
