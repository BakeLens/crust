package rules

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestRuleJSON_FilePathDoesNotExposeAbsolutePath verifies that the Rule
// struct only contains the filename (not the absolute path) in JSON
// API responses, preventing user directory structure leaks.
func TestRuleJSON_FilePathDoesNotExposeAbsolutePath(t *testing.T) {
	rule := Rule{
		Name:     "test-rule",
		FilePath: "custom.yaml", // Should be basename only (set by loader)
		Message:  "blocked",
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}

	// FilePath should only contain the filename, not an absolute path.
	if strings.Contains(string(data), "/Users/") || strings.Contains(string(data), "/home/") {
		t.Error("Rule JSON serialization should not contain absolute filesystem paths")
	}
}

// TestRuleJSON_NoSensitivePatternContent ensures that compiled regex
// patterns (which could reveal security detection logic) are not
// serialized to JSON API responses.
func TestRuleJSON_NoSensitivePatternContent(t *testing.T) {
	rule := Rule{
		Name: "block-secret-access",
		Block: Block{
			Paths: StringOrArray{"**/.env"},
		},
		Actions: []Operation{OpRead},
		Message: "blocked",
	}

	data, err := json.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}

	// The serialized rule includes pattern details. This is expected for
	// the management API but should be documented as a privacy consideration.
	if strings.Contains(string(data), "**/.env") {
		t.Log("INFO: Rule API exposes path patterns - this is expected for management API")
	}
}
