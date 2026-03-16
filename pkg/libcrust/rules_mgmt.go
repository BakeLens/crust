//go:build libcrust

package libcrust

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

var errNotInit = errors.New("engine not initialized")

// GetRules returns all active rules as a JSON string.
func GetRules() string {
	e := getEngine()
	if e == nil {
		return `{"rules":[],"total":0}`
	}

	allRules := e.GetRules()
	return mustJSON(map[string]any{
		"rules": allRules,
		"total": len(allRules),
	})
}

// GetBuiltinRules returns only builtin rules as JSON.
func GetBuiltinRules() string {
	e := getEngine()
	if e == nil {
		return "[]"
	}
	return mustJSON(e.GetBuiltinRules())
}

// GetUserRules returns only user-defined rules as JSON.
func GetUserRules() string {
	e := getEngine()
	if e == nil {
		return "[]"
	}
	return mustJSON(e.GetUserRules())
}

// ReloadRules reloads user rules from disk.
func ReloadRules() error {
	e := getEngine()
	if e == nil {
		return errNotInit
	}
	return e.ReloadUserRules()
}

// GetRuleFiles returns a JSON array of user rule file names.
func GetRuleFiles() string {
	dir := rules.DefaultUserRulesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return "[]"
		}
		return errJSON(err)
	}

	var files []string
	for _, e := range entries {
		if !e.IsDir() && isYAMLFile(e.Name()) {
			files = append(files, e.Name())
		}
	}
	if files == nil {
		files = []string{}
	}
	return mustJSON(files)
}

// AddRuleFile writes a YAML rule file to the user rules directory
// and reloads the engine.
func AddRuleFile(filename string, content string) error {
	if filename == "" {
		return fmt.Errorf("filename is required")
	}
	if !isYAMLFile(filename) {
		return fmt.Errorf("filename must end in .yaml")
	}
	// Validate content before writing.
	e := getEngine()
	if e != nil {
		if _, err := e.ValidateYAMLFull([]byte(content)); err != nil {
			return fmt.Errorf("invalid YAML: %w", err)
		}
	}

	dir := rules.DefaultUserRulesDir()
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create rules dir: %w", err)
	}

	path := filepath.Join(dir, filename)
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		return fmt.Errorf("write rule file: %w", err)
	}

	if e != nil {
		return e.ReloadUserRules()
	}
	return nil
}

// DeleteRuleFile removes a user rule file and reloads the engine.
func DeleteRuleFile(filename string) error {
	if filename == "" {
		return fmt.Errorf("filename is required")
	}
	// Prevent path traversal.
	if strings.Contains(filename, "/") || strings.Contains(filename, "\\") || strings.Contains(filename, "..") {
		return fmt.Errorf("invalid filename")
	}

	dir := rules.DefaultUserRulesDir()
	path := filepath.Join(dir, filename)
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil // already gone
		}
		return fmt.Errorf("delete rule file: %w", err)
	}

	e := getEngine()
	if e != nil {
		return e.ReloadUserRules()
	}
	return nil
}

// GetSecurityStatus returns protection status as JSON.
func GetSecurityStatus() string {
	e := getEngine()
	enabled := e != nil

	ruleCount := 0
	lockedCount := 0
	if e != nil {
		ruleCount = e.RuleCount()
		lockedCount = e.LockedRuleCount()
	}

	return mustJSON(map[string]any{
		"enabled":            enabled,
		"rules_count":        ruleCount,
		"locked_rules_count": lockedCount,
	})
}

func isYAMLFile(name string) bool {
	lower := strings.ToLower(name)
	return strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
}
