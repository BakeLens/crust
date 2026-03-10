package rules

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/pathutil"
)

func TestIsYAMLFile(t *testing.T) {
	tests := []struct {
		name string
		file string
		want bool
	}{
		{"lowercase .yaml", "rules.yaml", true},
		{"uppercase .YAML", "rules.YAML", true},
		{"mixed .Yaml", "rules.Yaml", true},
		{"yml extension", "rules.yml", false},
		{"no extension", "Makefile", false},
		{"empty", "", false},
		{"nested path", "rules.d/custom.YAML", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isYAMLFile(tt.file); got != tt.want {
				t.Errorf("isYAMLFile(%q) = %v, want %v", tt.file, got, tt.want)
			}
		})
	}
}

func TestLoader_RejectsUnknownYAMLFields(t *testing.T) {
	content := `rules:
  - block: "**/.env"
    bloock: "typo"
`
	loader := NewLoader(t.TempDir())
	// Test parseRuleSet directly — LoadUser logs+skips bad files by design.
	_, err := loader.parseRuleSet([]byte(content), "test.yaml", SourceUser)
	if err == nil {
		t.Fatal("expected error for unknown YAML field 'bloock', got nil")
	}
	if !strings.Contains(err.Error(), "unknown fields") {
		t.Errorf("expected 'unknown fields' error, got: %v", err)
	}
}

func TestValidatePathInDirectory_CaseInsensitive(t *testing.T) {
	if pathutil.DefaultFS().CaseSensitive {
		t.Skip("case-insensitive path validation not applicable on case-sensitive filesystem")
	}

	// Create a temp rules directory with mixed-case parent
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "Rules.D")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a rule file
	ruleFile := filepath.Join(rulesDir, "test.yaml")
	if err := os.WriteFile(ruleFile, []byte("name: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	// Loader uses the mixed-case dir
	loader := NewLoader(rulesDir)

	// Validate should succeed — the file is inside the directory
	path, err := loader.ValidatePathInDirectory("test.yaml")
	if err != nil {
		t.Fatalf("ValidatePathInDirectory failed for valid file: %v", err)
	}
	if path == "" {
		t.Fatal("ValidatePathInDirectory returned empty path")
	}
}

func TestValidatePathInDirectory_TraversalBlocked(t *testing.T) {
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(rulesDir)

	// Path traversal must be blocked regardless of case sensitivity
	_, err := loader.ValidatePathInDirectory("../../../etc/passwd")
	if err == nil {
		t.Fatal("ValidatePathInDirectory should reject path traversal")
	}
}

func TestAddRuleFile_NoOverwrite(t *testing.T) {
	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a source rule file
	srcDir := filepath.Join(tmpDir, "src")
	if err := os.MkdirAll(srcDir, 0o755); err != nil {
		t.Fatal(err)
	}
	ruleContent := []byte("rules:\n  - block: \"**/secret\"\n")
	srcPath := filepath.Join(srcDir, "test.yaml")
	if err := os.WriteFile(srcPath, ruleContent, 0o644); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(rulesDir)

	// First add should use the original filename.
	dest1, err := loader.AddRuleFile(srcPath)
	if err != nil {
		t.Fatalf("first AddRuleFile: %v", err)
	}
	if filepath.Base(dest1) != "test.yaml" {
		t.Fatalf("expected test.yaml, got %s", filepath.Base(dest1))
	}

	// Second add should get a timestamped name (not overwrite the first).
	dest2, err := loader.AddRuleFile(srcPath)
	if err != nil {
		t.Fatalf("second AddRuleFile: %v", err)
	}
	if dest2 == dest1 {
		t.Fatal("second AddRuleFile should have a different destination")
	}
	if !strings.Contains(filepath.Base(dest2), "test_") {
		t.Fatalf("expected timestamped name, got %s", filepath.Base(dest2))
	}

	// Both files should exist with correct content.
	for _, p := range []string{dest1, dest2} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("ReadFile(%s): %v", p, err)
		}
		if string(data) != string(ruleContent) {
			t.Fatalf("%s: got %q, want %q", p, data, ruleContent)
		}
	}
}

func TestValidatePathInDirectory_SymlinkTraversal(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink test not reliable on Windows CI")
	}

	tmpDir := t.TempDir()
	rulesDir := filepath.Join(tmpDir, "rules.d")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Create a symlink pointing outside the rules directory
	outsideFile := filepath.Join(tmpDir, "outside.yaml")
	if err := os.WriteFile(outsideFile, []byte("name: evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	symlink := filepath.Join(rulesDir, "evil.yaml")
	if err := os.Symlink(outsideFile, symlink); err != nil {
		t.Fatal(err)
	}

	loader := NewLoader(rulesDir)

	_, err := loader.ValidatePathInDirectory("evil.yaml")
	if err == nil {
		t.Fatal("ValidatePathInDirectory should reject symlink pointing outside directory")
	}
}
