package rules

import (
	"context"
	"fmt"
	"testing"
)

// newEvasionTestEngine creates an engine with all builtin rules enabled.
// Uses a test normalizer with home=/home/user to match standard test fixtures.
func newEvasionTestEngine(t *testing.T) *Engine {
	t.Helper()
	normalizer := NewNormalizerWithEnv("/home/user", "/home/user/project", nil)
	engine, err := NewEngineWithNormalizer(context.Background(), EngineConfig{
		UserRulesDir:   "",
		DisableBuiltin: false,
		DisableDLP:     true, // DLP not relevant for evasion tests
	}, normalizer)
	if err != nil {
		t.Fatalf("engine init: %v", err)
	}
	t.Cleanup(engine.Close)
	return engine
}

// ---------------------------------------------------------------------------
// GAP: Interpreter evasion — the engine does not parse code strings passed
// to python3, node, ruby, perl, etc. These commands wrap a blocked action
// inside an interpreter's -c/-e flag, so the extractor never sees the
// underlying file path or network target.
//
// Each test asserts the CURRENT behavior (Matched==false). When we add
// interpreter-aware extraction, flip the assertion to Matched==true.
// ---------------------------------------------------------------------------

func TestEvasion_PythonOsSystem(t *testing.T) {
	// FIXED: python3 -c wrapping cat /etc/shadow is now caught by
	// interpreter-aware path extraction (extractFromInterpreterCode scans the code string).
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "python3 -c \"import os; os.system('cat /etc/shadow')\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: python3 os.system('cat /etc/shadow') should be BLOCKED by interpreter-aware extraction")
	}
	t.Logf("OK: python3 os.system blocked by rule=%s", result.RuleName)
}

func TestEvasion_PythonSubprocess(t *testing.T) {
	// PARTIAL: The engine catches this because "/etc/shadow" appears as a literal
	// path string in the arguments, and the extractor picks it up even inside
	// Python code. This is NOT true interpreter-aware parsing — it's incidental
	// path extraction. If the attacker obfuscates the path (e.g., chr(47)+'etc'+...),
	// it would bypass. Still, assert current behavior: BLOCKED.
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "python3 -c \"import subprocess; subprocess.run(['cat', '/etc/shadow'])\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: python3 subprocess with literal /etc/shadow should be BLOCKED (incidental path extraction)")
	}
	t.Logf("OK (incidental): python3 subprocess blocked by rule=%s — path extracted from string literal, not interpreter-aware parsing", result.RuleName)
}

func TestEvasion_PythonUrllib(t *testing.T) {
	// FIXED: python3 -c wrapping urllib to hit cloud metadata endpoint is now
	// caught by interpreter-aware host extraction (extractFromInterpreterCode scans the code string).
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "python3 -c \"import urllib.request; urllib.request.urlopen('http://169.254.169.254/')\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: python3 urllib to cloud metadata should be BLOCKED by interpreter-aware extraction")
	}
	t.Logf("OK: python3 urllib blocked by rule=%s", result.RuleName)
}

func TestEvasion_NodeFsRead(t *testing.T) {
	// PARTIAL: The engine catches this because "/etc/shadow" appears as a literal
	// path string in the arguments. This is incidental path extraction, not
	// interpreter-aware parsing. Obfuscated paths would bypass.
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "node -e \"require('fs').readFileSync('/etc/shadow')\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: node -e with literal /etc/shadow should be BLOCKED (incidental path extraction)")
	}
	t.Logf("OK (incidental): node fs blocked by rule=%s — path extracted from string literal, not interpreter-aware parsing", result.RuleName)
}

func TestEvasion_NodeChildProcess(t *testing.T) {
	// FIXED: node -e wrapping child_process.execSync('cat /etc/shadow') is now
	// caught by interpreter-aware path extraction (extractFromInterpreterCode).
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "node -e \"require('child_process').execSync('cat /etc/shadow')\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: node child_process.execSync('cat /etc/shadow') should be BLOCKED by interpreter-aware extraction")
	}
	t.Logf("OK: node child_process blocked by rule=%s", result.RuleName)
}

func TestEvasion_RubyFileRead(t *testing.T) {
	// PARTIAL: The engine catches this because "/etc/shadow" appears as a literal
	// path string in the arguments. Incidental extraction, not interpreter-aware.
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "ruby -e \"File.read('/etc/shadow')\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: ruby -e with literal /etc/shadow should be BLOCKED (incidental path extraction)")
	}
	t.Logf("OK (incidental): ruby File.read blocked by rule=%s — path extracted from string literal, not interpreter-aware parsing", result.RuleName)
}

func TestEvasion_PerlSystem(t *testing.T) {
	// FIXED: perl -e wrapping system('cat /etc/shadow') is now caught by
	// interpreter-aware path extraction (extractFromInterpreterCode).
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "perl -e \"system('cat /etc/shadow')\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: perl system('cat /etc/shadow') should be BLOCKED by interpreter-aware extraction")
	}
	t.Logf("OK: perl system blocked by rule=%s", result.RuleName)
}

// ---------------------------------------------------------------------------
// OK: Attacks that the engine DOES catch — regression tests to make sure
// these keep working as we add interpreter evasion detection.
// ---------------------------------------------------------------------------

func TestEvasion_DirectCatBlocked(t *testing.T) {
	// OK: Direct `cat /etc/shadow` is blocked by protect-system-auth.
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "cat /etc/shadow"}`)

	if !result.Matched {
		t.Fatal("REGRESSION: direct 'cat /etc/shadow' should be BLOCKED by protect-system-auth")
	}
	t.Logf("OK: direct cat /etc/shadow blocked by rule=%s", result.RuleName)
}

func TestEvasion_SubshellBlocked(t *testing.T) {
	// OK: `sh -c "cat /etc/shadow"` is blocked — the engine unwraps sh -c.
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "sh -c \"cat /etc/shadow\""}`)

	if !result.Matched {
		t.Fatal("REGRESSION: 'sh -c \"cat /etc/shadow\"' should be BLOCKED")
	}
	t.Logf("OK: sh -c cat /etc/shadow blocked by rule=%s", result.RuleName)
}

func TestEvasion_VariableExpansionBlocked(t *testing.T) {
	// OK: Variable expansion `X=/etc/shadow; cat $X` is blocked — the engine
	// expands shell variables.
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "X=/etc/shadow; cat $X"}`)

	if !result.Matched {
		t.Fatal("REGRESSION: 'X=/etc/shadow; cat $X' should be BLOCKED")
	}
	t.Logf("OK: variable expansion blocked by rule=%s", result.RuleName)
}

func TestEvasion_Base64Blocked(t *testing.T) {
	// OK: Base64-encoded command piped to bash is blocked by the obfuscation
	// pre-filter (step 8).
	engine := newEvasionTestEngine(t)
	result := engine.EvaluateJSON("Bash", `{"command": "echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | bash"}`)

	if !result.Matched {
		t.Fatal("REGRESSION: base64-encoded 'cat /etc/shadow' piped to bash should be BLOCKED")
	}
	t.Logf("OK: base64 pipe to bash blocked by rule=%s", result.RuleName)
}

// ---------------------------------------------------------------------------
// Summary helper — run with -v to see the evasion gap report.
// ---------------------------------------------------------------------------

func TestEvasion_Summary(t *testing.T) {
	engine := newEvasionTestEngine(t)

	type evasionCase struct {
		name    string
		command string
		isGap   bool // true = currently undetected, false = caught
	}

	cases := []evasionCase{
		// Fixed (were gaps, now caught by interpreter-aware extraction)
		{"python3 os.system", `python3 -c "import os; os.system('cat /etc/shadow')"`, false},
		{"python3 subprocess", `python3 -c "import subprocess; subprocess.run(['cat', '/etc/shadow'])"`, false},
		{"python3 urllib", `python3 -c "import urllib.request; urllib.request.urlopen('http://169.254.169.254/')"`, false},
		{"node fs", `node -e "require('fs').readFileSync('/etc/shadow')"`, false},
		{"node child_process", `node -e "require('child_process').execSync('cat /etc/shadow')"`, false},
		{"ruby File.read", `ruby -e "File.read('/etc/shadow')"`, false},
		{"perl system", `perl -e "system('cat /etc/shadow')"`, false},
		// Caught
		{"direct cat", `cat /etc/shadow`, false},
		{"sh -c", `sh -c "cat /etc/shadow"`, false},
		{"variable expansion", `X=/etc/shadow; cat $X`, false},
		{"base64 pipe", `echo Y2F0IC9ldGMvc2hhZG93 | base64 -d | bash`, false},
	}

	gaps, caught := 0, 0
	for _, tc := range cases {
		result := engine.EvaluateJSON("Bash", fmt.Sprintf(`{"command": %q}`, tc.command))
		blocked := result.Matched

		status := "OK"
		if tc.isGap {
			if blocked {
				status = "FIXED" // gap was closed
				caught++
			} else {
				status = "GAP"
				gaps++
			}
		} else {
			if blocked {
				caught++
			} else {
				status = "REGRESSION"
			}
		}
		t.Logf("  %-6s %-25s blocked=%-5v rule=%s", status, tc.name, blocked, result.RuleName)
	}

	t.Logf("\n  Evasion summary: %d gaps, %d caught out of %d total", gaps, caught, len(cases))
}
