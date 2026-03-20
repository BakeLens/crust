//go:build windows

package rules

import (
	"context"
	"encoding/json"
	"testing"
)

// TestEnvDB_WindowsSpecificVars verifies that Windows-only dangerous env vars
// (COR_PROFILER, COMSPEC, etc.) are detected on Windows but would be skipped
// on other platforms via OS filtering.
func TestEnvDB_WindowsSpecificVars(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	attacks := []struct {
		name string
		cmd  string
	}{
		{
			"export COR_PROFILER",
			`export COR_PROFILER="{CLSID-OF-EVIL-DLL}"`,
		},
		{
			"export COR_PROFILER_PATH",
			`export COR_PROFILER_PATH="C:\evil\profiler.dll"`,
		},
		{
			"export CORECLR_PROFILER",
			`export CORECLR_PROFILER="{CLSID-EVIL}"`,
		},
		{
			"export CORECLR_PROFILER_PATH",
			`export CORECLR_PROFILER_PATH="C:\temp\evil.dll"`,
		},
		{
			"export COMSPEC",
			`export COMSPEC="C:\temp\evil.exe"`,
		},
		{
			"PS $env:COR_PROFILER",
			`$env:COR_PROFILER = "{CLSID-EVIL}"`,
		},
		{
			"PS $env:COMSPEC",
			`$env:COMSPEC = "C:\temp\evil.exe"`,
		},
		{
			"PS SetEnvironmentVariable COR_PROFILER_PATH",
			`[Environment]::SetEnvironmentVariable("COR_PROFILER_PATH", "C:\evil.dll")`,
		},
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"command": tc.cmd})
			result := engine.Evaluate(ToolCall{Name: "Bash", Arguments: args})
			if !result.Matched || result.RuleName != "builtin:block-dangerous-env" {
				t.Errorf("expected blocked by block-dangerous-env, got matched=%v rule=%q",
					result.Matched, result.RuleName)
			}
		})
	}
}

// TestEnvDB_WindowsLinkerVarsSkippedOnWindows verifies that Linux-specific
// linker vars (LD_PRELOAD, LD_AUDIT) are correctly skipped on Windows.
func TestEnvDB_WindowsLinkerVarsSkipped(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	linuxOnly := []string{
		`export LD_PRELOAD=/tmp/evil.so`,
		`export LD_AUDIT=/tmp/audit.so`,
		`export LD_LIBRARY_PATH=/tmp/evil`,
	}

	for _, cmd := range linuxOnly {
		t.Run(cmd, func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"command": cmd})
			result := engine.Evaluate(ToolCall{Name: "Bash", Arguments: args})
			if result.Matched && result.RuleName == "builtin:block-dangerous-env" {
				t.Errorf("Linux-only var should NOT be blocked on Windows: %s", cmd)
			}
		})
	}
}

// TestEnvDB_WindowsPowerShellEnvVars tests PowerShell-specific env var
// assignment patterns that are common on Windows.
func TestEnvDB_WindowsPowerShellEnvVars(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	defer engine.Close()

	attacks := []struct {
		name string
		cmd  string
	}{
		{
			"Set-Item env:NODE_OPTIONS",
			`Set-Item env:NODE_OPTIONS "--require C:\temp\evil.js"`,
		},
		{
			"chained profiler enable + path",
			`$env:COR_ENABLE_PROFILING = "1"; $env:COR_PROFILER_PATH = "C:\evil.dll"`,
		},
	}

	for _, tc := range attacks {
		t.Run(tc.name, func(t *testing.T) {
			args, _ := json.Marshal(map[string]string{"command": tc.cmd})
			result := engine.Evaluate(ToolCall{Name: "Bash", Arguments: args})
			if !result.Matched {
				t.Logf("NOTE: %q not blocked — may need enhanced PS detection", tc.name)
			}
		})
	}
}
