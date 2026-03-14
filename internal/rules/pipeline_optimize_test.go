package rules

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// =============================================================================
// Finding 1: NormalizeUnicode — RawJSON skipped when Content is set (FIXED)
// Step 4 now only normalizes RawJSON when Content is empty.
// =============================================================================

// TestFinding_UnicodeNormalizesLargeRawJSON verifies that for Write calls,
// RawJSON is a superset of Content. Step 4 now skips RawJSON normalization
// when Content is set, avoiding 2x Unicode work.
func TestFinding_UnicodeNormalizesLargeRawJSON(t *testing.T) {
	bigContent := strings.Repeat("x", 100_000)
	args, _ := json.Marshal(map[string]string{
		"file_path": "/tmp/test.txt",
		"content":   bigContent,
	})

	ext := NewExtractor()
	info := ext.Extract("Write", args)

	if info.Content == "" {
		t.Fatal("expected Content to be extracted from Write tool")
	}
	if info.RawJSON == "" {
		t.Fatal("expected RawJSON to be set")
	}
	// RawJSON always contains Content as a substring — normalizing both is redundant.
	if len(info.RawJSON) < len(info.Content) {
		t.Errorf("RawJSON (%d bytes) should be >= Content (%d bytes)",
			len(info.RawJSON), len(info.Content))
	}
}

// BenchmarkFinding_UnicodeRawJSONRedundancy compares content-only normalization
// (current behavior) vs the old approach of normalizing both Content and RawJSON.
func BenchmarkFinding_UnicodeRawJSONRedundancy(b *testing.B) {
	for _, size := range []int{1_000, 10_000, 100_000} {
		content := strings.Repeat("hello world ", size/12)
		args, _ := json.Marshal(map[string]string{
			"file_path": "/tmp/test.txt",
			"content":   content,
		})
		ext := NewExtractor()
		info := ext.Extract("Write", args)

		b.Run(fmt.Sprintf("%dk/content_only", size/1000), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				NormalizeUnicode(info.Content)
			}
		})
		b.Run(fmt.Sprintf("%dk/rawjson_also", size/1000), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				NormalizeUnicode(info.Content)
				NormalizeUnicode(info.RawJSON)
			}
		})
	}
}

// =============================================================================
// Finding 2: Null bytes in commands — already caught by step 6 (evasion)
// The extractor marks commands with null bytes as evasive. No change needed.
// =============================================================================

// TestFinding_NullByteInCommandCaughtByEvasion confirms that null bytes in
// commands are blocked by step 6 (shell evasion), not step 5 (null byte check).
func TestFinding_NullByteInCommandCaughtByEvasion(t *testing.T) {
	engine, err := NewTestEngine(nil)
	if err != nil {
		t.Fatal(err)
	}

	cmd := "cat /tmp/safe\x00 /etc/passwd"
	call := makeToolCall("Bash", map[string]any{"command": cmd})
	result := engine.Evaluate(call)

	if !result.Matched {
		t.Fatal("null byte in command should be blocked")
	}
	if result.RuleName != "builtin:block-shell-evasion" {
		t.Errorf("expected builtin:block-shell-evasion, got %q", result.RuleName)
	}
}

// =============================================================================
// Finding 3: Evasion boolean (step 6) now runs before PreFilter regex (step 7)
// (FIXED) Swapped to check the ~2ns boolean before the ~63ns regex.
// =============================================================================

// BenchmarkFinding_EvasiveCheckOrdering quantifies the cost difference between
// the evasive boolean check (step 6) and the PreFilter regex scan (step 7).
func BenchmarkFinding_EvasiveCheckOrdering(b *testing.B) {
	pf := NewPreFilter()
	cmd := "ls -la /tmp"

	b.Run("step5_boolean_check", func(b *testing.B) {
		b.ReportAllocs()
		evasive := false
		for b.Loop() {
			if evasive {
				_ = evasive
			}
		}
	})

	b.Run("step6_prefilter_check", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = pf.Check(cmd)
		}
	})
}

// =============================================================================
// Finding 4: IsEnabled() dead code removed (FIXED)
// compileRules already filters disabled rules — merged never contains them.
// The redundant IsEnabled() checks in the hot path have been removed.
// =============================================================================

// TestFinding_DisabledRulesFilteredAtCompileTime verifies that disabled rules
// never appear in the merged rule set, confirming the compile-time filter.
func TestFinding_DisabledRulesFilteredAtCompileTime(t *testing.T) {
	disabled := false
	rules := []Rule{
		{
			Name:    "enabled-rule",
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"/etc/shadow"}},
			Message: "blocked",
		},
		{
			Name:    "disabled-rule",
			Enabled: &disabled,
			Actions: []Operation{OpRead},
			Block:   Block{Paths: []string{"/etc/passwd"}},
			Message: "blocked",
		},
	}

	engine, err := NewTestEngine(rules)
	if err != nil {
		t.Fatal(err)
	}

	compiled := engine.getCompiledRules()
	for _, cr := range compiled {
		if !cr.Rule.IsEnabled() {
			t.Fatalf("disabled rule %q found in merged set — compileRules should have filtered it", cr.Rule.Name)
		}
	}

	// Only 1 rule should be in merged (the enabled one).
	if len(compiled) != 1 {
		t.Errorf("expected 1 compiled rule, got %d", len(compiled))
	}
	if compiled[0].Rule.Name != "enabled-rule" {
		t.Errorf("expected enabled-rule, got %q", compiled[0].Rule.Name)
	}
}

// =============================================================================
// Finding 5: Literal match strings pre-lowered at compile time (FIXED)
// compiledMatch now stores ContentLower/CommandLower, eliminating redundant
// strings.ToLower(substr) calls on every evaluation.
// =============================================================================

// BenchmarkFinding_ContainsIgnoreCaseAllocs compares the old containsIgnoreCase
// (re-lowers substr every call) vs pre-lowered substr (current behavior).
func BenchmarkFinding_ContainsIgnoreCaseAllocs(b *testing.B) {
	content := strings.Repeat("This is some normal content with no secrets. ", 100)
	substr := "api_key"

	// Old approach: re-lower substr every call.
	b.Run("relower_every_call", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			strings.Contains(strings.ToLower(content), strings.ToLower(substr))
		}
	})

	// Current approach: substr pre-lowered at compile time.
	substrLower := strings.ToLower(substr)
	b.Run("prelowered_substr", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			strings.Contains(strings.ToLower(content), substrLower)
		}
	})
}

// =============================================================================
// Finding 6: mergeUnique uses linear scan for small inputs (FIXED)
// For len(a)+len(b) <= 8 (typical: 1-3 paths), avoids map allocation.
// Falls back to map-based approach for larger inputs.
// =============================================================================

// BenchmarkFinding_MergeUniqueSmallInputs benchmarks mergeUnique for small
// inputs (linear scan path) and large inputs (map fallback path).
func BenchmarkFinding_MergeUniqueSmallInputs(b *testing.B) {
	a := []string{"/home/user/project/main.go"}
	bPaths := []string{"/home/user/project/main.go"}

	b.Run("small_linear_scan", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = mergeUnique(a, bPaths)
		}
	})

	// Large input to exercise the map-based fallback path.
	largePaths := make([]string, 10)
	for i := range largePaths {
		largePaths[i] = fmt.Sprintf("/home/user/project/file%d.go", i)
	}
	b.Run("large_map_fallback", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			_ = mergeUnique(largePaths[:5], largePaths[3:])
		}
	})
}
