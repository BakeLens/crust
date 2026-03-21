package earlyinit

import "testing"

// TestExportedVarsAccessible verifies that the package-level variables
// set by init() are accessible and have sensible zero/default values
// when running under `go test` (which does not pass --foreground).
func TestExportedVarsAccessible(t *testing.T) {
	// Under `go test`, --foreground is not in os.Args,
	// so Foreground should be false.
	if Foreground {
		t.Error("Foreground should be false under go test")
	}
	if Suppressed {
		t.Error("Suppressed should be false when Foreground is false")
	}
	// OrigTERM is only set when Foreground is true, so it should be empty.
	if OrigTERM != "" {
		t.Errorf("OrigTERM = %q, want empty (Foreground is false)", OrigTERM)
	}
}
