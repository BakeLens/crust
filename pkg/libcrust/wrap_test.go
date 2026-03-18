//go:build libcrust

package libcrust

import "testing"

func TestWrapEmptyArgs(t *testing.T) {
	if code := Wrap(nil); code != 1 {
		t.Errorf("Wrap(nil) = %d, want 1", code)
	}
	if code := Wrap([]string{}); code != 1 {
		t.Errorf("Wrap([]) = %d, want 1", code)
	}
}

func TestWrapStripsDashDash(t *testing.T) {
	// "--" alone should result in empty args → exit code 1
	if code := Wrap([]string{"--"}); code != 1 {
		t.Errorf("Wrap([--]) = %d, want 1", code)
	}
}
