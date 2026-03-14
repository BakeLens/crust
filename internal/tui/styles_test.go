package tui

import (
	"testing"

	"github.com/BakeLens/crust/internal/tui/terminal"
)

// These tests modify global state (plainMode) and must not run in parallel.

func enablePlainMode(t *testing.T) {
	t.Helper()
	SetPlainMode(true)
	t.Cleanup(func() { SetPlainMode(false) })
}

func TestHasCapability_PlainMode(t *testing.T) {
	enablePlainMode(t)

	caps := []terminal.Capability{
		terminal.CapTruecolor,
		terminal.CapHyperlinks,
		terminal.CapItalic,
		terminal.CapFaint,
		terminal.CapStrikethrough,
		terminal.CapWindowTitle,
	}
	for _, c := range caps {
		if hasCapability(c) {
			t.Errorf("hasCapability(%d) should return false in plain mode", c)
		}
	}
}

func TestCapabilityHelpers_PlainMode(t *testing.T) {
	enablePlainMode(t)

	tests := []struct {
		name string
		fn   func(string) string
	}{
		{"Faint", Faint},
		{"Italic", Italic},
		{"Strikethrough", Strikethrough},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.fn("hello")
			if got != "hello" {
				t.Errorf("%s in plain mode = %q, want %q", tt.name, got, "hello")
			}
		})
	}
}

func TestHyperlink_PlainMode(t *testing.T) {
	enablePlainMode(t)

	got := Hyperlink("https://example.com", "click")
	if got != "click" {
		t.Errorf("Hyperlink in plain mode = %q, want %q", got, "click")
	}
}

func TestHyperlink_EmptyURL(t *testing.T) {
	SetPlainMode(false)
	defer SetPlainMode(false)

	got := Hyperlink("", "click")
	if got != "click" {
		t.Errorf("Hyperlink with empty URL = %q, want %q", got, "click")
	}
}

func TestPrefix_PlainMode(t *testing.T) {
	enablePlainMode(t)

	got := Prefix()
	if got != "[crust]" {
		t.Errorf("Prefix() in plain mode = %q, want %q", got, "[crust]")
	}
}

func TestSeverityBadge_PlainMode(t *testing.T) {
	enablePlainMode(t)

	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "[CRITICAL]"},
		{"error", "[ERROR]"},
		{"high", "[HIGH]"},
		{"warning", "[WARNING]"},
		{"info", "[INFO]"},
		{"unknown", "[unknown]"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeverityBadge(tt.severity)
			if got != tt.want {
				t.Errorf("SeverityBadge(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestSeverityStyle_MapsCorrectly(t *testing.T) {
	tests := []struct {
		severity string
		want     string
	}{
		{"critical", "critical"},
		{"error", "critical"},
		{"high", "high"},
		{"warning", "warning"},
		{"info", "info"},
		{"unknown", "muted"},
	}
	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			got := SeverityStyle(tt.severity)
			var expected string
			switch tt.want {
			case "critical":
				expected = StyleCritical.Render("x")
			case "high":
				expected = StyleHigh.Render("x")
			case "warning":
				expected = StyleWarnBadge.Render("x")
			case "info":
				expected = StyleInfoBadge.Render("x")
			case "muted":
				expected = StyleMuted.Render("x")
			}
			if got.Render("x") != expected {
				t.Errorf("SeverityStyle(%q) returned wrong style", tt.severity)
			}
		})
	}
}

func TestSeparator_PlainMode(t *testing.T) {
	enablePlainMode(t)

	got := Separator("")
	if got != "---" {
		t.Errorf("Separator(\"\") in plain mode = %q, want %q", got, "---")
	}

	got = Separator("Title")
	if got != "--- Title ---" {
		t.Errorf("Separator(\"Title\") in plain mode = %q, want %q", got, "--- Title ---")
	}
}

func TestSetPlainMode_Overrides(t *testing.T) {
	SetPlainMode(true)
	if !IsPlainMode() {
		t.Error("IsPlainMode() should be true after SetPlainMode(true)")
	}

	SetPlainMode(false)
	if IsPlainMode() {
		t.Error("IsPlainMode() should be false after SetPlainMode(false)")
	}

	SetPlainMode(false)
}

func TestPlainMode_ConcurrentAccess(t *testing.T) {
	// Bug #16: Data race on plainMode — initPlainMode writes without holding plainMu.
	// This test verifies no race occurs when SetPlainMode and IsPlainMode are called concurrently.
	// Run with -race to detect the issue.
	SetPlainMode(false)
	defer SetPlainMode(false)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range 1000 {
			SetPlainMode(i%2 == 0)
		}
	}()
	for range 1000 {
		_ = IsPlainMode()
	}
	<-done
}
