package logger

import "testing"

func TestParseLevel(t *testing.T) {
	// Verify boundary cases and error handling.
	tests := []struct {
		input   string
		want    Level
		wantErr bool
	}{
		{"", LevelInfo, false},        // empty defaults to info
		{"TRACE", LevelTrace, false},  // case-insensitive
		{"warning", LevelWarn, false}, // alias
		{"invalid", 0, true},
		{"verbose", 0, true},
		{"fatal", 0, true},
	}
	for _, tt := range tests {
		got, err := ParseLevel(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParseLevel(%q) should return error", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParseLevel(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if got != tt.want {
			t.Errorf("ParseLevel(%q) = %d, want %d", tt.input, got, tt.want)
		}
	}
}
