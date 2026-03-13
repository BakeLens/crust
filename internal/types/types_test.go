package types

import "testing"

func TestAgentValid(t *testing.T) {
	for _, a := range AllAgents() {
		if !a.Valid() {
			t.Errorf("AllAgents() contains invalid agent: %s", a)
		}
	}
	if AgentUnknown.Valid() {
		t.Error("AgentUnknown should not be valid")
	}
	if Agent("nonexistent").Valid() {
		t.Error("arbitrary string should not be valid")
	}
}

func TestParseAgent(t *testing.T) {
	tests := []struct {
		input string
		want  Agent
	}{
		{"claude-code", AgentClaudeCode},
		{"codex", AgentCodex},
		{"cline", AgentCline},
		{"cursor", AgentCursor},
		{"openclaw", AgentOpenClaw},
		{"opencode", AgentOpenCode},
		{"windsurf", AgentWindsurf},
		{"unknown", AgentUnknown},
		{"", AgentUnknown},
		{"Claude-Code", AgentUnknown}, // case-sensitive
	}
	for _, tt := range tests {
		got := ParseAgent(tt.input)
		if got != tt.want {
			t.Errorf("ParseAgent(%q) = %s, want %s", tt.input, got, tt.want)
		}
	}
}

func TestLogLevelValid(t *testing.T) {
	valid := []LogLevel{LogLevelTrace, LogLevelDebug, LogLevelInfo, LogLevelWarn, LogLevelError, ""}
	for _, l := range valid {
		if !l.Valid() {
			t.Errorf("LogLevel(%q).Valid() = false, want true", l)
		}
	}
	invalid := []LogLevel{"invalid", "verbose", "fatal", "warning"}
	for _, l := range invalid {
		if l.Valid() {
			t.Errorf("LogLevel(%q).Valid() = true, want false", l)
		}
	}
}
