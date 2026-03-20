package proxyutil

import (
	"encoding/json"
	"testing"
)

func TestForceNonStreaming(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool // stream should be false in output
	}{
		{"sets stream=false", `{"model":"gpt-4","stream":true,"messages":[]}`, true},
		{"adds stream=false when absent", `{"model":"claude-3","messages":[]}`, true},
		{"preserves other fields", `{"model":"x","stream":true,"temperature":0.5}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := ForceNonStreaming([]byte(tc.input))
			var m map[string]json.RawMessage
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("invalid JSON output: %v", err)
			}
			if string(m["stream"]) != "false" {
				t.Errorf("stream = %s, want false", m["stream"])
			}
		})
	}
}

func TestForceNonStreaming_InvalidJSON(t *testing.T) {
	input := []byte("not json")
	out := ForceNonStreaming(input)
	if string(out) != string(input) {
		t.Errorf("expected unchanged input on parse error")
	}
}
