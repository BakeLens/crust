package main

import (
	"encoding/json"
	"testing"

	"github.com/BakeLens/crust/internal/cli"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/muesli/termenv"
)

func TestRuleUnmarshal(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		wantName string
		wantOps  int
		wantErr  bool
	}{
		{
			name: "simple rule",
			jsonData: `{
				"name": "protect-env-files",
				"message": "Cannot access .env files",
				"actions": ["read", "write"],
				"block": {"paths": ["**/.env"]}
			}`,
			wantName: "protect-env-files",
			wantOps:  2,
			wantErr:  false,
		},
		{
			name: "rule with exceptions",
			jsonData: `{
				"name": "protect-ssh-keys",
				"message": "Cannot access SSH keys",
				"actions": ["read"],
				"block": {
					"paths": ["**/.ssh/id_*"],
					"except": ["**/.ssh/id_*.pub"]
				}
			}`,
			wantName: "protect-ssh-keys",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with match",
			jsonData: `{
				"name": "block-crontab",
				"message": "Cannot edit crontab",
				"actions": ["execute"],
				"block": {},
				"match": {
					"command": "re:crontab\\s+-e"
				}
			}`,
			wantName: "block-crontab",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with content match",
			jsonData: `{
				"name": "detect-private-key",
				"message": "Private key detected",
				"actions": ["write"],
				"block": {},
				"match": {
					"content": "re:-----BEGIN.*PRIVATE KEY-----"
				}
			}`,
			wantName: "detect-private-key",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with all conditions",
			jsonData: `{
				"name": "composite-rule",
				"message": "Blocked",
				"actions": ["execute"],
				"block": {},
				"all_conditions": [
					{"path": "/etc/**"},
					{"command": "re:ln\\s+-s"}
				]
			}`,
			wantName: "composite-rule",
			wantOps:  1,
			wantErr:  false,
		},
		{
			name: "rule with enabled pointer nil",
			jsonData: `{
				"name": "enabled-default",
				"message": "Test",
				"actions": ["read"],
				"block": {"paths": ["/test"]}
			}`,
			wantName: "enabled-default",
			wantOps:  1,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r rules.Rule
			err := json.Unmarshal([]byte(tt.jsonData), &r)

			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if r.Name != tt.wantName {
				t.Errorf("name = %q, want %q", r.Name, tt.wantName)
			}

			if len(r.Actions) != tt.wantOps {
				t.Errorf("actions count = %d, want %d", len(r.Actions), tt.wantOps)
			}
		})
	}
}

func TestRuleEnabled(t *testing.T) {
	tests := []struct {
		name        string
		jsonData    string
		wantEnabled bool
	}{
		{
			name:        "enabled nil (default true)",
			jsonData:    `{"name": "test", "actions": ["read"], "block": {}}`,
			wantEnabled: true,
		},
		{
			name:        "enabled true",
			jsonData:    `{"name": "test", "enabled": true, "actions": ["read"], "block": {}}`,
			wantEnabled: true,
		},
		{
			name:        "enabled false",
			jsonData:    `{"name": "test", "enabled": false, "actions": ["read"], "block": {}}`,
			wantEnabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r rules.Rule
			if err := json.Unmarshal([]byte(tt.jsonData), &r); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if r.IsEnabled() != tt.wantEnabled {
				t.Errorf("enabled = %v, want %v", r.IsEnabled(), tt.wantEnabled)
			}
		})
	}
}

func TestRulePriority(t *testing.T) {
	tests := []struct {
		name         string
		jsonData     string
		wantNil      bool
		wantPriority int
	}{
		{
			name:     "priority omitted (nil)",
			jsonData: `{"name": "test", "actions": ["read"], "block": {}}`,
			wantNil:  true,
		},
		{
			name:         "priority explicit zero",
			jsonData:     `{"name": "test", "priority": 0, "actions": ["read"], "block": {}}`,
			wantNil:      false,
			wantPriority: 0,
		},
		{
			name:         "priority explicit",
			jsonData:     `{"name": "test", "priority": 10, "actions": ["read"], "block": {}}`,
			wantNil:      false,
			wantPriority: 10,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r rules.Rule
			if err := json.Unmarshal([]byte(tt.jsonData), &r); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}
			if tt.wantNil {
				if r.Priority != nil {
					t.Errorf("priority = %v, want nil", *r.Priority)
				}
			} else {
				if r.Priority == nil {
					t.Fatalf("priority = nil, want %d", tt.wantPriority)
				}
				if *r.Priority != tt.wantPriority {
					t.Errorf("priority = %d, want %d", *r.Priority, tt.wantPriority)
				}
			}
		})
	}
}

func TestRuleBlockFields(t *testing.T) {
	jsonData := `{
		"name": "test-rule",
		"message": "Test",
		"actions": ["read", "write", "delete"],
		"block": {
			"paths": ["/path/one", "/path/two"],
			"except": ["/path/one/allowed"],
			"hosts": ["example.com"]
		}
	}`

	var r rules.Rule
	if err := json.Unmarshal([]byte(jsonData), &r); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if len(r.Block.Paths) != 2 {
		t.Errorf("paths count = %d, want 2", len(r.Block.Paths))
	}

	if len(r.Block.Except) != 1 {
		t.Errorf("except count = %d, want 1", len(r.Block.Except))
	}

	if len(r.Block.Hosts) != 1 {
		t.Errorf("hosts count = %d, want 1", len(r.Block.Hosts))
	}
}

func TestRuleMatchFields(t *testing.T) {
	jsonData := `{
		"name": "test-match",
		"message": "Test",
		"actions": ["execute"],
		"block": {},
		"match": {
			"path": "/etc/**",
			"command": "re:rm\\s+-rf",
			"host": "evil.com",
			"content": "re:password",
			"tools": ["bash", "write"]
		}
	}`

	var r rules.Rule
	if err := json.Unmarshal([]byte(jsonData), &r); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if r.Match == nil {
		t.Fatal("match is nil")
	}

	if r.Match.Path != "/etc/**" {
		t.Errorf("match.path = %q, want %q", r.Match.Path, "/etc/**")
	}

	if r.Match.Command != "re:rm\\s+-rf" {
		t.Errorf("match.command = %q, want %q", r.Match.Command, "re:rm\\s+-rf")
	}

	if r.Match.Host != "evil.com" {
		t.Errorf("match.host = %q, want %q", r.Match.Host, "evil.com")
	}

	if r.Match.Content != "re:password" {
		t.Errorf("match.content = %q, want %q", r.Match.Content, "re:password")
	}

	if len(r.Match.Tools) != 2 {
		t.Errorf("match.tools count = %d, want 2", len(r.Match.Tools))
	}
}

func TestRuleCompositeConditions(t *testing.T) {
	tests := []struct {
		name     string
		jsonData string
		wantAll  int
		wantAny  int
	}{
		{
			name: "all conditions",
			jsonData: `{
				"name": "test",
				"message": "Test",
				"actions": ["execute"],
				"block": {},
				"all_conditions": [
					{"path": "/etc/**"},
					{"command": "re:ln"}
				]
			}`,
			wantAll: 2,
			wantAny: 0,
		},
		{
			name: "any conditions",
			jsonData: `{
				"name": "test",
				"message": "Test",
				"actions": ["execute"],
				"block": {},
				"any_conditions": [
					{"command": "re:curl.*-T"},
					{"command": "re:curl.*--upload"}
				]
			}`,
			wantAll: 0,
			wantAny: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var r rules.Rule
			if err := json.Unmarshal([]byte(tt.jsonData), &r); err != nil {
				t.Fatalf("unmarshal error: %v", err)
			}

			if len(r.AllConditions) != tt.wantAll {
				t.Errorf("all_conditions count = %d, want %d", len(r.AllConditions), tt.wantAll)
			}

			if len(r.AnyConditions) != tt.wantAny {
				t.Errorf("any_conditions count = %d, want %d", len(r.AnyConditions), tt.wantAny)
			}
		})
	}
}

func TestRulesResponseUnmarshal(t *testing.T) {
	jsonData := `{
		"total": 2,
		"rules": [
			{
				"name": "rule-one",
				"message": "Rule one",
				"actions": ["read"],
				"block": {"paths": ["/one"]}
			},
			{
				"name": "rule-two",
				"message": "Rule two",
				"actions": ["write"],
				"block": {"paths": ["/two"]}
			}
		]
	}`

	var resp cli.RulesResponse
	if err := json.Unmarshal([]byte(jsonData), &resp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if resp.Total != 2 {
		t.Errorf("total = %d, want 2", resp.Total)
	}

	if len(resp.Rules) != 2 {
		t.Errorf("rules count = %d, want 2", len(resp.Rules))
	}

	if resp.Rules[0].Name != "rule-one" {
		t.Errorf("rules[0].name = %q, want %q", resp.Rules[0].Name, "rule-one")
	}
}

func TestColorProfileFromTERM(t *testing.T) {
	tests := []struct {
		term string
		want termenv.Profile
	}{
		{"", termenv.Ascii},
		{"dumb", termenv.Ascii},
		{"linux", termenv.ANSI},
		{"xterm", termenv.ANSI},
		{"xterm-256color", termenv.ANSI256},
		{"screen-256color", termenv.ANSI256},
		{"tmux-256color", termenv.ANSI256},
		{"xterm-color", termenv.ANSI},
		{"ansi", termenv.ANSI},
		{"xterm-kitty", termenv.TrueColor},
		{"xterm-ghostty", termenv.TrueColor},
		{"alacritty", termenv.TrueColor},
		{"foot", termenv.TrueColor},
	}
	for _, tt := range tests {
		t.Run(tt.term, func(t *testing.T) {
			if got := colorProfileFromTERM(tt.term); got != tt.want {
				t.Errorf("colorProfileFromTERM(%q) = %v, want %v", tt.term, got, tt.want)
			}
		})
	}
}
