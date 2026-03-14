package rules

import (
	"bytes"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestStringOrArray_String(t *testing.T) {
	input := `block: "**/.env"`
	var cfg struct {
		Block StringOrArray `yaml:"block"`
	}
	if err := yaml.Unmarshal([]byte(input), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Block) != 1 || cfg.Block[0] != "**/.env" {
		t.Errorf("expected [**/.env], got %v", cfg.Block)
	}
}

func TestStringOrArray_Array(t *testing.T) {
	yamlStr := `block: ["**/.env", "~/.ssh/*"]`
	var cfg struct {
		Block StringOrArray `yaml:"block"`
	}
	if err := yaml.Unmarshal([]byte(yamlStr), &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.Block) != 2 {
		t.Errorf("expected 2 patterns, got %d", len(cfg.Block))
	}
}

func TestStringOrArray_Empty(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
	}{
		{"empty string", `block: ""`, true},
		{"empty array", `block: []`, true},
		{"array with empty", `block: ["a", ""]`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg struct {
				Block StringOrArray `yaml:"block"`
			}
			err := yaml.Unmarshal([]byte(tt.input), &cfg)
			if tt.wantErr && err == nil {
				t.Error("expected error, got nil")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRuleConfig_SimpleBlock(t *testing.T) {
	yamlStr := `
rules:
  - block: "**/.env"
  - block: ["**/credentials*", "**/secrets*"]
    except: "**/*.example"
`
	var rs RuleSetConfig
	if err := yaml.Unmarshal([]byte(yamlStr), &rs); err != nil {
		t.Fatal(err)
	}
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}
	if len(rs.Rules) != 2 {
		t.Errorf("expected 2 rules, got %d", len(rs.Rules))
	}

	// Test conversion
	rules := rs.ToRules()
	if rules[0].Name != "block-recursive--env" {
		t.Errorf("unexpected generated name: %s", rules[0].Name)
	}
}

func TestRuleConfig_WithActions(t *testing.T) {
	yamlStr := `
rules:
  - block: "/etc/**"
    actions: [delete]
    message: "Cannot delete system files"
`
	var rs RuleSetConfig
	if err := yaml.Unmarshal([]byte(yamlStr), &rs); err != nil {
		t.Fatal(err)
	}
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}

	rules := rs.ToRules()
	if len(rules[0].Actions) != 1 || rules[0].Actions[0] != OpDelete {
		t.Errorf("expected [delete], got %v", rules[0].Actions)
	}
}

func TestRuleConfig_AdvancedMatch(t *testing.T) {
	yamlStr := `
rules:
  - name: block-proc-access
    match:
      path: "re:/proc/\\d+/environ"
      tool: [Bash, Read]
    message: "Cannot read process environment"
`
	var rs RuleSetConfig
	if err := yaml.Unmarshal([]byte(yamlStr), &rs); err != nil {
		t.Fatal(err)
	}
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}

	rules := rs.ToRules()
	if rules[0].Match == nil {
		t.Fatal("expected Match to be set")
	}
	if rules[0].Match.Path != "re:/proc/\\d+/environ" {
		t.Errorf("unexpected path: %s", rules[0].Match.Path)
	}
	if len(rules[0].Match.Tools) != 2 {
		t.Errorf("expected 2 tools, got %d", len(rules[0].Match.Tools))
	}
	// Tools should be normalized to lowercase
	if rules[0].Match.Tools[0] != "bash" {
		t.Errorf("expected lowercase 'bash', got %s", rules[0].Match.Tools[0])
	}
}

func TestRuleConfig_Composite(t *testing.T) {
	yamlStr := `
rules:
  - name: block-symlink-bypass
    all:
      - command: "re:ln\\s+-s"
      - path: "/etc/**"
  - name: block-dangerous-curl
    any:
      - command: "re:curl.*--upload-file"
      - command: "re:curl.*-T\\s"
`
	var rs RuleSetConfig
	if err := yaml.Unmarshal([]byte(yamlStr), &rs); err != nil {
		t.Fatal(err)
	}
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}

	rules := rs.ToRules()
	// First rule: all conditions
	if len(rules[0].AllConditions) != 2 {
		t.Errorf("expected 2 all conditions, got %d", len(rules[0].AllConditions))
	}
	// Second rule: any conditions
	if len(rules[1].AnyConditions) != 2 {
		t.Errorf("expected 2 any conditions, got %d", len(rules[1].AnyConditions))
	}
}

func TestRuleConfig_ValidationErrors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name: "no format",
			input: `
rules:
  - name: test`,
			wantErr: "must have block, match, all, or any",
		},
		{
			name: "mixed formats",
			input: `
rules:
  - block: "**/.env"
    match:
      path: "/etc/*"`,
			wantErr: "cannot mix block/match/all/any",
		},
		{
			name: "match without name",
			input: `
rules:
  - match:
      path: "/etc/*"`,
			wantErr: "require a name",
		},
		{
			name: "empty match",
			input: `
rules:
  - name: test
    match: {}`,
			wantErr: "must have at least one field",
		},
		{
			name: "unknown action",
			input: `
rules:
  - block: "**/.env"
    actions: [reed]`,
			wantErr: "unknown operation",
		},
		{
			name: "duplicate name",
			input: `
rules:
  - block: "**/.env"
    name: test
  - block: "**/.git"
    name: test`,
			wantErr: "duplicate rule name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rs RuleSetConfig
			err := yaml.Unmarshal([]byte(tt.input), &rs)
			if err == nil {
				err = rs.Validate()
			}
			if err == nil {
				t.Error("expected error, got nil")
				return
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestIsUnknownFieldError(t *testing.T) {
	input := `
rules:
  - name: test
    block: "/etc/passwd"
    alert_webhook: "https://example.com"
`
	var rs RuleSetConfig
	dec := yaml.NewDecoder(bytes.NewReader([]byte(input)))
	dec.KnownFields(true)
	err := dec.Decode(&rs)
	if err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
	if !isUnknownFieldError(err) {
		t.Errorf("expected unknown field error, got: %v", err)
	}
}

func TestRuleConfig_CaseInsensitiveActions(t *testing.T) {
	// YAML actions with mixed case should be accepted and normalized to lowercase
	yamlStr := `
rules:
  - block: "**/.env"
    actions: [Read, WRITE]
`
	var rs RuleSetConfig
	if err := yaml.Unmarshal([]byte(yamlStr), &rs); err != nil {
		t.Fatal(err)
	}
	if err := rs.Validate(); err != nil {
		t.Fatal(err)
	}

	rules := rs.ToRules()
	if rules[0].Actions[0] != OpRead {
		t.Errorf("expected lowercase 'read', got %q", rules[0].Actions[0])
	}
	if rules[0].Actions[1] != OpWrite {
		t.Errorf("expected lowercase 'write', got %q", rules[0].Actions[1])
	}
}

func TestRuleSetConfig_VersionValidation(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr bool
		errMsg  string
	}{
		{
			name: "version 0 (unset) is accepted",
			input: `
rules:
  - block: "**/.env"
`,
			wantErr: false,
		},
		{
			name: "version 1 is accepted",
			input: `
version: 1
rules:
  - block: "**/.env"
`,
			wantErr: false,
		},
		{
			name: "version 2 is rejected",
			input: `
version: 2
rules:
  - block: "**/.env"
`,
			wantErr: true,
			errMsg:  "unsupported version",
		},
		{
			name: "version 99 is rejected",
			input: `
version: 99
rules:
  - block: "**/.env"
`,
			wantErr: true,
			errMsg:  "unsupported version",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var rs RuleSetConfig
			if err := yaml.Unmarshal([]byte(tt.input), &rs); err != nil {
				t.Fatalf("YAML parse error: %v", err)
			}
			err := rs.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("error %q does not contain %q", err.Error(), tt.errMsg)
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}
