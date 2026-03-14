package rules

import (
	"testing"

	"gopkg.in/yaml.v3"
)

func TestRule_Validate(t *testing.T) {
	tests := []struct {
		name    string
		rule    Rule
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid rule with paths",
			rule: Rule{
				Name:    "protect-env",
				Message: "Cannot access .env files",
				Actions: []Operation{OpRead, OpWrite},
				Block: Block{
					Paths: []string{"**/.env"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid rule with hosts",
			rule: Rule{
				Name:    "block-internal",
				Message: "Cannot access internal network",
				Actions: []Operation{OpNetwork},
				Block: Block{
					Hosts: []string{"10.**", "192.168.**"},
				},
			},
			wantErr: false,
		},
		{
			name: "valid rule with paths and except",
			rule: Rule{
				Name:    "protect-env",
				Message: "Cannot access .env files",
				Actions: []Operation{OpRead},
				Block: Block{
					Paths:  []string{"**/.env", "**/.env.*"},
					Except: []string{"**/.env.example"},
				},
			},
			wantErr: false,
		},
		{
			name: "missing name",
			rule: Rule{
				Message: "test",
				Actions: []Operation{OpRead},
				Block:   Block{Paths: []string{"*"}},
			},
			wantErr: true,
			errMsg:  "rule name is required",
		},
		{
			name: "missing message",
			rule: Rule{
				Name:    "test",
				Actions: []Operation{OpRead},
				Block:   Block{Paths: []string{"*"}},
			},
			wantErr: true,
			errMsg:  "rule message is required",
		},
		{
			name: "missing operations",
			rule: Rule{
				Name:    "test",
				Message: "test",
				Block:   Block{Paths: []string{"*"}},
			},
			wantErr: true,
			errMsg:  "at least one action is required",
		},
		{
			name: "invalid action",
			rule: Rule{
				Name:    "test",
				Message: "test",
				Actions: []Operation{"invalid"},
				Block:   Block{Paths: []string{"*"}},
			},
			wantErr: true,
			errMsg:  "invalid action: invalid",
		},
		{
			name: "missing paths and hosts",
			rule: Rule{
				Name:    "test",
				Message: "test",
				Actions: []Operation{OpRead},
				Block:   Block{},
			},
			wantErr: true,
			errMsg:  "block.paths, block.hosts, match, all, or any is required",
		},
		{
			name: "hosts without network operation",
			rule: Rule{
				Name:    "test",
				Message: "test",
				Actions: []Operation{OpRead},
				Block: Block{
					Hosts: []string{"10.**"},
				},
			},
			wantErr: true,
			errMsg:  "block.hosts requires 'network' operation",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.rule.Validate()
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tt.errMsg)
				} else if tt.errMsg != "" && err.Error() != tt.errMsg {
					t.Errorf("expected error %q, got %q", tt.errMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
		})
	}
}

func TestRule_IsEnabled(t *testing.T) {
	t.Run("default is true", func(t *testing.T) {
		r := Rule{}
		if !r.IsEnabled() {
			t.Error("expected default enabled to be true")
		}
	})

	t.Run("explicit true", func(t *testing.T) {
		enabled := true
		r := Rule{Enabled: &enabled}
		if !r.IsEnabled() {
			t.Error("expected enabled to be true")
		}
	})

	t.Run("explicit false", func(t *testing.T) {
		enabled := false
		r := Rule{Enabled: &enabled}
		if r.IsEnabled() {
			t.Error("expected enabled to be false")
		}
	})
}

func TestRule_GetPriority(t *testing.T) {
	t.Run("default is 50", func(t *testing.T) {
		r := Rule{}
		if r.GetPriority() != 50 {
			t.Errorf("expected default priority 50, got %d", r.GetPriority())
		}
	})

	t.Run("explicit priority", func(t *testing.T) {
		r := Rule{Priority: new(10)}
		if r.GetPriority() != 10 {
			t.Errorf("expected priority 10, got %d", r.GetPriority())
		}
	})

	t.Run("explicit priority zero", func(t *testing.T) {
		r := Rule{Priority: new(0)}
		if r.GetPriority() != 0 {
			t.Errorf("expected priority 0, got %d", r.GetPriority())
		}
	})
}

func TestRule_GetSeverity(t *testing.T) {
	t.Run("default is critical", func(t *testing.T) {
		r := Rule{}
		if r.GetSeverity() != SeverityCritical {
			t.Errorf("expected default severity critical, got %s", r.GetSeverity())
		}
	})

	t.Run("explicit severity", func(t *testing.T) {
		r := Rule{Severity: SeverityWarning}
		if r.GetSeverity() != SeverityWarning {
			t.Errorf("expected severity warning, got %s", r.GetSeverity())
		}
	})
}

func TestRule_PriorityYAMLUnmarshal(t *testing.T) {
	t.Run("omitted yields nil", func(t *testing.T) {
		var rs RuleSet
		err := yaml.Unmarshal([]byte("version: 1\nrules:\n  - name: test\n    message: msg\n    actions: [read]\n    block:\n      paths: [\"/x\"]\n"), &rs)
		if err != nil {
			t.Fatal(err)
		}
		if rs.Rules[0].Priority != nil {
			t.Errorf("expected nil Priority, got %d", *rs.Rules[0].Priority)
		}
		if rs.Rules[0].GetPriority() != DefaultRulePriority {
			t.Errorf("expected default priority %d, got %d", DefaultRulePriority, rs.Rules[0].GetPriority())
		}
	})

	t.Run("explicit 0 yields 0", func(t *testing.T) {
		var rs RuleSet
		err := yaml.Unmarshal([]byte("version: 1\nrules:\n  - name: test\n    priority: 0\n    message: msg\n    actions: [read]\n    block:\n      paths: [\"/x\"]\n"), &rs)
		if err != nil {
			t.Fatal(err)
		}
		if rs.Rules[0].Priority == nil {
			t.Fatal("expected non-nil Priority for explicit 0")
		}
		if *rs.Rules[0].Priority != 0 {
			t.Errorf("expected Priority 0, got %d", *rs.Rules[0].Priority)
		}
		if rs.Rules[0].GetPriority() != 0 {
			t.Errorf("expected GetPriority() 0, got %d", rs.Rules[0].GetPriority())
		}
	})
}

func TestRule_HasAction(t *testing.T) {
	r := Rule{
		Actions: []Operation{OpRead, OpWrite, OpDelete},
	}

	tests := []struct {
		op   Operation
		want bool
	}{
		{OpRead, true},
		{OpWrite, true},
		{OpDelete, true},
		{OpCopy, false},
		{OpNetwork, false},
	}

	for _, tt := range tests {
		t.Run(string(tt.op), func(t *testing.T) {
			if got := r.HasAction(tt.op); got != tt.want {
				t.Errorf("HasAction(%s) = %v, want %v", tt.op, got, tt.want)
			}
		})
	}
}

func TestValidateRuleSet(t *testing.T) {
	t.Run("valid ruleset", func(t *testing.T) {
		rs := &RuleSet{
			Version: 1,
			Rules: []Rule{
				{
					Name:    "rule1",
					Message: "msg1",
					Actions: []Operation{OpRead},
					Block:   Block{Paths: []string{"*"}},
				},
				{
					Name:    "rule2",
					Message: "msg2",
					Actions: []Operation{OpWrite},
					Block:   Block{Paths: []string{"*"}},
				},
			},
		}
		if err := validateRuleSet(rs); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("invalid version", func(t *testing.T) {
		rs := &RuleSet{Version: 2}
		err := validateRuleSet(rs)
		if err == nil {
			t.Error("expected error for invalid version")
		}
	})

	t.Run("duplicate rule names", func(t *testing.T) {
		rs := &RuleSet{
			Version: 1,
			Rules: []Rule{
				{
					Name:    "same-name",
					Message: "msg1",
					Actions: []Operation{OpRead},
					Block:   Block{Paths: []string{"*"}},
				},
				{
					Name:    "same-name",
					Message: "msg2",
					Actions: []Operation{OpWrite},
					Block:   Block{Paths: []string{"*"}},
				},
			},
		}
		err := validateRuleSet(rs)
		if err == nil {
			t.Error("expected error for duplicate rule names")
		}
	})

	t.Run("invalid rule in set", func(t *testing.T) {
		rs := &RuleSet{
			Version: 1,
			Rules: []Rule{
				{
					Name: "", // invalid - missing name
				},
			},
		}
		err := validateRuleSet(rs)
		if err == nil {
			t.Error("expected error for invalid rule")
		}
	})
}

func TestRule_Validate_CaseInsensitiveActions(t *testing.T) {
	// Rule.Validate should accept uppercase operations (matching YAML path behavior).
	r := Rule{
		Name:    "test",
		Message: "test",
		Actions: []Operation{"READ"},
		Block:   Block{Paths: []string{"*"}},
	}
	if err := r.Validate(); err != nil {
		t.Errorf("Rule.Validate rejected uppercase operation: %v", err)
	}
}

func TestOperation_Constants(t *testing.T) {
	// Verify all operations are in ValidOperations
	ops := []Operation{OpRead, OpWrite, OpDelete, OpCopy, OpMove, OpExecute, OpNetwork}
	for _, op := range ops {
		if !ValidOperations[op] {
			t.Errorf("operation %s not in ValidOperations", op)
		}
	}

	// Verify count matches
	if len(ValidOperations) != len(ops) {
		t.Errorf("ValidOperations has %d entries, expected %d", len(ValidOperations), len(ops))
	}
}
