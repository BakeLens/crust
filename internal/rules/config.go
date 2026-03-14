package rules

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// StringOrArray handles YAML fields that accept string or []string
type StringOrArray []string

func (s *StringOrArray) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		if node.Value == "" {
			return errors.New("empty pattern not allowed")
		}
		*s = []string{node.Value}
		return nil
	case yaml.SequenceNode:
		var arr []string
		if err := node.Decode(&arr); err != nil {
			return err
		}
		if len(arr) == 0 {
			return errors.New("empty pattern list not allowed")
		}
		for i, v := range arr {
			if v == "" {
				return fmt.Errorf("pattern[%d]: empty pattern not allowed", i)
			}
		}
		*s = arr
		return nil
	case yaml.DocumentNode, yaml.MappingNode, yaml.AliasNode:
		return fmt.Errorf("must be string or array, got %v", node.Kind)
	default:
		// Future yaml.v3 Kind values.
		return fmt.Errorf("must be string or array, got %v", node.Kind)
	}
}

// RuleConfig is the YAML structure for a rule (progressive disclosure)
type RuleConfig struct {
	// Simple format (Level 1-3): block: "pattern" or block: ["p1", "p2"]
	Block  StringOrArray `yaml:"block,omitempty"`
	Except StringOrArray `yaml:"except,omitempty"`

	// Advanced format (Level 4): match: { path: ..., command: ... }
	Match *MatchConfig `yaml:"match,omitempty"`

	// Composite format (Level 5): all: [...] or any: [...]
	All []MatchConfig `yaml:"all,omitempty"`
	Any []MatchConfig `yaml:"any,omitempty"`

	// Common fields
	Name     string      `yaml:"name,omitempty"`
	Locked   *bool       `yaml:"locked,omitempty"`
	Actions  []Operation `yaml:"actions,omitempty"`
	Message  string      `yaml:"message,omitempty"`
	Severity Severity    `yaml:"severity,omitempty"`
}

// MatchConfig is a single match condition
type MatchConfig struct {
	Path    string        `yaml:"path,omitempty"`
	Command string        `yaml:"command,omitempty"`
	Host    string        `yaml:"host,omitempty"`
	Content string        `yaml:"content,omitempty"` // Pattern to match in Write/Edit content
	Tool    StringOrArray `yaml:"tool,omitempty"`
}

// Validate checks RuleConfig for semantic errors
func (r *RuleConfig) Validate() error {
	formats := 0
	if len(r.Block) > 0 {
		formats++
	}
	if r.Match != nil {
		formats++
	}
	if len(r.All) > 0 {
		formats++
	}
	if len(r.Any) > 0 {
		formats++
	}

	if formats == 0 {
		return errors.New("rule must have block, match, all, or any")
	}
	if formats > 1 {
		return errors.New("rule cannot mix block/match/all/any")
	}

	// except is only valid with block format
	if len(r.Except) > 0 && len(r.Block) == 0 {
		return errors.New("except is only valid with block format")
	}

	// Composite/match rules require name
	if (r.Match != nil || len(r.All) > 0 || len(r.Any) > 0) && r.Name == "" {
		return errors.New("match/composite rules require a name")
	}

	// Validate match conditions
	if r.Match != nil {
		if err := r.Match.Validate(); err != nil {
			return fmt.Errorf("match: %w", err)
		}
	}
	for i, cond := range r.All {
		if err := cond.Validate(); err != nil {
			return fmt.Errorf("all[%d]: %w", i, err)
		}
	}
	for i, cond := range r.Any {
		if err := cond.Validate(); err != nil {
			return fmt.Errorf("any[%d]: %w", i, err)
		}
	}

	// Validate actions (operations this rule applies to)
	for _, op := range r.Actions {
		lower := Operation(strings.ToLower(string(op)))
		if lower != OpAll && !ValidOperations[lower] {
			return fmt.Errorf("unknown operation: %q", op)
		}
	}

	return nil
}

// Validate checks if a match condition has at least one field
func (m *MatchConfig) Validate() error {
	if m.Path == "" && m.Command == "" && m.Host == "" && m.Content == "" && len(m.Tool) == 0 {
		return errors.New("must have at least one field (path, command, host, content, tool)")
	}
	return nil
}

// ToRule converts RuleConfig to the internal Rule type
func (r *RuleConfig) ToRule() *Rule {
	rule := &Rule{
		Name:     r.Name,
		Locked:   r.Locked,
		Message:  r.Message,
		Severity: r.Severity,
		Actions:  parseActions(r.Actions),
	}

	// Simple block format
	if len(r.Block) > 0 {
		rule.Block = Block{
			Paths:  r.Block,
			Except: r.Except,
		}
		if rule.Name == "" {
			rule.Name = generateName(r.Block[0])
		}
		if rule.Message == "" {
			rule.Message = "Access blocked: " + r.Block[0]
		}
		return rule
	}

	// Advanced match format
	if r.Match != nil {
		rule.Match = convertMatch(r.Match)
		return rule
	}

	// Composite format
	if len(r.All) > 0 {
		rule.AllConditions = convertMatches(r.All)
		return rule
	}
	if len(r.Any) > 0 {
		rule.AnyConditions = convertMatches(r.Any)
		return rule
	}

	return rule
}

func convertMatch(cfg *MatchConfig) *Match {
	return &Match{
		Path:    cfg.Path,
		Command: cfg.Command,
		Host:    cfg.Host,
		Content: cfg.Content,
		Tools:   normalizeTools(cfg.Tool),
	}
}

func convertMatches(cfgs []MatchConfig) []Match {
	matches := make([]Match, len(cfgs))
	for i := range cfgs {
		matches[i] = *convertMatch(&cfgs[i])
	}
	return matches
}

func normalizeTools(tools StringOrArray) StringOrArray {
	if len(tools) == 0 {
		return nil
	}
	normalized := make(StringOrArray, len(tools))
	for i, t := range tools {
		normalized[i] = strings.ToLower(t)
	}
	return normalized
}

func generateName(pattern string) string {
	name := pattern
	name = strings.ReplaceAll(name, "**", "recursive")
	name = strings.ReplaceAll(name, "*", "any")
	name = strings.ReplaceAll(name, "/", "-")
	name = strings.ReplaceAll(name, ".", "-")
	name = strings.TrimPrefix(name, "-")
	name = strings.TrimSuffix(name, "-")
	if name == "" {
		name = "unnamed-rule"
	}
	return "block-" + name
}

// AllOperations is the default set of operations when no actions are specified.
var AllOperations = []Operation{OpRead, OpWrite, OpDelete, OpCopy, OpMove, OpExecute, OpNetwork}

func parseActions(ops []Operation) []Operation {
	if len(ops) == 0 {
		return AllOperations
	}
	result := make([]Operation, 0, len(ops))
	for _, op := range ops {
		lower := Operation(strings.ToLower(string(op)))
		if lower == OpAll {
			return AllOperations
		}
		if ValidOperations[lower] {
			result = append(result, lower)
		}
	}
	return result
}

// RuleSetConfig is the top-level YAML structure
type RuleSetConfig struct {
	Version int          `yaml:"version"`
	Rules   []RuleConfig `yaml:"rules"`
}

// Validate validates all rules in the set
func (rs *RuleSetConfig) Validate() error {
	if rs.Version != 0 && rs.Version != 1 {
		return fmt.Errorf("unsupported version: %d (expected 1)", rs.Version)
	}
	names := make(map[string]bool)
	for i, rule := range rs.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule[%d] %q: %w", i, rule.Name, err)
		}
		name := rule.Name
		if name == "" && len(rule.Block) > 0 {
			name = generateName(rule.Block[0])
		}
		if names[name] {
			return fmt.Errorf("duplicate rule name: %s", name)
		}
		names[name] = true
	}
	return nil
}

// ToRules converts all RuleConfigs to internal Rules
func (rs *RuleSetConfig) ToRules() []Rule {
	rules := make([]Rule, len(rs.Rules))
	for i := range rs.Rules {
		rules[i] = *rs.Rules[i].ToRule()
	}
	return rules
}
