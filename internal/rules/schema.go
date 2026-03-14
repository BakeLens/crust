//go:generate go run ./cmd/schema-check

package rules

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Rule types for path-based security rules

// RuleSet represents a collection of rules from a YAML file
type RuleSet struct {
	Version int    `yaml:"version" json:"version"`
	Rules   []Rule `yaml:"rules" json:"rules"`
}

// Rule represents a security rule with path/host blocking
type Rule struct {
	Name        string      `yaml:"name" json:"name"`
	Description string      `yaml:"description,omitempty" json:"description,omitempty"`
	Enabled     *bool       `yaml:"enabled,omitempty" json:"enabled,omitempty"`   // default true
	Locked      *bool       `yaml:"locked,omitempty" json:"locked,omitempty"`     // locked rules survive --disable-builtin
	Priority    *int        `yaml:"priority,omitempty" json:"priority,omitempty"` // lower = higher priority, default 50
	Block       Block       `yaml:"block" json:"block"`
	Actions     []Operation `yaml:"actions" json:"actions"`
	Message     string      `yaml:"message" json:"message"`
	Severity    Severity    `yaml:"severity,omitempty" json:"severity,omitempty"`

	// Advanced match (Level 4)
	Match *Match `yaml:"-" json:"match,omitempty"`

	// Composite conditions (Level 5)
	AllConditions []Match `yaml:"-" json:"all_conditions,omitempty"` // AND
	AnyConditions []Match `yaml:"-" json:"any_conditions,omitempty"` // OR

	// Runtime fields
	Source   Source `yaml:"-" json:"source,omitempty"`
	FilePath string `yaml:"-" json:"file_path,omitempty"`
	HitCount int64  `yaml:"-" json:"hit_count,omitempty"` // number of times this rule matched
}

// Match represents a single match condition for advanced rules
type Match struct {
	Path    string        `json:"path,omitempty"`
	Command string        `json:"command,omitempty"`
	Host    string        `json:"host,omitempty"`
	Content string        `json:"content,omitempty"` // Pattern to match in Write/Edit content
	Tools   StringOrArray `json:"tools,omitempty"`
}

// Block defines what paths/hosts to block
type Block struct {
	Paths  StringOrArray `yaml:"paths,omitempty" json:"paths,omitempty"`   // glob patterns
	Except StringOrArray `yaml:"except,omitempty" json:"except,omitempty"` // exclusions
	Hosts  StringOrArray `yaml:"hosts,omitempty" json:"hosts,omitempty"`   // for network ops
}

// Operation represents the type of file/network operation
type Operation string

const (
	OpNone    Operation = ""
	OpRead    Operation = "read"
	OpWrite   Operation = "write"
	OpDelete  Operation = "delete"
	OpCopy    Operation = "copy"
	OpMove    Operation = "move"
	OpExecute Operation = "execute"
	OpNetwork Operation = "network"
	OpAll     Operation = "all" // expands to AllOperations at parse time
)

// ValidOperations is the set of all valid operation types.
var ValidOperations = map[Operation]bool{
	OpRead:    true,
	OpWrite:   true,
	OpDelete:  true,
	OpCopy:    true,
	OpMove:    true,
	OpExecute: true,
	OpNetwork: true,
}

// Default values for rules
const (
	DefaultRulePriority          = 50
	DefaultRuleSeverity Severity = SeverityCritical
)

// IsEnabled returns whether the rule is enabled (default true)
func (r *Rule) IsEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

// IsLocked returns whether the rule is locked (cannot be disabled via --disable-builtin)
func (r *Rule) IsLocked() bool {
	return r.Locked != nil && *r.Locked
}

// lockedTrue is a convenience pointer for setting Locked=true in Go-constructed rules.
var lockedTrue = func() *bool { t := true; return &t }()

// GetPriority returns the rule priority (default 50)
func (r *Rule) GetPriority() int {
	if r.Priority == nil {
		return DefaultRulePriority
	}
	return *r.Priority
}

// IntPtr is a convenience helper for creating *int values in Go-constructed rules.
func IntPtr(v int) *int { return new(v) }

// GetSeverity returns the rule severity (default critical)
func (r *Rule) GetSeverity() Severity {
	if r.Severity == "" {
		return DefaultRuleSeverity
	}
	return r.Severity
}

// Validate checks if the rule is well-formed
func (r *Rule) Validate() error {
	if r.Name == "" {
		return errors.New("rule name is required")
	}

	if r.Message == "" {
		return errors.New("rule message is required")
	}

	if len(r.Actions) == 0 {
		return errors.New("at least one action is required")
	}

	for _, op := range r.Actions {
		if !ValidOperations[Operation(strings.ToLower(string(op)))] {
			return fmt.Errorf("invalid action: %s", op)
		}
	}

	// Validate severity if explicitly set
	if r.Severity != "" && !ValidSeverities[r.Severity] {
		return fmt.Errorf("invalid severity: %s", r.Severity)
	}

	// Check if rule has any matching criteria (simple block, advanced match, or composite)
	hasBlockPaths := len(r.Block.Paths) > 0
	hasBlockHosts := len(r.Block.Hosts) > 0
	hasMatch := r.Match != nil
	hasAllConditions := len(r.AllConditions) > 0
	hasAnyConditions := len(r.AnyConditions) > 0

	if !hasBlockPaths && !hasBlockHosts && !hasMatch && !hasAllConditions && !hasAnyConditions {
		return errors.New("block.paths, block.hosts, match, all, or any is required")
	}

	// Validate that hosts are only used with network operation (for simple block format)
	if hasBlockHosts {
		hasNetwork := slices.Contains(r.Actions, OpNetwork)
		if !hasNetwork {
			return errors.New("block.hosts requires 'network' operation")
		}
	}

	// Validate advanced match
	if hasMatch {
		if err := r.Match.Validate(); err != nil {
			return fmt.Errorf("match: %w", err)
		}
	}

	// Validate composite conditions
	for i, cond := range r.AllConditions {
		if err := cond.Validate(); err != nil {
			return fmt.Errorf("all[%d]: %w", i, err)
		}
	}
	for i, cond := range r.AnyConditions {
		if err := cond.Validate(); err != nil {
			return fmt.Errorf("any[%d]: %w", i, err)
		}
	}

	return nil
}

// Validate checks if a Match condition has at least one field
func (m *Match) Validate() error {
	if m.Path == "" && m.Command == "" && m.Host == "" && m.Content == "" && len(m.Tools) == 0 {
		return errors.New("match must have at least one field (path, command, host, content, tools)")
	}
	return nil
}

// validateRuleSet validates all rules in a ruleset
func validateRuleSet(rs *RuleSet) error {
	if rs.Version != 1 {
		return fmt.Errorf("unsupported version: %d (expected 1)", rs.Version)
	}

	names := make(map[string]bool)
	for i, rule := range rs.Rules {
		if err := rule.Validate(); err != nil {
			return fmt.Errorf("rule[%d] %q: %w", i, rule.Name, err)
		}
		if names[rule.Name] {
			return fmt.Errorf("duplicate rule name: %s", rule.Name)
		}
		names[rule.Name] = true
	}

	return nil
}

// HasAction checks if the rule applies to the given action
func (r *Rule) HasAction(op Operation) bool {
	return slices.Contains(r.Actions, op)
}

// HasAnyAction returns true if any of the given operations matches this rule's actions.
func (r *Rule) HasAnyAction(ops []Operation) bool {
	for _, op := range ops {
		if slices.Contains(r.Actions, op) {
			return true
		}
	}
	return false
}

// GetName returns the rule name.
func (r *Rule) GetName() string { return r.Name }

// GetBlockPaths returns the blocked path patterns.
func (r *Rule) GetBlockPaths() []string { return r.Block.Paths }

// GetBlockExcept returns the exception path patterns.
func (r *Rule) GetBlockExcept() []string { return r.Block.Except }

// GetActions returns the rule actions as strings.
func (r *Rule) GetActions() []string {
	out := make([]string, len(r.Actions))
	for i, op := range r.Actions {
		out[i] = string(op)
	}
	return out
}

// GetBlockHosts returns the blocked host patterns.
func (r *Rule) GetBlockHosts() []string { return r.Block.Hosts }

// IsContentOnly returns true if this rule only matches on content (raw JSON)
// Content-only rules are evaluated for ALL tool calls regardless of operation
func (r *Rule) IsContentOnly() bool {
	// Must have Match with Content set
	if r.Match == nil || r.Match.Content == "" {
		return false
	}
	// Must not have other match conditions
	if r.Match.Path != "" || r.Match.Command != "" || r.Match.Host != "" || len(r.Match.Tools) > 0 {
		return false
	}
	// Must not have block paths/hosts
	if len(r.Block.Paths) > 0 || len(r.Block.Hosts) > 0 {
		return false
	}
	// Must not have composite conditions
	if len(r.AllConditions) > 0 || len(r.AnyConditions) > 0 {
		return false
	}
	return true
}
