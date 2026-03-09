//go:generate go run ./cmd/schema-check

package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"slices"

	"github.com/BakeLens/crust/internal/rules"
)

// Plugin is a late-stage protection layer (step 13+).
// Runs only for tool calls that passed all built-in checks.
// Implementations must be safe for concurrent use.
type Plugin interface {
	// Name returns a unique identifier (e.g. "sandbox", "rate-limiter").
	Name() string

	// Init is called once when the plugin is registered.
	// cfg is plugin-specific JSON configuration; nil means use defaults.
	Init(cfg json.RawMessage) error

	// Evaluate inspects an allowed tool call.
	// Return nil to allow, non-nil to block.
	// Must be safe for concurrent calls.
	// The context carries the per-call timeout — plugins should respect ctx.Done().
	Evaluate(ctx context.Context, req Request) *Result

	// Close releases plugin resources (processes, connections, etc).
	Close() error
}

// Request is the data available to plugins.
// All fields are read-only deep copies — safe for concurrent use.
// Serialized as JSON over the wire protocol for external plugins.
//
// Every field is always present in the JSON encoding (no omitempty)
// to eliminate ambiguity between "absent" and "zero value".
//
// Operation and Operations use rules.Operation — the same enum used
// by the YAML rules engine — making the plugin protocol a strict
// child of the rules type system.
type Request struct {
	ToolName   string            `json:"tool_name"`
	Arguments  json.RawMessage   `json:"arguments"`
	Operation  rules.Operation   `json:"operation"`
	Operations []rules.Operation `json:"operations"`
	Command    string            `json:"command"`
	Paths      []string          `json:"paths"`
	Hosts      []string          `json:"hosts"`
	Content    string            `json:"content"`
	Evasive    bool              `json:"evasive"`

	// Rules is a snapshot of all active engine rules at evaluation time.
	// Plugins can use this for context-aware decisions (e.g., "is this path
	// already protected by a builtin rule?"). Read-only; plugins cannot
	// modify the engine's rules. Always present (empty array if no rules).
	Rules []RuleSnapshot `json:"rules"`
}

// RuleSnapshot is a read-only, JSON-safe view of an engine rule.
// Fields use the same typed enums as the YAML rules engine
// (rules.Source, rules.Severity, rules.Operation).
//
// Every field is always present in the JSON encoding (no omitempty)
// to eliminate ambiguity between "absent" and "zero value".
type RuleSnapshot struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	Source      rules.Source      `json:"source"`
	Severity    rules.Severity    `json:"severity"`
	Priority    int               `json:"priority"`
	Actions     []rules.Operation `json:"actions"`
	BlockPaths  []string          `json:"block_paths"`
	BlockExcept []string          `json:"block_except"`
	BlockHosts  []string          `json:"block_hosts"`
	Message     string            `json:"message"`
	Locked      bool              `json:"locked"`
	Enabled     bool              `json:"enabled"`
	HitCount    int64             `json:"hit_count"`
}

// SnapshotRule converts a rules.Rule to a plugin RuleSnapshot.
// Centralizes the conversion logic between the two type systems.
func SnapshotRule(r *rules.Rule) RuleSnapshot {
	return RuleSnapshot{
		Name:        r.Name,
		Description: r.Description,
		Source:      r.Source,
		Severity:    r.GetSeverity(),
		Priority:    r.GetPriority(),
		Actions:     slices.Clone(r.Actions),
		BlockPaths:  slices.Clone(r.GetBlockPaths()),
		BlockExcept: slices.Clone(r.GetBlockExcept()),
		BlockHosts:  slices.Clone(r.GetBlockHosts()),
		Message:     r.Message,
		Locked:      r.IsLocked(),
		Enabled:     r.IsEnabled(),
		HitCount:    r.HitCount,
	}
}

// MarshalJSON ensures nil slices are encoded as [] not null.
func (r *Request) MarshalJSON() ([]byte, error) {
	if r.Operations == nil {
		r.Operations = []rules.Operation{}
	}
	if r.Paths == nil {
		r.Paths = []string{}
	}
	if r.Hosts == nil {
		r.Hosts = []string{}
	}
	if r.Rules == nil {
		r.Rules = []RuleSnapshot{}
	}
	for i := range r.Rules {
		r.Rules[i] = ensureRuleSlices(r.Rules[i])
	}
	type noMethod Request // prevent infinite recursion
	return json.Marshal(noMethod(*r))
}

// MarshalJSON ensures nil slices are encoded as [] not null.
func (r *RuleSnapshot) MarshalJSON() ([]byte, error) {
	*r = ensureRuleSlices(*r)
	type noMethod RuleSnapshot
	return json.Marshal(noMethod(*r))
}

// ensureRuleSlices normalizes nil slices to empty in a RuleSnapshot.
func ensureRuleSlices(r RuleSnapshot) RuleSnapshot {
	if r.Actions == nil {
		r.Actions = []rules.Operation{}
	}
	if r.BlockPaths == nil {
		r.BlockPaths = []string{}
	}
	if r.BlockExcept == nil {
		r.BlockExcept = []string{}
	}
	if r.BlockHosts == nil {
		r.BlockHosts = []string{}
	}
	return r
}

// DeepCopy returns a copy of the request with all slices cloned and
// nil slices normalized to empty (matching the JSON wire protocol invariant).
// Prevents a plugin from mutating data seen by subsequent plugins.
func (r Request) DeepCopy() Request {
	cp := r
	cp.Arguments = cloneOrEmpty(r.Arguments)
	cp.Operations = cloneOpsOrEmpty(r.Operations)
	cp.Paths = cloneStrOrEmpty(r.Paths)
	cp.Hosts = cloneStrOrEmpty(r.Hosts)
	cp.Rules = slices.Clone(r.Rules)
	if cp.Rules == nil {
		cp.Rules = []RuleSnapshot{}
	}
	// Clone inner slices of each RuleSnapshot to prevent shared backing arrays.
	for i := range cp.Rules {
		cp.Rules[i].Actions = cloneOpsOrEmpty(cp.Rules[i].Actions)
		cp.Rules[i].BlockPaths = cloneStrOrEmpty(cp.Rules[i].BlockPaths)
		cp.Rules[i].BlockExcept = cloneStrOrEmpty(cp.Rules[i].BlockExcept)
		cp.Rules[i].BlockHosts = cloneStrOrEmpty(cp.Rules[i].BlockHosts)
	}
	return cp
}

// cloneOrEmpty clones a byte slice, returning empty (not nil) if nil.
func cloneOrEmpty(b []byte) []byte {
	if b == nil {
		return []byte{}
	}
	return slices.Clone(b)
}

// cloneStrOrEmpty clones a string slice, returning empty (not nil) if nil.
func cloneStrOrEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return slices.Clone(s)
}

// cloneOpsOrEmpty clones an operation slice, returning empty (not nil) if nil.
func cloneOpsOrEmpty(ops []rules.Operation) []rules.Operation {
	if ops == nil {
		return []rules.Operation{}
	}
	return slices.Clone(ops)
}

// Result describes why a plugin blocked a call.
// Return nil from Evaluate to allow the call.
//
// Severity and Action use the same typed enums as the YAML rules engine.
type Result struct {
	Plugin   string         `json:"plugin"`
	RuleName string         `json:"rule_name"`
	Severity rules.Severity `json:"severity"`
	Action   rules.Action   `json:"action"`
	Message  string         `json:"message"`
}

// Validate checks that required fields are non-empty.
// Returns an error if the result would be meaningless (empty rule_name or message).
func (r *Result) Validate() error {
	if r.RuleName == "" {
		return errors.New("result rule_name must not be empty")
	}
	if r.Message == "" {
		return errors.New("result message must not be empty")
	}
	return nil
}

// EffectiveAction returns the action, defaulting to "block" if empty or invalid.
func (r *Result) EffectiveAction() rules.Action {
	if rules.ValidResponseActions[r.Action] {
		return r.Action
	}
	return rules.ActionBlock
}

// EffectiveSeverity returns the severity, defaulting to "high" if invalid.
func (r *Result) EffectiveSeverity() rules.Severity {
	if rules.ValidSeverities[r.Severity] {
		return r.Severity
	}
	return rules.SeverityHigh
}
