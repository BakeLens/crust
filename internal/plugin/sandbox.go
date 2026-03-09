package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

// ResourcePolicy defines resource limits for sandboxed processes.
type ResourcePolicy struct {
	MaxMemoryMB int `json:"max_memory_mb,omitempty"`
	MaxCPUPct   int `json:"max_cpu_pct,omitempty"`
	MaxTimeSec  int `json:"max_time_sec,omitempty"`
}

// SandboxConfig holds optional configuration for the sandbox plugin.
type SandboxConfig struct {
	ExtraPorts map[string][]int `json:"extra_ports,omitempty"`
	Resources  *ResourcePolicy  `json:"resources,omitempty"`
}

// DenyRule is a single deny rule in the sandbox input policy.
type DenyRule struct {
	Name       string   `json:"name"`
	Patterns   []string `json:"patterns,omitempty"`
	Except     []string `json:"except,omitempty"`
	Operations []string `json:"operations,omitempty"`
	Hosts      []string `json:"hosts,omitempty"`
}

// InputPolicy is the JSON policy sent to bakelens-sandbox on stdin.
type InputPolicy struct {
	Version    int              `json:"version"`
	Command    []string         `json:"command"`
	Rules      []DenyRule       `json:"rules"`
	ExtraPorts map[string][]int `json:"extra_ports,omitempty"`
	Resources  *ResourcePolicy  `json:"resources,omitempty"`
}

// SandboxPlugin wraps the bakelens-sandbox binary as an in-process plugin.
// It builds a sandbox InputPolicy from the plugin Request and validates it.
// The actual exec-time wrapping is a follow-up — for now it returns nil (allow)
// after successfully building the policy.
type SandboxPlugin struct {
	binaryPath string
	config     SandboxConfig
}

// NewSandboxPlugin creates a SandboxPlugin if bakelens-sandbox is on $PATH.
// Returns an error if the binary is not found.
func NewSandboxPlugin() (*SandboxPlugin, error) {
	path, err := exec.LookPath("bakelens-sandbox")
	if err != nil {
		return nil, fmt.Errorf("bakelens-sandbox not found: %w", err)
	}
	return &SandboxPlugin{binaryPath: path}, nil
}

func (s *SandboxPlugin) Name() string { return "sandbox" }

func (s *SandboxPlugin) Init(cfg json.RawMessage) error {
	if len(cfg) == 0 {
		return nil
	}
	return json.Unmarshal(cfg, &s.config)
}

// Evaluate builds a sandbox policy from the request.
// Returns nil (allow) — the policy is available for future exec-time wrapping.
func (s *SandboxPlugin) Evaluate(_ context.Context, req Request) *Result {
	if req.Command == "" {
		return nil // not an executable tool call
	}

	policy := s.BuildPolicy(req)

	// Validate the policy is well-formed JSON.
	if _, err := json.Marshal(policy); err != nil {
		return &Result{
			RuleName: "sandbox:policy-error",
			Severity: rules.SeverityHigh,
			Action:   rules.ActionBlock,
			Message:  fmt.Sprintf("failed to build sandbox policy: %v", err),
		}
	}

	return nil // allow — policy built successfully
}

func (s *SandboxPlugin) Close() error { return nil }

// BinaryPath returns the resolved path to the bakelens-sandbox binary.
func (s *SandboxPlugin) BinaryPath() string { return s.binaryPath }

// BuildPolicy translates a plugin Request into a sandbox InputPolicy.
func (s *SandboxPlugin) BuildPolicy(req Request) InputPolicy {
	policy := InputPolicy{
		Version:    1,
		Command:    splitCommand(req.Command),
		Rules:      buildDenyRules(req.Rules),
		ExtraPorts: s.config.ExtraPorts,
		Resources:  s.config.Resources,
	}
	return policy
}

// splitCommand splits a shell command string into tokens.
// This is a simple split on whitespace — proper shlex parsing is a follow-up.
func splitCommand(cmd string) []string {
	parts := strings.Fields(cmd)
	if parts == nil {
		return []string{}
	}
	return parts
}

// buildDenyRules translates RuleSnapshots into sandbox DenyRules.
func buildDenyRules(snapshots []RuleSnapshot) []DenyRule {
	var denyRules []DenyRule
	for _, snap := range snapshots {
		if !snap.Enabled {
			continue
		}
		// Build filesystem deny rule if paths are present.
		if len(snap.BlockPaths) > 0 {
			dr := DenyRule{
				Name:     snap.Name,
				Patterns: snap.BlockPaths,
				Except:   snap.BlockExcept,
			}
			if len(snap.Actions) > 0 {
				dr.Operations = operationsToStrings(snap.Actions)
			}
			denyRules = append(denyRules, dr)
		}
		// Build network deny rule if hosts are present.
		if len(snap.BlockHosts) > 0 {
			dr := DenyRule{
				Name:  snap.Name + ":network",
				Hosts: snap.BlockHosts,
			}
			denyRules = append(denyRules, dr)
		}
	}
	if denyRules == nil {
		return []DenyRule{}
	}
	return denyRules
}

// operationsToStrings converts []rules.Operation to []string.
func operationsToStrings(ops []rules.Operation) []string {
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = string(op)
	}
	return out
}
