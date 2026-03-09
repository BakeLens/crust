package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

// ResourcePolicy defines resource limits for sandboxed processes.
// Field names match the bakelens-sandbox schema (docs/schema.json).
type ResourcePolicy struct {
	MemoryLimitMB   *int `json:"memory_limit_mb,omitempty"`
	CPUTimeLimitSec *int `json:"cpu_time_limit_secs,omitempty"`
	MaxProcesses    *int `json:"max_processes,omitempty"`
}

// SandboxConfig holds optional configuration for the sandbox plugin.
type SandboxConfig struct {
	ExtraPorts map[string][]int `json:"extra_ports,omitempty"`
	Resources  *ResourcePolicy  `json:"resources,omitempty"`
}

// HostEntry is a pre-resolved host for network deny.
// DNS resolution happens upstream; the sandbox receives resolved IPs.
type HostEntry struct {
	Name        string   `json:"name"`
	ResolvedIPs []string `json:"resolved_ips"`
}

// DenyRule is a single deny rule in the sandbox input policy.
type DenyRule struct {
	Name       string      `json:"name"`
	Patterns   []string    `json:"patterns,omitempty"`
	Except     []string    `json:"except,omitempty"`
	Operations []string    `json:"operations"`
	Hosts      []HostEntry `json:"hosts,omitempty"`
}

// InputPolicy is the JSON policy sent to bakelens-sandbox on stdin.
type InputPolicy struct {
	Version    int              `json:"version"`
	Command    []string         `json:"command"`
	Rules      []DenyRule       `json:"rules"`
	ExtraPorts map[string][]int `json:"extra_ports,omitempty"`
	Resources  *ResourcePolicy  `json:"resources,omitempty"`
}

// SandboxExecResult holds the result of executing a command under the sandbox.
type SandboxExecResult struct {
	ExitCode int
	Stdout   []byte
	Stderr   []byte
}

// SandboxPlugin wraps the bakelens-sandbox binary as an in-process plugin.
// It builds a sandbox InputPolicy from the plugin Request, validates it,
// and can execute commands under the sandbox via Exec.
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

// Exec runs a command under the sandbox with the given policy.
// The policy JSON is sent on stdin to bakelens-sandbox, which executes
// the command in a sandboxed environment.
//
// Exit code protocol (from bakelens-sandbox):
//
//	0-124 = target command exit code
//	125   = sandbox setup error (parse stderr JSON)
//	128+N = target killed by signal N
func (s *SandboxPlugin) Exec(ctx context.Context, policy InputPolicy) (*SandboxExecResult, error) {
	policyJSON, err := json.Marshal(policy)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sandbox policy: %w", err)
	}

	cmd := exec.CommandContext(ctx, s.binaryPath) //nolint:gosec // binaryPath is resolved via LookPath at construction time
	cmd.Stdin = bytes.NewReader(policyJSON)
	cmd.Env = append(os.Environ(), "PATH=/usr/bin:/bin:/usr/local/bin")

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()

	result := &SandboxExecResult{
		Stdout: stdout.Bytes(),
		Stderr: stderr.Bytes(),
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return result, fmt.Errorf("failed to run sandbox: %w", err)
		}
	}

	return result, nil
}

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
				Name:       snap.Name,
				Patterns:   snap.BlockPaths,
				Except:     snap.BlockExcept,
				Operations: operationsToStrings(snap.Actions),
			}
			denyRules = append(denyRules, dr)
		}
		// Build network deny rule if hosts are present.
		if len(snap.BlockHosts) > 0 {
			dr := DenyRule{
				Name:       snap.Name + ":network",
				Operations: []string{}, // network-only rule; filesystem ops empty
				Hosts:      resolveHosts(snap.BlockHosts),
			}
			denyRules = append(denyRules, dr)
		}
	}
	if denyRules == nil {
		return []DenyRule{}
	}
	return denyRules
}

// resolveHosts converts host strings to HostEntry objects.
// If a host is already an IP/CIDR, it's used directly.
// Otherwise, DNS resolution is attempted; unresolvable hosts are
// included with the hostname as a placeholder IP (best-effort).
func resolveHosts(hosts []string) []HostEntry {
	var resolver net.Resolver
	ctx := context.Background()
	entries := make([]HostEntry, 0, len(hosts))
	for _, h := range hosts {
		entry := HostEntry{Name: h}
		// Check if already an IP or CIDR.
		if net.ParseIP(h) != nil {
			entry.ResolvedIPs = []string{h}
		} else if _, _, err := net.ParseCIDR(h); err == nil {
			entry.ResolvedIPs = []string{h}
		} else {
			// Attempt DNS resolution.
			ips, err := resolver.LookupHost(ctx, h)
			if err != nil || len(ips) == 0 {
				// Best-effort: use 0.0.0.0 as placeholder so the rule is
				// still structurally valid. The sandbox will accept it but
				// it won't match real traffic.
				entry.ResolvedIPs = []string{"0.0.0.0"}
			} else {
				entry.ResolvedIPs = ips
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// operationsToStrings converts []rules.Operation to []string.
func operationsToStrings(ops []rules.Operation) []string {
	out := make([]string, len(ops))
	for i, op := range ops {
		out[i] = string(op)
	}
	return out
}
