package plugin

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

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
// Operations uses rules.Operation (type string) — JSON-serializes to the
// same "read", "write", etc. strings expected by the sandbox schema.
type DenyRule struct {
	Name       string            `json:"name"`
	Patterns   []string          `json:"patterns,omitempty"`
	Except     []string          `json:"except,omitempty"`
	Operations []rules.Operation `json:"operations"`
	Hosts      []HostEntry       `json:"hosts,omitempty"`
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

// SandboxPluginName is the identifier for the sandbox plugin/executor.
const SandboxPluginName = "sandbox"

// SandboxPlugin wraps the sandbox binary as an in-process plugin.
// It builds a sandbox InputPolicy from the plugin Request, validates it,
// and can execute commands under the sandbox via Exec.
type SandboxPlugin struct {
	binaryPath string
	config     SandboxConfig
}

// NewSandboxPlugin creates a SandboxPlugin if the sandbox binary is on $PATH.
// Returns an error if the binary is not found.
func NewSandboxPlugin() (*SandboxPlugin, error) {
	path, err := exec.LookPath("bakelens-sandbox")
	if err != nil {
		return nil, fmt.Errorf("sandbox binary not found: %w", err)
	}
	return &SandboxPlugin{binaryPath: path}, nil
}

func (s *SandboxPlugin) Name() string { return SandboxPluginName }

func (s *SandboxPlugin) Init(cfg json.RawMessage) error {
	if len(cfg) == 0 {
		return nil
	}
	if err := json.Unmarshal(cfg, &s.config); err != nil {
		return err
	}
	return s.config.validate()
}

// Sandbox schema limits (from bakelens-sandbox docs/schema.json).
const (
	maxRuleName     = 128
	maxHostName     = 253
	maxResolvedIPs  = 64
	maxRules        = 256
	maxPatterns     = 64
	maxExcept       = 64
	maxPatternLen   = 512
	maxHostsPerRule = 256
	maxExtraPorts   = 1024
)

// validate checks SandboxConfig against sandbox schema constraints.
func (c *SandboxConfig) validate() error {
	for proto, ports := range c.ExtraPorts {
		if proto != "tcp" && proto != "udp" && proto != "sctp" {
			return fmt.Errorf("extra_ports: invalid protocol %q (must be tcp/udp/sctp)", proto)
		}
		if len(ports) > maxExtraPorts {
			return fmt.Errorf("extra_ports[%s]: %d ports exceeds max %d", proto, len(ports), maxExtraPorts)
		}
		seen := make(map[int]bool, len(ports))
		for _, p := range ports {
			if p < 1 || p > 65535 {
				return fmt.Errorf("extra_ports[%s]: port %d out of range 1-65535", proto, p)
			}
			if seen[p] {
				return fmt.Errorf("extra_ports[%s]: duplicate port %d", proto, p)
			}
			seen[p] = true
		}
	}
	if c.Resources != nil {
		if err := c.Resources.validate(); err != nil {
			return err
		}
	}
	return nil
}

// validate checks ResourcePolicy fields against sandbox schema ranges.
func (r *ResourcePolicy) validate() error {
	if r.MemoryLimitMB != nil {
		v := *r.MemoryLimitMB
		if v < 16 || v > 1048576 {
			return fmt.Errorf("resources.memory_limit_mb: %d out of range 16-1048576", v)
		}
	}
	if r.CPUTimeLimitSec != nil {
		v := *r.CPUTimeLimitSec
		if v < 1 || v > 922337203 {
			return fmt.Errorf("resources.cpu_time_limit_secs: %d out of range 1-922337203", v)
		}
	}
	if r.MaxProcesses != nil {
		v := *r.MaxProcesses
		if v < 1 {
			return fmt.Errorf("resources.max_processes: %d must be >= 1", v)
		}
	}
	return nil
}

// Evaluate builds a sandbox policy from the request and checks req.Paths
// against the policy's deny rules. The engine's extractor already extracted
// paths (including from interpreter code), so we just match them here.
func (s *SandboxPlugin) Evaluate(ctx context.Context, req Request) *Result {
	if req.Command == "" {
		return nil // not an executable tool call
	}

	policy := s.BuildPolicyCtx(ctx, req)

	// Validate the policy is well-formed JSON.
	if _, err := json.Marshal(policy); err != nil {
		return &Result{
			RuleName: "sandbox:policy-error",
			Severity: rules.SeverityHigh,
			Action:   rules.ActionBlock,
			Message:  fmt.Sprintf("failed to build sandbox policy: %v", err),
		}
	}

	// Check extracted paths against policy deny rules.
	// req.Paths comes from the engine's extractor (handles interpreter
	// code, shell parsing, variable expansion, etc.).
	for _, rule := range policy.Rules {
		if len(rule.Patterns) == 0 {
			continue
		}
		for _, path := range req.Paths {
			if matchesDenyRule(rule, path) {
				return &Result{
					RuleName: "sandbox:" + rule.Name,
					Severity: rules.SeverityCritical,
					Action:   rules.ActionBlock,
					Message:  fmt.Sprintf("Sandbox policy denies access to %q (rule %q)", path, rule.Name),
				}
			}
		}
	}

	return nil
}

func (s *SandboxPlugin) Close() error { return nil }

// Wrap prepares a WrapResult for running cmd under sandbox enforcement.
// The caller starts the returned Cmd, writes Handshake to its stdin,
// reads "ready" from stdout, then switches to passthrough mode.
//
// Returns nil if the sandbox binary is not available.
func (s *SandboxPlugin) Wrap(ctx context.Context, cmd []string, policy json.RawMessage) *WrapResult {
	if !s.Available() || len(cmd) == 0 {
		return nil
	}

	params, err := json.Marshal(WrapParams{
		Policy:  policy,
		Command: cmd,
	})
	if err != nil {
		return nil
	}

	req, err := json.Marshal(WireRequest{Method: MethodWrap, Params: params})
	if err != nil {
		return nil
	}
	// Wire protocol is JSON-newline: append \n so the plugin's line scanner can read it.
	req = append(req, '\n')

	child := exec.CommandContext(ctx, s.binaryPath) //nolint:gosec // binaryPath resolved via LookPath
	child.Env = append(os.Environ(), "PATH=/usr/bin:/bin:/usr/local/bin")

	return &WrapResult{
		Cmd:       child,
		Handshake: req,
	}
}

// BinaryPath returns the resolved path to the bakelens-sandbox binary.
func (s *SandboxPlugin) BinaryPath() string { return s.binaryPath }

// Available reports whether the sandbox binary exists and is executable.
func (s *SandboxPlugin) Available() bool { return s.binaryPath != "" }

// ExecGeneric implements the Executor interface with generic types.
// Unmarshals the policy JSON into InputPolicy and delegates to ExecPolicy.
func (s *SandboxPlugin) Exec(ctx context.Context, cmd []string, policy json.RawMessage) (*ExecResult, error) {
	var p InputPolicy
	if len(policy) > 0 {
		if err := json.Unmarshal(policy, &p); err != nil {
			return nil, fmt.Errorf("unmarshal sandbox policy: %w", err)
		}
	}
	p.Command = cmd
	result, err := s.ExecPolicy(ctx, p)
	if err != nil {
		return nil, err
	}
	return &ExecResult{
		ExitCode: result.ExitCode,
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	}, nil
}

// ExecPolicy runs a command under the sandbox with the given policy.
// The policy JSON is sent on stdin to the sandbox binary.
//
// Exit code protocol:
//
//	0-124 = target command exit code
//	125   = sandbox setup error (parse stderr JSON)
//	128+N = target killed by signal N
func (s *SandboxPlugin) ExecPolicy(ctx context.Context, policy InputPolicy) (*SandboxExecResult, error) {
	if !s.Available() {
		return nil, errors.New("sandbox binary not available")
	}

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
