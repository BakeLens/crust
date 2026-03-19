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
	"github.com/gobwas/glob"
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

// BinaryPath returns the resolved path to the bakelens-sandbox binary.
func (s *SandboxPlugin) BinaryPath() string { return s.binaryPath }

// Available reports whether the sandbox binary exists and is executable.
func (s *SandboxPlugin) Available() bool { return s.binaryPath != "" }

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

// BuildPolicy translates a plugin Request into a sandbox InputPolicy.
// Uses context.Background() for DNS resolution; prefer BuildPolicyCtx.
func (s *SandboxPlugin) BuildPolicy(req Request) InputPolicy {
	return s.BuildPolicyCtx(context.Background(), req)
}

// BuildPolicyCtx translates a plugin Request into a sandbox InputPolicy.
// The context is used for DNS resolution timeouts in network deny rules.
func (s *SandboxPlugin) BuildPolicyCtx(ctx context.Context, req Request) InputPolicy {
	policy := InputPolicy{
		Version:    1,
		Command:    splitCommand(req.Command),
		Rules:      buildDenyRules(ctx, req.Rules),
		ExtraPorts: s.config.ExtraPorts,
		Resources:  s.config.Resources,
	}
	return policy
}

// splitCommand splits a shell command string into tokens.
// This is a simple split on whitespace — proper shlex parsing is a follow-up.
func splitCommand(cmd string) []string {
	if cmd == "" {
		return []string{}
	}
	return strings.Fields(cmd)
}

// buildDenyRules translates RuleSnapshots into sandbox DenyRules.
func buildDenyRules(ctx context.Context, snapshots []RuleSnapshot) []DenyRule {
	seen := make(map[string]bool)
	var denyRules []DenyRule
	for _, snap := range snapshots {
		if !snap.Enabled {
			continue
		}
		// Build filesystem deny rule if paths are present and at least one
		// sandbox-supported operation exists (filters out network-only rules).
		if len(snap.BlockPaths) > 0 {
			ops := operationsToStrings(snap.Actions)
			if len(ops) > 0 {
				name := clampName(snap.Name, seen)
				dr := DenyRule{
					Name:       name,
					Patterns:   clampPatterns(absolutePatterns(snap.BlockPaths), maxPatterns),
					Except:     clampPatterns(absolutePatterns(snap.BlockExcept), maxExcept),
					Operations: ops,
				}
				denyRules = append(denyRules, dr)
			}
		}
		// Build network deny rule if hosts are present.
		if len(snap.BlockHosts) > 0 {
			name := clampName(snap.Name+":network", seen)
			hosts := resolveHosts(ctx, snap.BlockHosts)
			if len(hosts) > maxHostsPerRule {
				hosts = hosts[:maxHostsPerRule]
			}
			dr := DenyRule{
				Name:       name,
				Operations: []string{}, // network-only rule; filesystem ops empty
				Hosts:      hosts,
			}
			denyRules = append(denyRules, dr)
		}
	}
	if denyRules == nil {
		return []DenyRule{}
	}
	if len(denyRules) > maxRules {
		denyRules = denyRules[:maxRules]
	}
	return denyRules
}

// clampName truncates to maxRuleName and ensures uniqueness by appending a suffix.
func clampName(name string, seen map[string]bool) string {
	if len(name) > maxRuleName {
		name = name[:maxRuleName]
	}
	if !seen[name] {
		seen[name] = true
		return name
	}
	// Append numeric suffix for uniqueness.
	for i := 2; ; i++ {
		suffix := fmt.Sprintf(":%d", i)
		candidate := name
		if len(candidate)+len(suffix) > maxRuleName {
			candidate = candidate[:maxRuleName-len(suffix)]
		}
		candidate += suffix
		if !seen[candidate] {
			seen[candidate] = true
			return candidate
		}
	}
}

// clampPatterns deduplicates, truncates each to maxPatternLen, and caps the count.
func clampPatterns(patterns []string, maxCount int) []string { //nolint:unparam // maxPatterns and maxExcept are separate schema limits
	if len(patterns) == 0 {
		return patterns
	}
	seen := make(map[string]bool, len(patterns))
	out := make([]string, 0, len(patterns))
	for _, p := range patterns {
		if len(p) > maxPatternLen {
			p = p[:maxPatternLen]
		}
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
		if len(out) >= maxCount {
			break
		}
	}
	return out
}

// resolveHosts converts host strings to HostEntry objects.
// If a host is already an IP/CIDR, it's used directly.
// Otherwise, DNS resolution is attempted; unresolvable hosts are
// included with the hostname as a placeholder IP (best-effort).
func resolveHosts(ctx context.Context, hosts []string) []HostEntry {
	var resolver net.Resolver
	entries := make([]HostEntry, 0, len(hosts))
	for _, h := range hosts {
		name := h
		if len(name) > maxHostName {
			name = name[:maxHostName]
		}
		entry := HostEntry{Name: name}
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
				if len(ips) > maxResolvedIPs {
					ips = ips[:maxResolvedIPs]
				}
				entry.ResolvedIPs = ips
			}
		}
		entries = append(entries, entry)
	}
	return entries
}

// absolutePatterns converts "**/" prefixed glob patterns to absolute paths
// required by the sandbox schema (must start with "/", "~", or "$HOME").
//
// The engine expands $HOME before patterns reach plugins, so by the time
// this runs, all $HOME patterns are already absolute (e.g. "/Users/cyy/.ssh/id_*").
// The only remaining case is "**/" recursive globs which need a "/" prefix.
func absolutePatterns(patterns []string) []string {
	if len(patterns) == 0 {
		return patterns
	}
	out := make([]string, len(patterns))
	for i, p := range patterns {
		out[i] = absolutePattern(p)
	}
	return out
}

func absolutePattern(p string) string {
	if len(p) == 0 || p[0] == '/' || p[0] == '~' {
		return p
	}
	if strings.HasPrefix(p, "**/") {
		return "/" + p // **/.env → /**/.env
	}
	return p
}

// sandboxOperations is the set of operations supported by the bakelens-sandbox schema.
// "network" and "all" are crust-only operations that have no sandbox equivalent.
var sandboxOperations = map[rules.Operation]bool{
	rules.OpRead:    true,
	rules.OpWrite:   true,
	rules.OpDelete:  true,
	rules.OpCopy:    true,
	rules.OpMove:    true,
	rules.OpExecute: true,
}

// operationsToStrings converts []rules.Operation to []string,
// filtering out operations not supported by the sandbox schema
// and deduplicating (sandbox requires uniqueItems).
func operationsToStrings(ops []rules.Operation) []string {
	seen := make(map[rules.Operation]bool, len(ops))
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		if sandboxOperations[op] && !seen[op] {
			seen[op] = true
			out = append(out, string(op))
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Interpreter evasion detection
// ---------------------------------------------------------------------------

// matchesDenyRule checks if a path matches any of the rule's deny patterns
// and is not excluded by the rule's except patterns. Uses the same glob
// library (gobwas/glob) as the rule engine's Matcher.
func matchesDenyRule(rule DenyRule, path string) bool {
	for _, pattern := range rule.Patterns {
		g, err := glob.Compile(pattern, '/')
		if err != nil {
			continue
		}
		if g.Match(path) {
			// Check exceptions.
			for _, exc := range rule.Except {
				eg, err := glob.Compile(exc, '/')
				if err != nil {
					continue
				}
				if eg.Match(path) {
					return false
				}
			}
			return true
		}
	}
	return false
}
