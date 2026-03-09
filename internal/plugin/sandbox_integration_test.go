package plugin

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

// requireSandbox skips the test if bakelens-sandbox is not installed.
func requireSandbox(t *testing.T) *SandboxPlugin {
	t.Helper()
	path, err := exec.LookPath("bakelens-sandbox")
	if err != nil {
		t.Skip("bakelens-sandbox not installed")
	}
	return &SandboxPlugin{binaryPath: path}
}

// execPolicy runs a policy through the real sandbox binary.
// It sets the command to ["/usr/bin/true"] and returns any sandbox setup error.
func execPolicy(t *testing.T, sp *SandboxPlugin, policy InputPolicy) error {
	t.Helper()
	policy.Command = []string{"/usr/bin/true"}
	result, err := sp.Exec(context.Background(), policy)
	if err != nil {
		return err
	}
	if result.ExitCode != 0 {
		return fmt.Errorf("exit %d: %s", result.ExitCode, string(result.Stderr))
	}
	return nil
}

// --- Integration tests: invoke the real bakelens-sandbox binary ---

func TestSandboxExec_MinimalPolicy(t *testing.T) {
	sp := requireSandbox(t)
	policy := sp.BuildPolicy(Request{Command: "echo hello"})
	if err := execPolicy(t, sp, policy); err != nil {
		t.Fatalf("minimal policy: %v", err)
	}
}

func TestSandboxExec_FilesystemDenyRule(t *testing.T) {
	sp := requireSandbox(t)
	policy := sp.BuildPolicy(Request{
		Command: "echo test",
		Rules: []RuleSnapshot{
			{
				Name:       "block-ssh",
				Enabled:    true,
				Actions:    []rules.Operation{rules.OpRead, rules.OpWrite},
				BlockPaths: []string{"/home/user/.ssh/**"},
			},
		},
	})
	if err := execPolicy(t, sp, policy); err != nil {
		t.Fatalf("filesystem deny: %v", err)
	}
}

func TestSandboxExec_FilesystemDenyWithExcept(t *testing.T) {
	sp := requireSandbox(t)
	policy := sp.BuildPolicy(Request{
		Command: "echo test",
		Rules: []RuleSnapshot{
			{
				Name:        "block-ssh-except-config",
				Enabled:     true,
				Actions:     []rules.Operation{rules.OpRead, rules.OpWrite},
				BlockPaths:  []string{"/home/user/.ssh/**"},
				BlockExcept: []string{"/home/user/.ssh/config"},
			},
		},
	})
	if err := execPolicy(t, sp, policy); err != nil {
		t.Fatalf("filesystem deny with except: %v", err)
	}
}

func TestSandboxExec_ExtraPorts(t *testing.T) {
	sp := requireSandbox(t)
	sp.config.ExtraPorts = map[string][]int{"tcp": {8080, 9090}}
	policy := sp.BuildPolicy(Request{Command: "echo test"})
	if err := execPolicy(t, sp, policy); err != nil {
		t.Fatalf("extra_ports: %v", err)
	}
}

func TestSandboxExec_Resources(t *testing.T) {
	sp := requireSandbox(t)
	procs := 32
	sp.config.Resources = &ResourcePolicy{MaxProcesses: &procs}
	policy := sp.BuildPolicy(Request{Command: "echo test"})
	if err := execPolicy(t, sp, policy); err != nil {
		t.Fatalf("resources: %v", err)
	}
}

func TestSandboxExec_CommandExitCode(t *testing.T) {
	sp := requireSandbox(t)
	policy := sp.BuildPolicy(Request{Command: "false"})
	policy.Command = []string{"/usr/bin/false"}
	result, err := sp.Exec(context.Background(), policy)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	if result.ExitCode != 1 {
		t.Errorf("expected exit code 1, got %d", result.ExitCode)
	}
}

func TestSandboxExec_CommandOutput(t *testing.T) {
	sp := requireSandbox(t)
	policy := sp.BuildPolicy(Request{Command: "echo hello"})
	policy.Command = []string{"/bin/echo", "hello"}
	result, err := sp.Exec(context.Background(), policy)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit %d: %s", result.ExitCode, string(result.Stderr))
	}
	got := strings.TrimSpace(string(result.Stdout))
	if got != "hello" {
		t.Errorf("stdout: got %q, want %q", got, "hello")
	}
}

func TestSandboxExec_FilesystemDenyBlocks(t *testing.T) {
	sp := requireSandbox(t)
	policy := sp.BuildPolicy(Request{
		Command: "cat /etc/shadow",
		Rules: []RuleSnapshot{
			{
				Name:       "block-shadow",
				Enabled:    true,
				Actions:    []rules.Operation{rules.OpRead},
				BlockPaths: []string{"/etc/shadow"},
			},
		},
	})
	policy.Command = []string{"/bin/cat", "/etc/shadow"}
	result, err := sp.Exec(context.Background(), policy)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	// The sandbox should deny reading /etc/shadow.
	// The command should fail (non-zero exit) because the read is blocked.
	if result.ExitCode == 0 {
		t.Error("expected non-zero exit code when reading denied path")
	}
}

func TestSandboxExec_MultipleRules(t *testing.T) {
	sp := requireSandbox(t)
	policy := sp.BuildPolicy(Request{
		Command: "echo test",
		Rules: []RuleSnapshot{
			{
				Name:       "block-ssh",
				Enabled:    true,
				Actions:    []rules.Operation{rules.OpRead, rules.OpWrite},
				BlockPaths: []string{"/home/user/.ssh/**"},
			},
			{
				Name:       "block-secrets",
				Enabled:    true,
				Actions:    []rules.Operation{rules.OpRead},
				BlockPaths: []string{"/var/secrets/**"},
			},
			{
				Name:       "disabled-rule",
				Enabled:    false,
				Actions:    []rules.Operation{rules.OpRead},
				BlockPaths: []string{"/etc/**"},
			},
		},
	})
	if err := execPolicy(t, sp, policy); err != nil {
		t.Fatalf("multiple rules: %v", err)
	}
	// Disabled rule should be excluded.
	if len(policy.Rules) != 2 {
		t.Errorf("expected 2 rules (disabled excluded), got %d", len(policy.Rules))
	}
}

func TestSandboxExec_InvalidPolicy(t *testing.T) {
	sp := requireSandbox(t)
	// Empty command is invalid per schema (minItems: 1).
	policy := InputPolicy{
		Version: 1,
		Command: []string{},
		Rules:   []DenyRule{},
	}
	result, err := sp.Exec(context.Background(), policy)
	if err != nil {
		t.Fatalf("exec error: %v", err)
	}
	// Exit code 125 = sandbox setup error (parse_error).
	if result.ExitCode != 125 {
		t.Errorf("expected exit code 125 for invalid policy, got %d (stderr: %s)",
			result.ExitCode, string(result.Stderr))
	}
}

// --- Schema validation tests (pure Go, no binary) ---

func TestSandboxSchema_PolicyStructure(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}

	tests := []struct {
		name string
		req  Request
	}{
		{"minimal", Request{Command: "echo hello"}},
		{"filesystem_deny", Request{
			Command: "echo test",
			Rules: []RuleSnapshot{{
				Name: "block-ssh", Enabled: true,
				Actions:    []rules.Operation{rules.OpRead, rules.OpWrite},
				BlockPaths: []string{"/home/user/.ssh/**"},
			}},
		}},
		{"network_deny", Request{
			Command: "echo test",
			Rules: []RuleSnapshot{{
				Name: "block-evil", Enabled: true,
				BlockHosts: []string{"evil.com", "1.2.3.4"},
			}},
		}},
		{"mixed_rule", Request{
			Command: "echo test",
			Rules: []RuleSnapshot{{
				Name: "mixed", Enabled: true,
				Actions:    []rules.Operation{rules.OpRead},
				BlockPaths: []string{"/var/secrets/**"},
				BlockHosts: []string{"internal.corp"},
			}},
		}},
		{"with_except", Request{
			Command: "echo test",
			Rules: []RuleSnapshot{{
				Name: "except", Enabled: true,
				Actions:     []rules.Operation{rules.OpRead, rules.OpWrite},
				BlockPaths:  []string{"/home/user/.ssh/**"},
				BlockExcept: []string{"/home/user/.ssh/config"},
			}},
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := sp.BuildPolicy(tt.req)
			validatePolicySchema(t, policy)
		})
	}
}

func TestSandboxSchema_HostEntries(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox"}
	policy := sp.BuildPolicy(Request{
		Command: "echo test",
		Rules: []RuleSnapshot{{
			Name: "block-net", Enabled: true,
			BlockHosts: []string{"evil.com", "10.0.0.1", "192.168.0.0/16"},
		}},
	})
	validatePolicySchema(t, policy)

	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(policy.Rules))
	}
	r := policy.Rules[0]
	if len(r.Hosts) != 3 {
		t.Fatalf("expected 3 host entries, got %d", len(r.Hosts))
	}

	// IP passthrough.
	for _, h := range r.Hosts {
		if h.Name == "10.0.0.1" && (len(h.ResolvedIPs) != 1 || h.ResolvedIPs[0] != "10.0.0.1") {
			t.Errorf("IP passthrough failed for 10.0.0.1: %v", h.ResolvedIPs)
		}
		if h.Name == "192.168.0.0/16" && (len(h.ResolvedIPs) != 1 || h.ResolvedIPs[0] != "192.168.0.0/16") {
			t.Errorf("CIDR passthrough failed: %v", h.ResolvedIPs)
		}
	}
}

func TestSandboxSchema_Resources(t *testing.T) {
	mem, cpu, procs := 512, 30, 32
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox", config: SandboxConfig{
		Resources: &ResourcePolicy{MemoryLimitMB: &mem, CPUTimeLimitSec: &cpu, MaxProcesses: &procs},
	}}
	policy := sp.BuildPolicy(Request{Command: "echo test"})
	validatePolicySchema(t, policy)
}

func TestSandboxSchema_ExtraPorts(t *testing.T) {
	sp := &SandboxPlugin{binaryPath: "/usr/bin/bakelens-sandbox", config: SandboxConfig{
		ExtraPorts: map[string][]int{"tcp": {8080, 9090}},
	}}
	policy := sp.BuildPolicy(Request{Command: "echo test"})
	validatePolicySchema(t, policy)
}

// --- Schema validation helpers ---

func validatePolicySchema(t *testing.T, policy InputPolicy) {
	t.Helper()
	data, err := json.Marshal(policy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("not a JSON object: %v", err)
	}

	// Required top-level fields.
	for _, f := range []string{"version", "command", "rules"} {
		if _, ok := raw[f]; !ok {
			t.Errorf("missing required field %q", f)
		}
	}

	// additionalProperties: false
	allowed := map[string]bool{"version": true, "command": true, "rules": true, "extra_ports": true, "resources": true}
	for k := range raw {
		if !allowed[k] {
			t.Errorf("unknown top-level field %q", k)
		}
	}

	var version int
	if err := json.Unmarshal(raw["version"], &version); err != nil || version != 1 {
		t.Errorf("version must be 1, got %v", string(raw["version"]))
	}

	var command []string
	if err := json.Unmarshal(raw["command"], &command); err != nil || len(command) == 0 {
		t.Error("command must be non-empty string array")
	}

	var denyRules []json.RawMessage
	_ = json.Unmarshal(raw["rules"], &denyRules)
	for i, dr := range denyRules {
		validateDenyRuleSchema(t, i, dr)
	}

	if ep, ok := raw["extra_ports"]; ok {
		var ports map[string][]int
		if err := json.Unmarshal(ep, &ports); err != nil {
			t.Errorf("extra_ports: %v", err)
		}
		for proto, pp := range ports {
			if proto != "tcp" && proto != "udp" && proto != "sctp" {
				t.Errorf("extra_ports: unknown protocol %q", proto)
			}
			for _, p := range pp {
				if p < 1 || p > 65535 {
					t.Errorf("extra_ports[%s]: port %d out of range", proto, p)
				}
			}
		}
	}

	if res, ok := raw["resources"]; ok {
		var resMap map[string]json.RawMessage
		if err := json.Unmarshal(res, &resMap); err != nil {
			t.Errorf("resources: %v", err)
		}
		for k := range resMap {
			if k != "memory_limit_mb" && k != "cpu_time_limit_secs" && k != "max_processes" {
				t.Errorf("resources: unknown field %q", k)
			}
		}
	}
}

func validateDenyRuleSchema(t *testing.T, idx int, data json.RawMessage) {
	t.Helper()
	p := fmt.Sprintf("rules[%d]", idx)

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("%s: not a JSON object", p)
	}

	if _, ok := raw["name"]; !ok {
		t.Errorf("%s: missing 'name'", p)
	}
	if _, ok := raw["operations"]; !ok {
		t.Errorf("%s: missing 'operations'", p)
	}

	allowedFields := map[string]bool{"name": true, "patterns": true, "except": true, "operations": true, "hosts": true}
	for k := range raw {
		if !allowedFields[k] {
			t.Errorf("%s: unknown field %q", p, k)
		}
	}

	validOps := map[string]bool{"read": true, "write": true, "delete": true, "copy": true, "move": true, "execute": true}
	var ops []string
	if o, ok := raw["operations"]; ok {
		_ = json.Unmarshal(o, &ops)
		for _, op := range ops {
			if !validOps[op] {
				t.Errorf("%s: invalid operation %q", p, op)
			}
		}
	}

	var hosts []json.RawMessage
	if h, ok := raw["hosts"]; ok {
		_ = json.Unmarshal(h, &hosts)
	}
	if len(ops) == 0 && len(hosts) == 0 {
		t.Errorf("%s: must have non-empty operations or hosts", p)
	}

	for hi, hr := range hosts {
		hp := fmt.Sprintf("%s.hosts[%d]", p, hi)
		var hm map[string]json.RawMessage
		if err := json.Unmarshal(hr, &hm); err != nil {
			t.Fatalf("%s: not a JSON object", hp)
		}
		for _, f := range []string{"name", "resolved_ips"} {
			if _, ok := hm[f]; !ok {
				t.Errorf("%s: missing %q", hp, f)
			}
		}
		for k := range hm {
			if k != "name" && k != "resolved_ips" {
				t.Errorf("%s: unknown field %q", hp, k)
			}
		}
		if ips, ok := hm["resolved_ips"]; ok {
			var resolved []string
			_ = json.Unmarshal(ips, &resolved)
			if len(resolved) == 0 {
				t.Errorf("%s: resolved_ips must be non-empty", hp)
			}
			for _, ip := range resolved {
				if net.ParseIP(ip) == nil {
					if _, _, err := net.ParseCIDR(ip); err != nil {
						t.Errorf("%s: %q is not a valid IP or CIDR", hp, ip)
					}
				}
			}
		}
	}
}
