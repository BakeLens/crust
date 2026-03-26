package plugin

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/gobwas/glob"
)

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
			ops := filterSandboxOps(snap.Actions)
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
				Operations: []rules.Operation{}, // network-only rule; filesystem ops empty
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

// filterSandboxOps filters rules.Operation values to those supported by
// the sandbox schema, deduplicating (sandbox requires uniqueItems).
func filterSandboxOps(ops []rules.Operation) []rules.Operation {
	seen := make(map[rules.Operation]bool, len(ops))
	out := make([]rules.Operation, 0, len(ops))
	for _, op := range ops {
		if sandboxOperations[op] && !seen[op] {
			seen[op] = true
			out = append(out, op)
		}
	}
	return out
}

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
