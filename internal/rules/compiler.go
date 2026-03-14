package rules

import (
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/gobwas/glob"
)

// compiledMatch holds pre-compiled patterns from a Match condition.
// All regex/glob patterns are validated and compiled at rule insert time,
// so evaluation never needs to re-compile or handle invalid patterns.
type compiledMatch struct {
	Match        Match          // original for error messages/display
	PathRegex    *regexp.Regexp // non-nil if Match.Path starts with "re:"
	PathGlob     glob.Glob      // non-nil if Match.Path is a glob pattern
	CommandRegex *regexp.Regexp // non-nil if Match.Command starts with "re:"
	HostRegex    *regexp.Regexp // non-nil if Match.Host starts with "re:"
	HostGlob     glob.Glob      // non-nil if Match.Host is a glob pattern
	ContentRegex *regexp.Regexp // non-nil if Match.Content starts with "re:"
	ContentLower string         // pre-lowered Match.Content for literal match (empty if regex)
	CommandLower string         // pre-lowered Match.Command for literal match (empty if regex)
}

// compiledRule is a rule with pre-compiled matchers
type compiledRule struct {
	Rule        Rule
	PathMatcher *Matcher // pre-compiled Block.Paths/Except
	HostMatcher *Matcher // pre-compiled Block.Hosts

	// Pre-compiled Match patterns (Level 4+ rules)
	MatchCompiled      *compiledMatch
	AllCompiledMatches []compiledMatch
	AnyCompiledMatches []compiledMatch
}

// maxRegexLen limits user-defined regex pattern length to bound compilation cost.
const maxRegexLen = 4096

func compileRegex(pattern string) (*regexp.Regexp, error) {
	if len(pattern) > maxRegexLen {
		return nil, fmt.Errorf("regex pattern too long (%d > %d chars)", len(pattern), maxRegexLen)
	}
	return regexp.Compile(pattern)
}

// patternKind returns "regex" or "glob" based on the pattern prefix.
func patternKind(pattern string) string {
	if strings.HasPrefix(pattern, "re:") {
		return "regex"
	}
	return "glob"
}

// Glob separators used by compilePattern.
const (
	pathGlobSeparator rune = '/'
	hostGlobSeparator rune = '.'
)

// compilePattern compiles a pattern as either a regex (if "re:" prefixed) or a glob.
// The separator is used for glob compilation (pathGlobSeparator for paths, hostGlobSeparator for hosts).
func compilePattern(pattern string, separator rune) (*regexp.Regexp, glob.Glob, error) {
	if strings.HasPrefix(pattern, "re:") {
		re, err := compileRegex(pattern[3:])
		return re, nil, err
	}
	g, err := glob.Compile(pattern, separator)
	return nil, g, err
}

// matchAnyRegexGlob returns true if any item matches the regex, glob, or literal.
// Pass nil for unused matchers. Literal is only checked if both re and g are nil.
func matchAnyRegexGlob(items []string, re *regexp.Regexp, g glob.Glob, literal string) bool {
	for _, item := range items {
		if re != nil {
			if re.MatchString(item) {
				return true
			}
		} else if g != nil {
			if g.Match(item) {
				return true
			}
		} else if item == literal {
			return true
		}
	}
	return false
}

// matchTools checks if toolName (lowercase) is in the list of allowed tools
func matchTools(tools []string, toolName string) bool {
	toolLower := strings.ToLower(toolName)
	return slices.Contains(tools, toolLower)
}

// sanitizePattern rejects patterns containing null bytes or control characters.
// Returns an error so the user gets a clear message about what's wrong.
func sanitizePattern(pattern string) error {
	for i := range len(pattern) {
		if pattern[i] == 0 {
			return fmt.Errorf("pattern contains null byte at position %d", i)
		}
		if pattern[i] < 0x20 && pattern[i] != '\t' {
			return fmt.Errorf("pattern contains control character 0x%02x at position %d", pattern[i], i)
		}
	}
	return nil
}

// sanitizePatterns validates a slice of patterns, returning a contextual error.
func sanitizePatterns(patterns []string, ruleName, fieldName string) error {
	for i, p := range patterns {
		if err := sanitizePattern(p); err != nil {
			return fmt.Errorf("rule %q %s[%d]: %w", ruleName, fieldName, i, err)
		}
	}
	return nil
}

// compileMatchConditions compiles a slice of Match conditions into compiledMatch values.
func compileMatchConditions(conditions []Match, ruleName, condType string) ([]compiledMatch, error) {
	var compiled []compiledMatch
	for i, cond := range conditions {
		cm, err := compileMatchPattern(&cond)
		if err != nil {
			return nil, fmt.Errorf("rule %q %s[%d]: %w", ruleName, condType, i, err)
		}
		if cm != nil {
			compiled = append(compiled, *cm)
		}
	}
	return compiled, nil
}

// compileMatchPattern pre-compiles a single Match condition's patterns.
// Returns clear errors for invalid patterns so rules are rejected at insert time.
func compileMatchPattern(m *Match) (*compiledMatch, error) {
	if m == nil {
		return nil, nil
	}
	cm := &compiledMatch{Match: *m}

	// Sanitize all pattern fields
	for _, check := range []struct{ name, pattern string }{
		{"path", m.Path}, {"command", m.Command},
		{"host", m.Host}, {"content", m.Content},
	} {
		if check.pattern == "" {
			continue
		}
		if err := sanitizePattern(check.pattern); err != nil {
			return nil, fmt.Errorf("match.%s: %w", check.name, err)
		}
	}

	// Compile Path (regex or glob)
	if m.Path != "" {
		re, g, err := compilePattern(m.Path, pathGlobSeparator)
		if err != nil {
			return nil, fmt.Errorf("match.path %s %q: %w", patternKind(m.Path), m.Path, err)
		}
		cm.PathRegex, cm.PathGlob = re, g
	}

	// Compile Command (regex only; literals use substring match at runtime)
	if m.Command != "" && strings.HasPrefix(m.Command, "re:") {
		re, err := compileRegex(m.Command[3:])
		if err != nil {
			return nil, fmt.Errorf("match.command regex %q: %w", m.Command, err)
		}
		cm.CommandRegex = re
	} else if m.Command != "" {
		cm.CommandLower = strings.ToLower(m.Command)
	}

	// Compile Host (regex or glob)
	if m.Host != "" {
		re, g, err := compilePattern(m.Host, hostGlobSeparator)
		if err != nil {
			return nil, fmt.Errorf("match.host %s %q: %w", patternKind(m.Host), m.Host, err)
		}
		cm.HostRegex, cm.HostGlob = re, g
	}

	// Compile Content (regex only; literals use substring match at runtime)
	if m.Content != "" && strings.HasPrefix(m.Content, "re:") {
		re, err := compileRegex(m.Content[3:])
		if err != nil {
			return nil, fmt.Errorf("match.content regex %q: %w", m.Content, err)
		}
		cm.ContentRegex = re
	} else if m.Content != "" {
		cm.ContentLower = strings.ToLower(m.Content)
	}

	return cm, nil
}

// compileRules compiles path/host patterns in rules.
// When strict is true (builtin rules), any compilation error aborts the entire batch.
// When strict is false (user rules), bad rules are skipped with a warning.
func (e *Engine) compileRules(rules []Rule, strict bool) ([]compiledRule, error) {
	compiled := make([]compiledRule, 0, len(rules))

	for _, rule := range rules {
		if !rule.IsEnabled() {
			continue
		}

		cr, err := compileOneRule(rule)
		if err != nil {
			if strict {
				return nil, err
			}
			log.Warn("Skipping rule %q from %s: %v", rule.Name, rule.FilePath, err)
			continue
		}
		compiled = append(compiled, cr)
	}

	return compiled, nil
}

// compileOneRule validates and compiles a single rule's patterns.
// Returns a clear error if any pattern is invalid.
func compileOneRule(rule Rule) (compiledRule, error) {
	// Sanitize Block patterns before compilation
	for _, check := range []struct {
		patterns []string
		field    string
	}{
		{rule.Block.Paths, "block.paths"},
		{rule.Block.Except, "block.except"},
		{rule.Block.Hosts, "block.hosts"},
	} {
		if err := sanitizePatterns(check.patterns, rule.Name, check.field); err != nil {
			return compiledRule{}, err
		}
	}

	// Compile path matcher (Block.Paths/Except)
	var pathMatcher *Matcher
	if len(rule.Block.Paths) > 0 {
		var err error
		pathMatcher, err = NewMatcher(rule.Block.Paths, rule.Block.Except)
		if err != nil {
			return compiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile host matcher (Block.Hosts) — uses '.' separator for domain names
	var hostMatcher *Matcher
	if len(rule.Block.Hosts) > 0 {
		var err error
		hostMatcher, err = NewHostMatcher(rule.Block.Hosts)
		if err != nil {
			return compiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile Match patterns (Level 4+ rules)
	var matchCompiled *compiledMatch
	if rule.Match != nil {
		var err error
		matchCompiled, err = compileMatchPattern(rule.Match)
		if err != nil {
			return compiledRule{}, fmt.Errorf("rule %q: %w", rule.Name, err)
		}
	}

	// Compile AllConditions (AND logic) and AnyConditions (OR logic)
	allCompiled, err := compileMatchConditions(rule.AllConditions, rule.Name, "all")
	if err != nil {
		return compiledRule{}, err
	}
	anyCompiled, err := compileMatchConditions(rule.AnyConditions, rule.Name, "any")
	if err != nil {
		return compiledRule{}, err
	}

	return compiledRule{
		Rule:               rule,
		PathMatcher:        pathMatcher,
		HostMatcher:        hostMatcher,
		MatchCompiled:      matchCompiled,
		AllCompiledMatches: allCompiled,
		AnyCompiledMatches: anyCompiled,
	}, nil
}
