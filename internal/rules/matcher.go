package rules

import (
	"strings"

	"github.com/BakeLens/crust/internal/pathutil"
	"github.com/gobwas/glob"
)

// Matcher matches normalized paths against glob patterns
type Matcher struct {
	patterns []glob.Glob
	excepts  []glob.Glob
}

// NewMatcher creates a matcher from glob patterns and exceptions.
// Patterns are lowercased on case-insensitive filesystems to match
// the lowercasing applied to paths in Match(). Returns an error if
// any pattern fails to compile.
func NewMatcher(patterns, excepts []string) (*Matcher, error) {
	fs := pathutil.DefaultFS()
	m := &Matcher{
		patterns: make([]glob.Glob, 0, len(patterns)),
		excepts:  make([]glob.Glob, 0, len(excepts)),
	}

	// Compile patterns (normalize separators + lowercase on case-insensitive filesystems)
	for _, p := range patterns {
		p = pathutil.ToSlash(p) // normalize \ to / so patterns match forward-slash paths on Windows
		g, err := glob.Compile(fs.Lower(p), '/')
		if err != nil {
			return nil, err
		}
		m.patterns = append(m.patterns, g)
	}

	// Compile excepts (normalize separators + lowercase on case-insensitive filesystems)
	for _, e := range excepts {
		e = pathutil.ToSlash(e) // normalize \ to / so excepts match forward-slash paths on Windows
		g, err := glob.Compile(fs.Lower(e), '/')
		if err != nil {
			return nil, err
		}
		m.excepts = append(m.excepts, g)
	}

	return m, nil
}

// Match checks if path matches any pattern (and not excluded by except).
// Returns true only if: matches a pattern AND does NOT match any except.
// Empty patterns means nothing matches.
func (m *Matcher) Match(p string) bool {
	if len(m.patterns) == 0 {
		return false
	}

	// Normalize separators: convert \ to / so glob patterns match consistently.
	p = pathutil.ToSlash(p)

	// SECURITY: Lowercase on case-insensitive filesystems. Defense-in-depth:
	// paths should already be lowercased by the normalizer, but this catches
	// any paths that bypass normalization. Uses kernel syscall detection.
	p = pathutil.DefaultFS().Lower(p)

	// Standard match: check if the path matches any compiled pattern.
	for _, pat := range m.patterns {
		if pat.Match(p) {
			for _, e := range m.excepts {
				if e.Match(p) {
					return false
				}
			}
			return true
		}
	}

	return false
}

// NewHostMatcher creates a matcher for hostname patterns using '.' as separator.
// This ensures that *.evil.com matches sub.evil.com but not sub.sub.evil.com.
func NewHostMatcher(patterns []string) (*Matcher, error) {
	m := &Matcher{
		patterns: make([]glob.Glob, 0, len(patterns)),
	}
	for _, p := range patterns {
		g, err := glob.Compile(strings.ToLower(p), '.')
		if err != nil {
			return nil, err
		}
		m.patterns = append(m.patterns, g)
	}
	return m, nil
}

// MatchHost checks if a hostname matches any pattern. Does not apply
// filesystem-specific lowercasing (hostnames are always case-insensitive).
func (m *Matcher) MatchHost(host string) bool {
	if len(m.patterns) == 0 {
		return false
	}
	host = strings.ToLower(host)
	for _, pat := range m.patterns {
		if pat.Match(host) {
			return true
		}
	}
	return false
}

// MatchAnyHost checks if any hostname matches, returns the first match.
func (m *Matcher) MatchAnyHost(hosts []string) (matched bool, matchedHost string) {
	for _, host := range hosts {
		if m.MatchHost(host) {
			return true, host
		}
	}
	return false, ""
}

// containsGlob returns true if s contains unescaped glob metacharacters.
func containsGlob(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// MatchAny checks if any of the paths match, returns the first match.
// Returns (false, "") if no paths match.
func (m *Matcher) MatchAny(paths []string) (matched bool, matchedPath string) {
	for _, path := range paths {
		if m.Match(path) {
			return true, path
		}
	}
	return false, ""
}
