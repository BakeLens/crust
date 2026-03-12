package rules

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// SanitizeToolName removes dangerous characters from tool names.
func SanitizeToolName(name string) string {
	// Remove null bytes
	name = stripNullBytes(name)

	// Trim whitespace
	name = strings.TrimSpace(name)

	// Remove control characters
	name = stripControlChars(name)

	return name
}

// stripNullBytes removes null bytes from a string.
func stripNullBytes(s string) string {
	return strings.ReplaceAll(s, "\x00", "")
}

// stripControlChars removes ASCII control characters (except tab, newline).
func stripControlChars(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 && r != '\t' && r != '\n' && r != '\r' {
			return -1
		}
		return r
	}, s)
}

// NormalizeUnicode applies NFKC normalization, diacritical mark stripping,
// and cross-script confusable stripping.
// NFKC handles fullwidth→ASCII, compatibility decomposition, etc.
// stripDiacritics decomposes to NFD, strips combining marks, then recomposes
// to NFC — prevents accented characters from bypassing regex character
// classes (e.g., E+\u0301 → É which doesn't match [er]).
// stripConfusables handles Cyrillic/Greek homoglyphs (а→a, е→e, etc.).
func NormalizeUnicode(s string) string {
	s = strings.ToValidUTF8(s, "\uFFFD")
	s = norm.NFKC.String(s)
	s = stripDiacritics(s)
	s = stripConfusables(s)
	s = stripInvisible(s)
	s = norm.NFKC.String(s)
	return s
}

// stripDiacritics removes diacritical marks (combining marks, Unicode category Mn)
// from a string. It decomposes to NFD first so precomposed characters like É
// (U+00C9) are split into base + combining mark, then strips the marks, and
// recomposes via NFC. Shell commands and file paths never use diacritics
// legitimately, and they can bypass regex character classes.
func stripDiacritics(s string) string {
	// Decompose: É (U+00C9) → E (U+0045) + ◌́ (U+0301)
	decomposed := norm.NFD.String(s)
	// Strip combining marks (Mn = Mark, Nonspacing)
	stripped := strings.Map(func(r rune) rune {
		if unicode.Is(unicode.Mn, r) {
			return -1
		}
		return r
	}, decomposed)
	// Recompose remaining characters
	return norm.NFC.String(stripped)
}

// IsSuspiciousInput checks for common evasion patterns.
func IsSuspiciousInput(s string) (suspicious bool, reasons []string) {
	// Check for null bytes
	if strings.ContainsRune(s, 0) {
		suspicious = true
		reasons = append(reasons, "input contains hidden null characters")
	}

	// Check for fullwidth characters
	for _, r := range s {
		if r >= 0xFF01 && r <= 0xFF5E {
			suspicious = true
			reasons = append(reasons, "input uses lookalike fullwidth characters")
			break
		}
	}

	// Check for cross-script confusable characters
	for _, r := range s {
		if _, ok := confusableMap[r]; ok {
			suspicious = true
			reasons = append(reasons, "input uses lookalike characters from another script")
			break
		}
	}

	// Check for excessive path traversal
	if strings.Count(s, "..") > 3 {
		suspicious = true
		reasons = append(reasons, "input navigates too many parent directories")
	}

	// Check for very long repeated patterns (potential ReDoS)
	if len(s) > 10000 {
		suspicious = true
		reasons = append(reasons, fmt.Sprintf("input is unusually long (%d bytes)", len(s)))
	}

	// Check for control characters
	for _, r := range s {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			suspicious = true
			reasons = append(reasons, "input contains hidden control characters")
			break
		}
	}

	return
}
