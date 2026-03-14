//go:build ignore

// This program verifies builtin security.yaml integrity against a hardcoded
// SHA-512 checksum and expected rule inventory. Run via go generate.
package main

import (
	"crypto/sha512"
	"fmt"
	"os"
	"regexp"
)

const (
	file          = "builtin/security.yaml"
	expectedHash  = "fe3a5b468f4a4c7e12db703d5158602094553e4a24543923a186003cbaa138ec267fd5c0f3d99fd09cf20e78ad69a45262fff312ac3dedb0ac262ece1d79d13d"
	expectedCount = 30
)

// Critical rules that must be present — removal would silently disable
// core protections (credentials, self-protection, persistence, shells).
var criticalRules = []string{
	"protect-env-files",
	"protect-ssh-keys",
	"protect-system-auth",
	"protect-crust",
	"protect-shell-history",
	"protect-cloud-credentials",
	"protect-gpg-keys",
	"protect-browser-data",
	"protect-git-credentials",
	"protect-package-tokens",
	"protect-shell-rc",
	"protect-ssh-authorized-keys",
	"protect-desktop-app-tokens",
	"protect-os-keychains",
	"protect-github-cli",
	"detect-private-key-write",
	"block-eval-exec",
	"protect-system-config",
	"protect-persistence",
	"detect-reverse-shell",
	"block-ssrf-metadata",
	"protect-agent-config",
	"protect-vscode-settings",
	"protect-git-hooks",
	"protect-mobile-pii",
	"protect-mobile-clipboard",
	"protect-mobile-url-schemes",
	"protect-mobile-hardware",
	"protect-mobile-biometric",
	"protect-mobile-purchases",
}

func main() {
	data, err := os.ReadFile(file)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: %s: %v\n", file, err)
		os.Exit(1)
	}

	failed := 0

	// 1. SHA-512 checksum
	got := fmt.Sprintf("%x", sha512.Sum512(data))
	if got != expectedHash {
		fmt.Fprintf(os.Stderr, "FAIL: %s: SHA-512 mismatch\n  got:  %s\n  want: %s\n", file, got, expectedHash)
		failed++
	}

	// 2. Rule count
	nameRe := regexp.MustCompile(`(?m)^\s*- name:\s+(.+)$`)
	matches := nameRe.FindAllStringSubmatch(string(data), -1)
	if len(matches) != expectedCount {
		fmt.Fprintf(os.Stderr, "FAIL: %s: rule count mismatch (got %d, want %d)\n", file, len(matches), expectedCount)
		failed++
	}

	// 3. Critical rule presence
	found := make(map[string]bool, len(matches))
	for _, m := range matches {
		found[m[1]] = true
	}
	for _, name := range criticalRules {
		if !found[name] {
			fmt.Fprintf(os.Stderr, "FAIL: %s: critical rule %q missing\n", file, name)
			failed++
		}
	}

	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\n%d security.yaml integrity check(s) failed.\n", failed)
		os.Exit(1)
	}
	fmt.Printf("ok: %s verified (%d rules, SHA-512)\n", file, expectedCount)
}
