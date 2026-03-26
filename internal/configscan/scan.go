// Package configscan detects malicious endpoint redirects in project config files.
// CVE-2026-21852: .env sets ANTHROPIC_BASE_URL to attacker endpoint, leaking API keys.
package configscan

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Finding describes a suspicious endpoint redirect in a config file.
type Finding struct {
	File     string `json:"file"`
	Variable string `json:"variable"`
	Value    string `json:"value"`
	Risk     string `json:"risk"`
}

// envRedirectRe matches *_BASE_URL=, *_API_BASE=, *_API_URL=, *_ENDPOINT= patterns.
var envRedirectRe = regexp.MustCompile(`^([A-Z_]*(?:BASE_URL|API_BASE|API_URL|ENDPOINT))\s*=\s*["']?(\S+?)["']?\s*$`)

// knownSafeDomains are official API endpoints that are not suspicious.
var knownSafeDomains = map[string]bool{
	"api.anthropic.com":                 true,
	"api.openai.com":                    true,
	"generativelanguage.googleapis.com": true,
	"api.groq.com":                      true,
	"api.mistral.ai":                    true,
	"dashscope.aliyuncs.com":            true,
	"api.deepseek.com":                  true,
	"api.cohere.com":                    true,
	"openrouter.ai":                     true,
	"api.together.xyz":                  true,
	"api.fireworks.ai":                  true,
	"api.perplexity.ai":                 true,
	"api.x.ai":                          true,
	"localhost":                         true,
	"127.0.0.1":                         true,
	"0.0.0.0":                           true,
	"::1":                               true,
}

// ScanDir scans a directory and its parents (up to root or home) for
// config files containing suspicious endpoint redirects.
func ScanDir(dir string) []Finding {
	var findings []Finding
	findings = append(findings, scanEnvFiles(dir)...)
	findings = append(findings, scanClaudeSettings(dir)...)
	findings = append(findings, scanPackageManagerConfigs(dir)...)
	return findings
}

// ScanDirOnly scans a single directory without walking parents.
func ScanDirOnly(dir string) []Finding {
	var findings []Finding
	findings = append(findings, scanEnvFilesInDir(dir)...)
	findings = append(findings, scanClaudeSettingsInDir(dir)...)
	findings = append(findings, scanPackageManagerConfigsInDir(dir)...)
	return findings
}

// walkParents calls scanFn on dir and each parent directory up to (but not
// above) the user's home directory. Falls back to scanning dir only if home
// cannot be determined.
func walkParents(dir string, scanFn func(string) []Finding) []Finding {
	home, err := os.UserHomeDir()
	if err != nil {
		return scanFn(dir)
	}

	var findings []Finding
	for {
		findings = append(findings, scanFn(dir)...)
		parent := filepath.Dir(dir)
		if parent == dir || dir == home {
			break
		}
		dir = parent
	}
	return findings
}

// scanEnvFiles scans .env files in the given directory and parent dirs.
func scanEnvFiles(dir string) []Finding {
	return walkParents(dir, scanEnvFilesInDir)
}

func scanEnvFilesInDir(dir string) []Finding {
	var findings []Finding
	envFiles := []string{".env", ".env.local", ".env.production", ".env.development"}

	for _, name := range envFiles {
		path := filepath.Join(dir, name)
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if strings.HasPrefix(line, "#") {
				continue
			}
			m := envRedirectRe.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			varName, value := m[1], m[2]
			if isSuspiciousURL(value) {
				findings = append(findings, Finding{
					File:     path,
					Variable: varName,
					Value:    value,
					Risk:     "redirects API traffic to non-official endpoint",
				})
			}
		}
		f.Close()
	}
	return findings
}

// scanClaudeSettings scans .claude/settings*.json for apiUrl overrides.
func scanClaudeSettings(dir string) []Finding {
	return walkParents(dir, scanClaudeSettingsInDir)
}

func scanClaudeSettingsInDir(dir string) []Finding {
	var findings []Finding
	settingsPath := filepath.Join(dir, ".claude", "settings.json")

	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return nil
	}

	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		return nil
	}

	// Check for apiUrl field
	if apiURL, ok := settings["apiUrl"].(string); ok && apiURL != "" {
		if isSuspiciousURL(apiURL) {
			findings = append(findings, Finding{
				File:     settingsPath,
				Variable: "apiUrl",
				Value:    apiURL,
				Risk:     "Claude Code API URL overridden to non-official endpoint",
			})
		}
	}

	return findings
}

// extractHost returns the lowercase hostname from a URL, stripping protocol and path.
func extractHost(rawURL string) string {
	u := strings.ToLower(rawURL)
	u = strings.TrimPrefix(u, "https://")
	u = strings.TrimPrefix(u, "http://")
	if i := strings.IndexAny(u, "/:"); i >= 0 {
		u = u[:i]
	}
	return u
}

// isSuspiciousURL returns true if the URL doesn't point to a known safe API domain.
func isSuspiciousURL(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	return !knownSafeDomains[extractHost(rawURL)]
}

// scanPackageManagerConfigs scans for registry redirects in package manager configs.
func scanPackageManagerConfigs(dir string) []Finding {
	return walkParents(dir, scanPackageManagerConfigsInDir)
}

func scanPackageManagerConfigsInDir(dir string) []Finding {
	var findings []Finding

	// .npmrc — registry=https://evil.com
	findings = append(findings, scanNpmrc(filepath.Join(dir, ".npmrc"))...)

	// pyproject.toml — index-url = "https://evil.com/simple"
	findings = append(findings, scanPyprojectToml(filepath.Join(dir, "pyproject.toml"))...)

	return findings
}

// npmrcRegistryRe matches registry=<url> in .npmrc files, including scoped registries (@scope:registry=).
var npmrcRegistryRe = regexp.MustCompile(`(?i)^\s*(?:@[a-z0-9_-]+:)?registry\s*=\s*["']?(\S+?)["']?\s*$`)

// knownSafeRegistries are official package registries that are not suspicious.
var knownSafeRegistries = map[string]bool{
	"registry.npmjs.org":     true,
	"registry.yarnpkg.com":   true,
	"pypi.org":               true,
	"upload.pypi.org":        true,
	"files.pythonhosted.org": true,
	"crates.io":              true,
	"rubygems.org":           true,
	"repo1.maven.org":        true,
	"repo.maven.apache.org":  true,
	"plugins.gradle.org":     true,
	"jcenter.bintray.com":    true,
	"localhost":              true,
	"127.0.0.1":              true,
	"0.0.0.0":                true,
	"::1":                    true,
}

func scanNpmrc(path string) []Finding {
	var findings []Finding
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, ";") || strings.HasPrefix(line, "#") {
			continue
		}
		m := npmrcRegistryRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		url := m[1]
		if isSuspiciousRegistry(url) {
			findings = append(findings, Finding{
				File:     path,
				Variable: "registry",
				Value:    url,
				Risk:     "npm registry redirected to non-official endpoint",
			})
		}
	}
	return findings
}

// pyprojectIndexRe matches index-url or extra-index-url in pyproject.toml [tool.pip] or [tool.uv] sections.
// pyprojectIndexRe matches index-url or extra-index-url in pyproject.toml. Handles optional inline comments.
var pyprojectIndexRe = regexp.MustCompile(`(?i)^\s*(?:index-url|extra-index-url)\s*=\s*["'](\S+?)["']`)

func scanPyprojectToml(path string) []Finding {
	var findings []Finding
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		m := pyprojectIndexRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		url := m[1]
		if isSuspiciousRegistry(url) {
			findings = append(findings, Finding{
				File:     path,
				Variable: "index-url",
				Value:    url,
				Risk:     "Python package index redirected to non-official endpoint",
			})
		}
	}
	return findings
}

// isSuspiciousRegistry returns true if the URL doesn't point to a known safe package registry.
func isSuspiciousRegistry(rawURL string) bool {
	if rawURL == "" {
		return false
	}
	return !knownSafeRegistries[extractHost(rawURL)]
}

// FindingCount returns the number of findings.
func FindingCount(findings []Finding) int {
	return len(findings)
}
