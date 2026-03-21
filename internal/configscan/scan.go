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
	return findings
}

// ScanDirOnly scans a single directory without walking parents.
func ScanDirOnly(dir string) []Finding {
	var findings []Finding
	findings = append(findings, scanEnvFilesInDir(dir)...)
	findings = append(findings, scanClaudeSettingsInDir(dir)...)
	return findings
}

// scanEnvFiles scans .env files in the given directory and parent dirs.
func scanEnvFiles(dir string) []Finding {
	var findings []Finding
	home, err := os.UserHomeDir()
	if err != nil {
		// Can't determine home — only scan the given directory to avoid
		// walking up to filesystem root.
		return scanEnvFilesInDir(dir)
	}

	for {
		findings = append(findings, scanEnvFilesInDir(dir)...)

		parent := filepath.Dir(dir)
		if parent == dir {
			break // reached root
		}
		if dir == home {
			break // don't go above home
		}
		dir = parent
	}
	return findings
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
	var findings []Finding
	home, err := os.UserHomeDir()
	if err != nil {
		return scanClaudeSettingsInDir(dir)
	}

	for {
		findings = append(findings, scanClaudeSettingsInDir(dir)...)

		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		if dir == home {
			break
		}
		dir = parent
	}
	return findings
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

// isSuspiciousURL returns true if the URL doesn't point to a known safe domain.
func isSuspiciousURL(rawURL string) bool {
	// Strip protocol
	u := rawURL
	for _, prefix := range []string{"https://", "http://", "HTTP://", "HTTPS://"} {
		u = strings.TrimPrefix(u, prefix)
	}

	// Extract host (before first / or :)
	host := u
	if i := strings.IndexAny(host, "/:"); i >= 0 {
		host = host[:i]
	}
	host = strings.ToLower(host)

	return !knownSafeDomains[host]
}

// FindingCount returns the number of findings.
func FindingCount(findings []Finding) int {
	return len(findings)
}
