package rules

import (
	"encoding/json"
	"path"
	"strings"

	"gopkg.in/yaml.v3"
)

// extractCommandsFromContent dispatches file content to type-specific parsers
// that extract embedded shell commands. Each parser returns shell command strings
// suitable for passing through extractBashCommand (the bash AST pipeline).
//
// Detection order:
//  1. Exact basename match (Dockerfile, Makefile, package.json, etc.)
//  2. Extension match (.sh, .bash, .zsh, .ksh, .dash → entire file is shell)
//  3. Path pattern (.github/workflows/*.yml → GitHub Actions parser)
//  4. nil for everything else (fast path — most Write/Edit calls)
func extractCommandsFromContent(filename, content string) []string {
	if filename == "" || content == "" {
		return nil
	}

	base := path.Base(filename)

	// 1. Exact basename match
	switch base {
	case "Dockerfile", "dockerfile", "Containerfile", "containerfile":
		return extractDockerfileCommands(content)
	case "Makefile", "makefile", "GNUmakefile":
		return extractMakefileCommands(content)
	case ".gitmodules":
		return extractGitmodulesCommands(content)
	case "package.json":
		return extractPackageJSONCommands(content)
	case ".gitlab-ci.yml", ".gitlab-ci.yaml":
		return extractGitLabCICommands(content)
	case "docker-compose.yml", "docker-compose.yaml",
		"compose.yml", "compose.yaml":
		return extractDockerComposeCommands(content)
	}

	// 2. Extension match — shell scripts without shebangs
	ext := strings.ToLower(path.Ext(filename))
	switch ext {
	case ".sh", ".bash", ".zsh", ".ksh", ".dash":
		return extractShellByExtension(content)
	}

	// 3. Path pattern — GitHub Actions workflows
	if isGitHubActionsPath(filename) {
		return extractGitHubActionsCommands(content)
	}

	// 4. Dockerfile.* variants (Dockerfile.prod, Dockerfile.dev, etc.)
	if strings.HasPrefix(base, "Dockerfile.") || strings.HasPrefix(base, "dockerfile.") ||
		strings.HasPrefix(base, "Containerfile.") || strings.HasPrefix(base, "containerfile.") {
		return extractDockerfileCommands(content)
	}

	return nil
}

// isGitHubActionsPath checks if a file path is a GitHub Actions workflow.
func isGitHubActionsPath(filename string) bool {
	// Normalize to forward slashes for consistent matching
	normalized := strings.ReplaceAll(filename, "\\", "/")
	if !strings.Contains(normalized, ".github/workflows/") {
		return false
	}
	ext := strings.ToLower(path.Ext(filename))
	return ext == ".yml" || ext == ".yaml"
}

// extractShellByExtension returns the entire content as a single command.
// Files with shell extensions (.sh, .bash, .zsh) are shell scripts by definition.
func extractShellByExtension(content string) []string {
	if strings.TrimSpace(content) == "" {
		return nil
	}
	return []string{content}
}

// extractGitHubActionsCommands parses GitHub Actions YAML and collects `run:` fields
// from all job steps.
func extractGitHubActionsCommands(content string) []string {
	// Structure: { jobs: { <name>: { steps: [ { run: "..." } ] } } }
	var workflow struct {
		Jobs map[string]struct {
			Steps []struct {
				Run string `yaml:"run"`
			} `yaml:"steps"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(content), &workflow); err != nil {
		return nil
	}

	var cmds []string
	for _, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if cmd := strings.TrimSpace(step.Run); cmd != "" {
				cmds = append(cmds, cmd)
			}
		}
	}
	return cmds
}

// extractDockerfileCommands parses Dockerfile instructions and extracts shell
// commands from RUN, CMD, and ENTRYPOINT directives (shell form only).
// Handles line continuations (backslash-newline).
func extractDockerfileCommands(content string) []string {
	// Join continuation lines first
	joined := strings.ReplaceAll(content, "\\\n", "")
	lines := strings.Split(joined, "\n")

	var cmds []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Skip comments and empty lines
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		upper := strings.ToUpper(trimmed)

		// RUN <command>
		if strings.HasPrefix(upper, "RUN ") {
			cmd := strings.TrimSpace(trimmed[4:])
			if cmd != "" && !strings.HasPrefix(cmd, "[") { // skip exec form ["cmd", "arg"]
				cmds = append(cmds, cmd)
			}
			continue
		}

		// CMD <command> (shell form only, not exec form)
		if strings.HasPrefix(upper, "CMD ") {
			cmd := strings.TrimSpace(trimmed[4:])
			if cmd != "" && !strings.HasPrefix(cmd, "[") {
				cmds = append(cmds, cmd)
			}
			continue
		}

		// ENTRYPOINT <command> (shell form only)
		if strings.HasPrefix(upper, "ENTRYPOINT ") {
			cmd := strings.TrimSpace(trimmed[11:])
			if cmd != "" && !strings.HasPrefix(cmd, "[") {
				cmds = append(cmds, cmd)
			}
			continue
		}

		// HEALTHCHECK CMD <command> (shell form only)
		// Executes periodically — can be abused for persistence.
		if strings.HasPrefix(upper, "HEALTHCHECK ") {
			rest := strings.TrimSpace(trimmed[12:])
			restUpper := strings.ToUpper(rest)
			if strings.HasPrefix(restUpper, "CMD ") {
				cmd := strings.TrimSpace(rest[4:])
				if cmd != "" && !strings.HasPrefix(cmd, "[") {
					cmds = append(cmds, cmd)
				}
			}
			continue
		}
	}
	return cmds
}

// extractMakefileCommands collects tab-indented recipe lines from Makefiles.
// Strips leading @, -, and @- prefixes (silent/ignore-error modifiers).
func extractMakefileCommands(content string) []string {
	lines := strings.Split(content, "\n")
	var cmds []string
	for _, line := range lines {
		// Recipe lines start with a tab character
		if !strings.HasPrefix(line, "\t") {
			continue
		}
		cmd := strings.TrimPrefix(line, "\t")
		// Strip make-specific prefixes: @(silent), -(ignore-error), @-, -@
		cmd = strings.TrimLeft(cmd, "@-")
		cmd = strings.TrimSpace(cmd)
		if cmd != "" {
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

// extractPackageJSONCommands parses package.json and collects all script values.
func extractPackageJSONCommands(content string) []string {
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
	}
	if err := json.Unmarshal([]byte(content), &pkg); err != nil {
		return nil
	}

	var cmds []string
	for _, cmd := range pkg.Scripts {
		if cmd = strings.TrimSpace(cmd); cmd != "" {
			cmds = append(cmds, cmd)
		}
	}
	return cmds
}

// extractGitmodulesCommands parses .gitmodules for `update = !<command>` entries.
// Git executes the command after the `!` when `git submodule update` runs.
func extractGitmodulesCommands(content string) []string {
	lines := strings.Split(content, "\n")
	var cmds []string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Look for: update = !<command>
		if !strings.HasPrefix(trimmed, "update") {
			continue
		}
		// Split on '=' and check for '!' prefix
		_, val, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		val = strings.TrimSpace(val)
		if strings.HasPrefix(val, "!") {
			cmd := strings.TrimSpace(val[1:])
			if cmd != "" {
				cmds = append(cmds, cmd)
			}
		}
	}
	return cmds
}

// extractGitLabCICommands parses .gitlab-ci.yml and collects commands from
// script, before_script, and after_script fields across all jobs.
func extractGitLabCICommands(content string) []string {
	// GitLab CI structure: top-level keys are job names (except reserved keywords).
	// Each job can have script/before_script/after_script as string or []string.
	var doc map[string]any
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil
	}

	var cmds []string
	scriptFields := []string{"script", "before_script", "after_script"}

	for _, jobVal := range doc {
		job, ok := jobVal.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range scriptFields {
			cmds = append(cmds, yamlStringOrSlice(job[field])...)
		}
	}
	return cmds
}

// extractDockerComposeCommands parses docker-compose.yml and collects commands
// from services.*.command and services.*.entrypoint fields.
func extractDockerComposeCommands(content string) []string {
	var compose struct {
		Services map[string]struct {
			Command    any `yaml:"command"`
			Entrypoint any `yaml:"entrypoint"`
		} `yaml:"services"`
	}
	if err := yaml.Unmarshal([]byte(content), &compose); err != nil {
		return nil
	}

	var cmds []string
	for _, svc := range compose.Services {
		cmds = append(cmds, yamlStringOrSlice(svc.Command)...)
		cmds = append(cmds, yamlStringOrSlice(svc.Entrypoint)...)
	}
	return cmds
}

// yamlStringOrSlice extracts command strings from a YAML value that can be
// either a single string or a list of strings.
func yamlStringOrSlice(val any) []string {
	if val == nil {
		return nil
	}
	switch v := val.(type) {
	case string:
		if cmd := strings.TrimSpace(v); cmd != "" {
			return []string{cmd}
		}
	case []any:
		var result []string
		for _, item := range v {
			if s, ok := item.(string); ok {
				if cmd := strings.TrimSpace(s); cmd != "" {
					result = append(result, cmd)
				}
			}
		}
		return result
	}
	return nil
}
