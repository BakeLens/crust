//go:build darwin

package registry

import (
	"context"
	"fmt"
	"os"
	"os/exec"
)

func init() {
	// ── Claude Desktop / Cowork (macOS) ─────────────────────────────────────
	// Claude Desktop (and Cowork) is an Electron app that makes API calls
	// directly to api.anthropic.com. Unlike Claude Code, it has no proxy
	// config file. On macOS, Electron apps respect HTTPS_PROXY if set via
	// launchctl setenv (applies to all GUI apps launched by launchd).
	//
	// Patch: set HTTPS_PROXY to Crust's proxy URL via launchctl.
	// Restore: unset HTTPS_PROXY via launchctl.
	//
	// The user must relaunch Claude Desktop after patching for the env var
	// to take effect (launchctl setenv applies to newly launched processes).
	Register(&FuncTarget{
		AgentName: "Claude Desktop (proxy)",
		InstalledFunc: func() bool {
			_, err := os.Stat("/Applications/Claude.app")
			return err == nil
		},
		PatchFunc: func(proxyPort int, _ string) error {
			proxyURL := fmt.Sprintf("http://localhost:%d", proxyPort)
			if err := launchctlSetenv("HTTPS_PROXY", proxyURL); err != nil {
				return fmt.Errorf("set HTTPS_PROXY for Claude Desktop: %w", err)
			}
			if err := launchctlSetenv("HTTP_PROXY", proxyURL); err != nil {
				return fmt.Errorf("set HTTP_PROXY for Claude Desktop: %w", err)
			}
			return nil
		},
		RestoreFunc: func() error {
			// Best-effort: unset both. Errors are non-fatal (var may not be set).
			if err := launchctlUnsetenv("HTTPS_PROXY"); err != nil {
				log.Debug("unsetenv HTTPS_PROXY: %v", err)
			}
			if err := launchctlUnsetenv("HTTP_PROXY"); err != nil {
				log.Debug("unsetenv HTTP_PROXY: %v", err)
			}
			return nil
		},
	})
}

// launchctlSetenv sets an environment variable for all GUI apps via launchd.
func launchctlSetenv(key, value string) error {
	return exec.CommandContext(context.Background(), "launchctl", "setenv", key, value).Run()
}

// launchctlUnsetenv removes an environment variable from launchd.
func launchctlUnsetenv(key string) error {
	return exec.CommandContext(context.Background(), "launchctl", "unsetenv", key).Run()
}
