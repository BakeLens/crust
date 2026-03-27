//go:build notui

package startup

// RunManualSetup prompts for endpoint URL and API key (plain text, no TUI).
func RunManualSetup(defaultEndpoint string) (Config, error) {
	return runManualReader(defaultEndpoint)
}
