package startup

import (
	"bufio"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/BakeLens/crust/internal/tui"
)

// Config holds the configuration collected from startup.
type Config struct {
	// Mode
	AutoMode bool // auto mode: resolve provider from model name (per-provider keys or client auth)
	// Basic
	EndpointURL   string
	APIKey        string
	EncryptionKey string
	// Advanced - Telemetry
	TelemetryEnabled bool
	RetentionDays    int
	// Advanced - Rules
	DisableBuiltinRules bool
	// Advanced - Ports
	ProxyPort int
	// State
	Canceled bool
}

// Validate validates the startup configuration.
func (c *Config) Validate() error {
	if !c.AutoMode {
		if c.EndpointURL == "" {
			return errors.New("endpoint URL is required")
		}
		if _, err := url.Parse(c.EndpointURL); err != nil {
			return fmt.Errorf("invalid endpoint URL: %w", err)
		}
		if c.APIKey == "" {
			return errors.New("API key is required")
		}
	}
	if c.EncryptionKey != "" && len(c.EncryptionKey) < 16 {
		return errors.New("encryption key must be at least 16 characters")
	}
	if c.ProxyPort < 1 || c.ProxyPort > 65535 {
		return errors.New("proxy port must be between 1 and 65535")
	}
	if c.RetentionDays < 0 || c.RetentionDays > 36500 {
		return errors.New("retention days must be between 0 and 36500")
	}
	return nil
}

// ValidationErrors returns human-readable validation errors.
func (c *Config) ValidationErrors() []string {
	err := c.Validate()
	if err == nil {
		return nil
	}
	return []string{err.Error()}
}

// readPassword reads a password from the terminal without echoing.
func readPassword() (string, error) {
	fd := int(os.Stdin.Fd()) //nolint:gosec // Fd() fits in int on all supported platforms
	if term.IsTerminal(fd) {
		password, err := term.ReadPassword(fd)
		if err != nil {
			return "", err
		}
		return string(password), nil
	}

	// Fallback for non-terminal (piped input)
	reader := bufio.NewReader(os.Stdin)
	password, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(password), nil
}

// runManualReader prompts for endpoint URL and API key using plain text.
// Used as fallback when plain mode is active (piped, NO_COLOR, etc.)
// and as the sole implementation in notui builds.
func runManualReader(defaultEndpoint string) (Config, error) {
	reader := bufio.NewReader(os.Stdin)
	var config Config

	fmt.Println(tui.Separator("Manual Endpoint"))
	fmt.Println()

	prompt := ">"
	fmt.Printf("  %s Endpoint URL [%s]: ", prompt, defaultEndpoint)
	endpoint, err := reader.ReadString('\n')
	if err != nil {
		return config, fmt.Errorf("failed to read endpoint: %w", err)
	}
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		endpoint = defaultEndpoint
	}
	config.EndpointURL = endpoint

	fmt.Printf("  %s API Key: ", prompt)
	apiKey, err := readPassword()
	if err != nil {
		return config, fmt.Errorf("failed to read API key: %w", err)
	}
	config.APIKey = apiKey
	fmt.Println()

	fmt.Println()
	tui.PrintInfo("Manual mode — " + config.EndpointURL)

	return config, nil
}
