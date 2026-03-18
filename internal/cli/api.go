package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/BakeLens/crust/internal/config"
	"github.com/BakeLens/crust/internal/daemon"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/tui/dashboard"
)

// APIClient provides API access for CLI commands.
type APIClient struct {
	Cfg    *config.Config
	Client *http.Client // uses Unix socket / named pipe transport (or TCP for remote)
	Remote string       // non-empty when connecting to a remote daemon
}

// NewAPIClient creates a CLI API client.
// If remoteAddr is empty, connects via local Unix socket / named pipe.
// If remoteAddr is set (e.g., "localhost:9090"), connects over TCP.
func NewAPIClient(remoteAddr ...string) *APIClient {
	cfg, err := config.Load(config.DefaultConfigPath())
	if err != nil {
		cfg = config.DefaultConfig()
	}
	if len(remoteAddr) > 0 && remoteAddr[0] != "" {
		return &APIClient{
			Cfg:    cfg,
			Client: &http.Client{},
			Remote: remoteAddr[0],
		}
	}
	socketPath := cfg.API.SocketPath
	if socketPath == "" {
		socketPath = daemon.SocketFile(cfg.Server.Port)
	}
	return &APIClient{
		Cfg:    cfg,
		Client: &http.Client{Transport: security.APITransport(socketPath)},
	}
}

// APIURL returns the base URL for the management API.
// For local: dummy host routed via socket/pipe.
// For remote: TCP address of the daemon.
func (c *APIClient) APIURL() string {
	if c.Remote != "" {
		return "http://" + c.Remote
	}
	return dashboard.DefaultAPIBase
}

// ProxyBaseURL returns the proxy base URL.
func (c *APIClient) ProxyBaseURL() string {
	if c.Remote != "" {
		return "http://" + c.Remote
	}
	return fmt.Sprintf("http://localhost:%d", c.Cfg.Server.Port)
}

// CheckHealth checks if the proxy server is healthy (still uses TCP for the proxy).
func (c *APIClient) CheckHealth() (bool, error) {
	url := c.ProxyBaseURL() + "/health"
	resp, err := http.Get(url) //nolint:gosec,noctx // URL is from trusted config
	if err != nil || resp == nil {
		return false, err
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK, nil
}

// IsServerRunning checks if the Crust management API is reachable.
func (c *APIClient) IsServerRunning() bool {
	url := c.APIURL() + "/api/crust/rules/reload"
	resp, err := c.Client.Post(url, "application/json", nil) //nolint:noctx
	if err != nil || resp == nil {
		return false
	}
	defer resp.Body.Close()
	return true
}

// ReloadRules triggers a hot reload of rules.
func (c *APIClient) ReloadRules() ([]byte, error) {
	url := c.APIURL() + "/api/crust/rules/reload"
	resp, err := c.Client.Post(url, "application/json", nil) //nolint:noctx
	if err != nil || resp == nil {
		return nil, errors.New("server not running")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// GetRules fetches all rules from the server.
func (c *APIClient) GetRules() ([]byte, error) {
	url := c.APIURL() + "/api/crust/rules"
	resp, err := c.Client.Get(url) //nolint:noctx
	if err != nil || resp == nil {
		return nil, errors.New("server not running")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// GetAgents fetches detected agents from the daemon.
func (c *APIClient) GetAgents() ([]byte, error) {
	url := c.APIURL() + "/api/security/agents"
	resp, err := c.Client.Get(url) //nolint:noctx
	if err != nil || resp == nil {
		return nil, errors.New("server not running")
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// RulesResponse represents the API response for rules listing.
type RulesResponse struct {
	Rules []rules.Rule `json:"rules"`
	Total int          `json:"total"`
}

// GetRulesParsed fetches and parses rules from the server.
func (c *APIClient) GetRulesParsed() (*RulesResponse, error) {
	body, err := c.GetRules()
	if err != nil {
		return nil, err
	}

	var rulesResp RulesResponse
	if err := json.Unmarshal(body, &rulesResp); err != nil {
		return nil, err
	}
	return &rulesResp, nil
}
