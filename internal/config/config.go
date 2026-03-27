package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/BakeLens/crust/internal/fileutil"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/types"
	"gopkg.in/yaml.v3"
)

var cfgLog = logger.New("config")

// Config represents the crust configuration
type Config struct {
	Server    ServerConfig    `yaml:"server"`
	Upstream  UpstreamConfig  `yaml:"upstream"`
	Storage   StorageConfig   `yaml:"storage"`
	API       APIConfig       `yaml:"api"`
	Telemetry TelemetryConfig `yaml:"telemetry"`
	Security  SecurityConfig  `yaml:"security"`
	Rules     RulesConfig     `yaml:"rules"`
	// ProviderEnvKeys holds env var names referenced in provider api_key fields
	// (e.g., "OPENAI_API_KEY" from "$OPENAI_API_KEY"). Used by the daemon
	// to propagate these env vars to the child process.
	ProviderEnvKeys []string `yaml:"-"`
}

// APIConfig holds management API settings
type APIConfig struct {
	// SocketPath is the Unix domain socket path (or named pipe identifier on Windows).
	// Auto-derived from proxy port if empty: ~/.crust/crust-api-{proxyPort}.sock
	SocketPath string `yaml:"socket_path"`
}

// ServerConfig holds server settings
type ServerConfig struct {
	Port     int            `yaml:"port"`
	LogLevel types.LogLevel `yaml:"log_level"`
	NoColor  bool           `yaml:"no_color"`
}

// ProviderConfig holds per-provider settings.
// Supports both short form (just a URL string) and expanded form (url + api_key).
type ProviderConfig struct {
	URL    string `yaml:"url"`
	APIKey string `yaml:"api_key"`
}

// UnmarshalYAML allows ProviderConfig to be specified as either a plain string
// (short form: just the URL) or a mapping with url and api_key fields.
func (p *ProviderConfig) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		p.URL = value.Value
		return nil
	}
	// Decode as struct (expanded form)
	type plain ProviderConfig // avoid recursion
	return value.Decode((*plain)(p))
}

// MarshalYAML redacts the API key to prevent accidental credential exposure
// when the config is serialized (e.g., debug dumps, error reports).
func (p *ProviderConfig) MarshalYAML() (any, error) {
	if p.APIKey != "" {
		return map[string]string{"url": p.URL, "api_key": "***"}, nil
	}
	return p.URL, nil
}

// MarshalJSON redacts the API key in JSON serialization.
func (p *ProviderConfig) MarshalJSON() ([]byte, error) {
	if p.APIKey != "" {
		return json.Marshal(struct {
			URL    string `json:"url"`
			APIKey string `json:"api_key"`
		}{URL: p.URL, APIKey: "***"})
	}
	return json.Marshal(p.URL)
}

// String returns a redacted string representation, safe for logging.
func (p *ProviderConfig) String() string {
	if p.APIKey != "" {
		return fmt.Sprintf("{URL: %s, APIKey: ***}", p.URL)
	}
	return p.URL
}

// UpstreamConfig holds upstream (downstream target) settings
type UpstreamConfig struct {
	// URL is the target to forward requests to (e.g., router or provider)
	URL string `yaml:"url"`
	// Timeout in seconds for upstream requests
	Timeout int `yaml:"timeout"`
	// APIKey for upstream authentication (set at runtime, not from config file)
	APIKey string `yaml:"-"`
	// Providers maps user-defined model keywords to provider configs.
	// Short form: "my-llama": "http://localhost:11434/v1"
	// Expanded form: "openai": {url: "https://api.openai.com", api_key: "$OPENAI_API_KEY"}
	Providers map[string]ProviderConfig `yaml:"providers"`
}

// StorageConfig holds unified database settings
type StorageConfig struct {
	DBPath        string `yaml:"db_path"`
	EncryptionKey string `yaml:"encryption_key"` // SQLCipher encryption key (empty = no encryption)
}

// TelemetryConfig holds telemetry settings
type TelemetryConfig struct {
	Enabled       bool    `yaml:"enabled"`
	RetentionDays int     `yaml:"retention_days"` // Data retention in days, 0 = forever
	ServiceName   string  `yaml:"service_name"`
	SampleRate    float64 `yaml:"sample_rate"`
}

// SecurityConfig holds security module settings
type SecurityConfig struct {
	Enabled         bool            `yaml:"enabled"`           // enable security interception (uses rules engine)
	BufferStreaming bool            `yaml:"buffer_streaming"`  // enable response buffering for streaming requests
	MaxBufferEvents int             `yaml:"max_buffer_events"` // maximum SSE events to buffer before non-streaming retry (default: 50000; covers ~64K-token responses)
	BufferTimeout   int             `yaml:"buffer_timeout"`    // buffer timeout in seconds (default: 120)
	BlockMode       types.BlockMode `yaml:"block_mode"`        // "remove" (default) or "replace" (substitute with a text warning block)
}

// Validate validates the SecurityConfig and sets defaults for nil fields.
func (c *SecurityConfig) Validate() error {
	// Validate and default BlockMode
	if c.BlockMode == types.BlockModeUnset {
		c.BlockMode = types.BlockModeRemove
	} else if !c.BlockMode.Valid() {
		return fmt.Errorf("invalid block_mode %q: must be 'remove' or 'replace'", c.BlockMode)
	}

	// Warn when security is enabled but streaming bypass is active
	if c.Enabled && !c.BufferStreaming {
		cfgLog.Warn("buffer_streaming is disabled: streaming responses will bypass security interception")
	}

	// Validate buffer settings when buffering is enabled
	if c.BufferStreaming {
		if c.MaxBufferEvents <= 0 {
			return fmt.Errorf("max_buffer_events must be positive when buffer_streaming is enabled, got %d", c.MaxBufferEvents)
		}
		if c.BufferTimeout <= 0 {
			return fmt.Errorf("buffer_timeout must be positive when buffer_streaming is enabled, got %d", c.BufferTimeout)
		}
	}

	return nil
}

// RulesConfig holds rule engine settings
type RulesConfig struct {
	Enabled        bool   `yaml:"enabled"`
	UserDir        string `yaml:"user_dir"`        // directory for user rules (default: ~/.crust/rules.d)
	DisableBuiltin bool   `yaml:"disable_builtin"` // disable embedded builtin rules (locked rules remain active)
	Watch          bool   `yaml:"watch"`           // enable file watching for hot reload
}

// DefaultConfigPath returns the default config file path (~/.crust/config.yaml).
func DefaultConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "config.yaml"
	}
	return filepath.Join(home, ".crust", "config.yaml")
}

// defaultDBPath returns the default database path under ~/.crust/.
func defaultDBPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return "./crust.db"
	}
	return filepath.Join(home, ".crust", "crust.db")
}

// DefaultConfig returns the default configuration
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:     9090,
			LogLevel: types.LogLevelInfo,
			NoColor:  false,
		},
		Upstream: UpstreamConfig{
			URL:     "https://openrouter.ai/api",
			Timeout: 300,
		},
		Storage: StorageConfig{
			DBPath: defaultDBPath(),
		},
		API: APIConfig{},
		Telemetry: TelemetryConfig{
			Enabled:       false, // disabled by default
			RetentionDays: 7,
			ServiceName:   "crust",
			SampleRate:    1.0,
		},
		Security: SecurityConfig{
			Enabled:         true,
			BufferStreaming: true, // enabled by default for security
			MaxBufferEvents: 50000,
			BufferTimeout:   120,
			BlockMode:       types.BlockModeRemove,
		},
		Rules: RulesConfig{
			Enabled:        true,
			UserDir:        "", // empty means use default ~/.crust/rules.d
			DisableBuiltin: false,
			Watch:          true,
		},
	}
}

// Validate checks all Config fields and returns a multi-error report.
// Call this AFTER CLI overrides have been applied, not during Load().
func (c *Config) Validate() error {
	var errs []string

	// Port ranges
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		errs = append(errs, fmt.Sprintf("server.port: must be 1-65535 (got %d)", c.Server.Port))
	}

	// Log level
	if !c.Server.LogLevel.Valid() {
		errs = append(errs, fmt.Sprintf("server.log_level: unknown log level %q (valid: trace, debug, info, warn, error)", c.Server.LogLevel))
	}

	// Upstream URL (only validate format; empty is valid for --auto mode)
	if c.Upstream.URL != "" {
		if u, err := url.Parse(c.Upstream.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, fmt.Sprintf("upstream.url: must be a valid http/https URL (got %q)", c.Upstream.URL))
		}
	}

	// Upstream timeout (0 = no timeout, valid for long streaming)
	if c.Upstream.Timeout < 0 {
		errs = append(errs, fmt.Sprintf("upstream.timeout: must be >= 0 (got %d)", c.Upstream.Timeout))
	}

	// Provider URLs
	for name, prov := range c.Upstream.Providers {
		if prov.URL == "" {
			errs = append(errs, fmt.Sprintf("upstream.providers.%s: URL must not be empty", name))
		} else if u, err := url.Parse(prov.URL); err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			errs = append(errs, fmt.Sprintf("upstream.providers.%s: must be a valid http/https URL (got %q)", name, prov.URL))
		}
	}

	// Telemetry
	if c.Telemetry.RetentionDays < 0 || c.Telemetry.RetentionDays > 36500 {
		errs = append(errs, fmt.Sprintf("telemetry.retention_days: must be 0-36500 (got %d)", c.Telemetry.RetentionDays))
	}
	if c.Telemetry.SampleRate < 0 || c.Telemetry.SampleRate > 1 {
		errs = append(errs, fmt.Sprintf("telemetry.sample_rate: must be 0.0-1.0 (got %g)", c.Telemetry.SampleRate))
	}

	// Security (delegate)
	if err := c.Security.Validate(); err != nil {
		errs = append(errs, err.Error())
	}

	if len(errs) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("config validation failed:\n")
	for i, e := range errs {
		fmt.Fprintf(&sb, "  %d. %s\n", i+1, e)
	}
	return errors.New(sb.String())
}

// rawConfig mirrors Config but uses pointers for fields where zero is
// invalid so YAML can distinguish "absent" (nil → use default) from
// "explicitly set to 0" (non-nil → copy, let Validate() reject).
type rawConfig struct {
	Server struct {
		Port     *int           `yaml:"port"`
		LogLevel types.LogLevel `yaml:"log_level"`
		NoColor  bool           `yaml:"no_color"`
	} `yaml:"server"`
	Upstream  UpstreamConfig `yaml:"upstream"`
	Storage   StorageConfig  `yaml:"storage"`
	API       APIConfig      `yaml:"api"`
	Telemetry struct {
		Enabled       bool     `yaml:"enabled"`
		RetentionDays int      `yaml:"retention_days"`
		ServiceName   string   `yaml:"service_name"`
		SampleRate    *float64 `yaml:"sample_rate"`
	} `yaml:"telemetry"`
	Security struct {
		Enabled         bool            `yaml:"enabled"`
		BufferStreaming bool            `yaml:"buffer_streaming"`
		MaxBufferEvents *int            `yaml:"max_buffer_events"`
		BufferTimeout   *int            `yaml:"buffer_timeout"`
		BlockMode       types.BlockMode `yaml:"block_mode"`
	} `yaml:"security"`
	Rules RulesConfig `yaml:"rules"`
}

// applyTo merges parsed YAML onto defaults.
// nil = absent in YAML → keep default. non-nil = explicitly set → copy.
func (r *rawConfig) applyTo(dst *Config) {
	if r.Server.Port != nil {
		dst.Server.Port = *r.Server.Port
	}
	if r.Server.LogLevel != "" {
		dst.Server.LogLevel = r.Server.LogLevel
	}
	dst.Server.NoColor = r.Server.NoColor

	if r.Upstream.URL != "" {
		dst.Upstream.URL = r.Upstream.URL
	}
	dst.Upstream.Timeout = r.Upstream.Timeout
	if len(r.Upstream.Providers) > 0 {
		dst.Upstream.Providers = r.Upstream.Providers
	}

	if r.Storage.DBPath != "" {
		dst.Storage.DBPath = r.Storage.DBPath
	}
	if r.Storage.EncryptionKey != "" {
		dst.Storage.EncryptionKey = r.Storage.EncryptionKey
	}

	if r.API.SocketPath != "" {
		dst.API.SocketPath = r.API.SocketPath
	}

	dst.Telemetry.Enabled = r.Telemetry.Enabled
	dst.Telemetry.RetentionDays = r.Telemetry.RetentionDays
	if r.Telemetry.ServiceName != "" {
		dst.Telemetry.ServiceName = r.Telemetry.ServiceName
	}
	if r.Telemetry.SampleRate != nil {
		dst.Telemetry.SampleRate = *r.Telemetry.SampleRate
	}

	dst.Security.Enabled = r.Security.Enabled
	dst.Security.BufferStreaming = r.Security.BufferStreaming
	if r.Security.MaxBufferEvents != nil {
		dst.Security.MaxBufferEvents = *r.Security.MaxBufferEvents
	}
	if r.Security.BufferTimeout != nil {
		dst.Security.BufferTimeout = *r.Security.BufferTimeout
	}
	if r.Security.BlockMode != types.BlockModeUnset {
		dst.Security.BlockMode = r.Security.BlockMode
	}

	dst.Rules.Enabled = r.Rules.Enabled
	if r.Rules.UserDir != "" {
		dst.Rules.UserDir = r.Rules.UserDir
	}
	dst.Rules.DisableBuiltin = r.Rules.DisableBuiltin
	dst.Rules.Watch = r.Rules.Watch
}

// isUnknownFieldError returns true if the error is from yaml.Decoder.KnownFields(true)
// detecting an unrecognized key (e.g. typo like "servr:").
func isUnknownFieldError(err error) bool {
	return err != nil && strings.Contains(err.Error(), "not found in type")
}

// Load loads configuration from a YAML file.
// Note: Load does NOT call Validate(). Callers should apply CLI overrides
// first, then call cfg.Validate() themselves.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	data, err := fileutil.ReadFileWithLock(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	// Parse into rawConfig (pointer fields detect absent vs explicit zero).
	var raw rawConfig
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		if isUnknownFieldError(err) {
			cfgLog.Warn("config has unknown fields (ignored): %v", err)
			raw = rawConfig{}
			if err2 := yaml.Unmarshal(data, &raw); err2 != nil {
				return nil, fmt.Errorf("config parse error: %w", err2)
			}
		} else {
			return nil, fmt.Errorf("config parse error: %w", err)
		}
	}

	// Merge: nil → keep default, non-nil → copy (Validate catches bad values).
	raw.applyTo(cfg)

	// Expand environment variables in provider API keys.
	// Collect referenced env var names so the daemon can propagate them.
	for name, prov := range cfg.Upstream.Providers {
		if prov.APIKey != "" {
			raw := prov.APIKey
			// Collect env var names using the same parser as os.ExpandEnv
			os.Expand(raw, func(key string) string {
				cfg.ProviderEnvKeys = append(cfg.ProviderEnvKeys, key)
				return ""
			})
			prov.APIKey = os.ExpandEnv(prov.APIKey)
			if prov.APIKey == "" {
				cfgLog.Warn("upstream.providers.%s: api_key references unset env var %q (expanded to empty)", name, raw)
			}
			cfg.Upstream.Providers[name] = prov
		}
	}

	return cfg, nil
}
