//go:build !libcrust

package daemon

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BakeLens/crust/internal/config"
	"github.com/BakeLens/crust/internal/httpproxy"
	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/selfprotect"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// ServerConfig holds the parameters needed to start the daemon server.
// These are derived from CLI flags and config file values in main.go,
// then passed to RunServer for execution.
type ServerConfig struct {
	Cfg              *config.Config
	LogLevel         string
	DisableBuiltin   bool
	Endpoint         string
	APIKey           string
	DBKey            string
	ProxyPort        int
	ListenAddr       string
	TelemetryEnabled bool
	RetentionDays    int
	BlockMode        string
	AutoMode         bool
}

// RunServer runs the daemon server. It blocks until a shutdown signal is
// received or a fatal error occurs. It returns an error string and exit code;
// the caller (main.go) is responsible for os.Exit.
func RunServer(scfg ServerConfig) error {
	cfg := scfg.Cfg

	// Write PID file
	if err := WritePID(); err != nil {
		return fmt.Errorf("failed to write PID file: %w", err)
	}
	defer CleanupPID()

	// Configure logger
	if scfg.LogLevel != "" {
		logger.SetGlobalLevelFromString(scfg.LogLevel)
	} else {
		logger.SetGlobalLevelFromString(string(cfg.Server.LogLevel))
	}

	// Apply command-line overrides
	if scfg.Endpoint != "" {
		cfg.Upstream.URL = scfg.Endpoint
	}
	if scfg.APIKey != "" {
		cfg.Upstream.APIKey = scfg.APIKey
	}
	if scfg.DBKey != "" {
		cfg.Storage.EncryptionKey = scfg.DBKey
	}
	if scfg.DisableBuiltin {
		cfg.Rules.DisableBuiltin = true
	}
	if scfg.ProxyPort > 0 {
		cfg.Server.Port = scfg.ProxyPort
	}
	if scfg.TelemetryEnabled {
		cfg.Telemetry.Enabled = true
	}
	if scfg.RetentionDays > 0 {
		cfg.Telemetry.RetentionDays = scfg.RetentionDays
	}
	if scfg.BlockMode != "" {
		parsed, err := types.ParseBlockMode(scfg.BlockMode)
		if err != nil {
			return fmt.Errorf("invalid --block-mode %q: must be 'remove' or 'replace'", scfg.BlockMode)
		}
		cfg.Security.BlockMode = parsed
	}

	// Validate config AFTER all CLI overrides have been applied
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("configuration error:\n%w", err)
	}

	// Write port file so `crust wrap` can discover the proxy port
	if err := WritePort(cfg.Server.Port); err != nil {
		return fmt.Errorf("failed to write port file: %w", err)
	}

	// Patch known agent configs to point at the proxy (restored on shutdown).
	PatchAgentConfigs(cfg.Server.Port)
	defer RestoreAgentConfigs()

	log.Info("Starting Crust daemon...")

	// engineCtx controls the lifetime of worker subprocesses (shell, pwsh).
	engineCtx, engineCancel := context.WithCancel(context.Background())
	defer engineCancel()

	// Initialize rules engine
	var ruleWatcher *rules.Watcher
	rulesDir := cfg.Rules.UserDir
	if rulesDir == "" {
		rulesDir = rules.DefaultUserRulesDir()
	}

	var ruleEngine *rules.Engine
	if cfg.Rules.Enabled {
		engineCfg := rules.EngineConfig{
			UserRulesDir:        rulesDir,
			DisableBuiltin:      cfg.Rules.DisableBuiltin,
			SubprocessIsolation: true,
			PreChecker:          selfprotect.Check,
		}

		var err error
		ruleEngine, err = rules.NewEngine(engineCtx, engineCfg)
		if err != nil {
			return fmt.Errorf("failed to initialize rules engine: %w", err)
		}

		rules.SetGlobalEngine(ruleEngine) // TODO: remove once libcrust is refactored
		log.Info("Rules engine: %d rules loaded", ruleEngine.RuleCount())

		if cfg.Rules.Watch {
			ruleWatcher, err = rules.NewWatcher(ruleEngine)
			if err != nil {
				log.Warn("Failed to create rule watcher: %v", err)
			} else {
				if err := ruleWatcher.Start(); err != nil {
					log.Warn("Failed to start rule watcher: %v", err)
				}
			}
		}
	}

	// Derive socket path for management API
	socketPath := cfg.API.SocketPath
	if socketPath == "" {
		socketPath = SocketFile(cfg.Server.Port)
	}

	// Initialize manager
	managerCfg := security.Config{
		DBPath:          cfg.Storage.DBPath,
		DBKey:           cfg.Storage.EncryptionKey,
		SocketPath:      socketPath,
		SecurityEnabled: cfg.Security.Enabled,
		RetentionDays:   cfg.Telemetry.RetentionDays,
		BufferStreaming: cfg.Security.BufferStreaming,
		MaxBufferEvents: cfg.Security.MaxBufferEvents,
		BufferTimeout:   cfg.Security.BufferTimeout,
		BlockMode:       cfg.Security.BlockMode,
		Engine:          ruleEngine,
	}

	manager, err := security.Init(managerCfg)
	if err != nil {
		return fmt.Errorf("failed to initialize manager: %w", err)
	}
	defer func() {
		if ruleWatcher != nil {
			_ = ruleWatcher.Stop()
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = manager.Shutdown(ctx)
	}()

	// Initialize telemetry
	if cfg.Telemetry.Enabled {
		telemetryCfg := telemetry.Config{
			Enabled:     cfg.Telemetry.Enabled,
			ServiceName: cfg.Telemetry.ServiceName,
			SampleRate:  cfg.Telemetry.SampleRate,
		}
		tp, err := telemetry.Init(context.Background(), telemetryCfg)
		if err != nil {
			return fmt.Errorf("failed to initialize telemetry: %w", err)
		}
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_ = tp.Shutdown(ctx)
		}()
	}

	// Create proxy
	proxyHandler, err := httpproxy.NewProxy(cfg.Upstream.URL, cfg.Upstream.APIKey, time.Duration(cfg.Upstream.Timeout)*time.Second, cfg.Upstream.Providers, scfg.AutoMode, manager.GetInterceptor(), manager.InterceptionCfg())
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}

	// Create HTTP server
	mux := http.NewServeMux()
	listenAddr := scfg.ListenAddr
	if listenAddr != "" && listenAddr != "127.0.0.1" && listenAddr != "localhost" {
		mgmtHandler := manager.APIHandler()
		for _, prefix := range security.APIPrefixes() {
			mux.Handle(prefix, mgmtHandler)
		}
	}
	mux.Handle("/", proxyHandler)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	bindAddr := "127.0.0.1"
	if listenAddr != "" {
		bindAddr = listenAddr
	}

	server := &http.Server{
		Addr:              fmt.Sprintf("%s:%d", bindAddr, cfg.Server.Port),
		Handler:           loggingMiddleware(mux),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       time.Duration(cfg.Upstream.Timeout) * time.Second,
		WriteTimeout:      0, // Must be 0 for SSE streaming
	}

	log.Info("Crust listening on %s:%d", bindAddr, cfg.Server.Port)
	if scfg.AutoMode {
		log.Info("  Mode: auto (provider resolved from model name)")
		if cfg.Upstream.URL != "" {
			log.Info("  Fallback upstream: %s", cfg.Upstream.URL)
		}
	} else {
		log.Info("  Upstream: %s", cfg.Upstream.URL)
	}
	log.Info("  API: %s", socketPath)

	// Register signal handler before starting the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	// Start server
	serverErr := make(chan error, 1)
	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr <- err
		}
	}()
	select {
	case <-quit:
	case err := <-serverErr:
		log.Error("Server error: %v", err)
	}

	log.Info("Shutting down...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Error("Server forced to shutdown: %v", err)
	}

	log.Info("Crust stopped")
	return nil
}

func loggingMiddleware(next http.Handler) http.Handler {
	httpLog := logger.New("http")
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		start := time.Now()
		next.ServeHTTP(w, r)
		httpLog.Debug("%s %s from %s (%v)", r.Method, r.URL.Path, r.RemoteAddr, time.Since(start))
	})
}
