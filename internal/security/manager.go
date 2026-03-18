//go:build !libcrust

package security

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/plugin"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// Manager manages the security and telemetry module components
type Manager struct {
	storage       telemetry.Recorder
	interceptor   *Interceptor
	registry      *plugin.Registry
	apiServer     *APIServer
	retentionDays int

	// Streaming buffering settings
	bufferStreaming bool
	maxBufferEvents int
	bufferTimeout   int
	blockMode       types.BlockMode

	apiHTTPServer *http.Server
	apiListener   net.Listener
	socketPath    string // Unix socket path or Windows pipe name (for cleanup)
	stopChan      chan struct{}
	stopOnce      sync.Once
	wg            sync.WaitGroup
}

// globalManager and globalManagerMu are in manager_common.go

// Config holds manager configuration
type Config struct {
	DBPath          string
	DBKey           string // Encryption key for SQLCipher
	SocketPath      string // Unix socket path or Windows pipe identifier
	SecurityEnabled bool
	RetentionDays   int // Data retention in days, 0 = forever
	// Streaming buffering settings
	BufferStreaming bool            // Enable response buffering for streaming requests
	MaxBufferEvents int             // Maximum SSE events to buffer
	BufferTimeout   int             // Buffer timeout in seconds
	BlockMode       types.BlockMode // types.BlockModeRemove (default) or types.BlockModeReplace
}

// Init initializes the manager
func Init(cfg Config) (*Manager, error) {
	// Initialize storage (with optional encryption)
	storage, err := telemetry.NewStorage(cfg.DBPath, cfg.DBKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}

	// Set global storage for telemetry
	telemetry.SetGlobalStorage(storage)

	// Seed in-memory metrics from persisted events (last 24h) so stats
	// survive daemon restarts.
	seedCtx, seedCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer seedCancel()
	if counts, err := storage.GetLayerCounts(seedCtx); err == nil {
		m := eventlog.GetMetrics()
		for _, lc := range counts {
			m.Seed(lc.Layer, lc.Blocked, lc.Count)
		}
	}

	// Default block mode to "remove" if not specified
	blockMode := cfg.BlockMode
	if blockMode == types.BlockModeUnset {
		blockMode = types.BlockModeRemove
	}

	m := &Manager{
		storage:         storage,
		retentionDays:   cfg.RetentionDays,
		bufferStreaming: cfg.BufferStreaming,
		maxBufferEvents: cfg.MaxBufferEvents,
		bufferTimeout:   cfg.BufferTimeout,
		blockMode:       blockMode,
		stopChan:        make(chan struct{}),
	}

	// Run initial cleanup
	if cfg.RetentionDays > 0 {
		if deleted, err := storage.CleanupOldData(context.Background(), cfg.RetentionDays); err != nil {
			log.Warn("Initial cleanup failed: %v", err)
		} else if deleted > 0 {
			log.Info("Initial cleanup: removed %d old records", deleted)
		}
	}

	// Initialize plugin registry and sandbox plugin.
	pool := plugin.NewPool(0, 0)
	m.registry = plugin.NewRegistry(pool)
	if sp, err := plugin.NewSandboxPlugin(); err == nil {
		if regErr := m.registry.Register(sp, nil); regErr != nil {
			log.Warn("sandbox plugin registration failed: %v", regErr)
		} else {
			log.Info("sandbox plugin registered (binary: %s)", sp.BinaryPath())
		}
	} else {
		log.Info("sandbox plugin not available: %v", err)
	}

	// Initialize interceptor if security is enabled and rules engine exists
	if cfg.SecurityEnabled {
		ruleEngine := rules.GetGlobalEngine()
		if ruleEngine != nil {
			m.interceptor = NewInterceptor(ruleEngine, storage)
		}
	}

	// Initialize API server with Unix domain socket (or named pipe on Windows)
	m.apiServer = NewAPIServer(storage, m.interceptor)
	m.socketPath = cfg.SocketPath

	ln, err := apiListener(cfg.SocketPath)
	if err != nil {
		storage.Close()
		return nil, fmt.Errorf("failed to create API listener: %w", err)
	}
	m.apiListener = ln
	m.apiHTTPServer = &http.Server{
		Handler:           m.apiServer.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	m.wg.Go(func() {
		if err := m.apiHTTPServer.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Error("API server error: %v", err)
		}
	})

	// Start periodic cleanup if retention is enabled
	if cfg.RetentionDays > 0 {
		m.wg.Go(m.cleanupLoop)
	}

	globalManagerMu.Lock()
	globalManager = m
	globalManagerMu.Unlock()

	// Register storage sink for event recording after global manager is set.
	initEventSink()

	return m, nil
}

// cleanupLoop runs periodic data cleanup
func (m *Manager) cleanupLoop() {
	// Run cleanup every hour
	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-m.stopChan:
			return
		case <-ticker.C:
			if m.retentionDays > 0 {
				cleanCtx, cleanCancel := context.WithTimeout(context.Background(), 30*time.Second)
				if _, err := m.storage.CleanupOldData(cleanCtx, m.retentionDays); err != nil {
					log.Warn("Periodic cleanup failed: %v", err)
				}
				cleanCancel()
			}
		}
	}
}

// Shutdown shuts down the manager
func (m *Manager) Shutdown(ctx context.Context) error {
	if m == nil {
		return nil
	}

	m.stopOnce.Do(func() { close(m.stopChan) })

	if m.apiHTTPServer != nil {
		if err := m.apiHTTPServer.Shutdown(ctx); err != nil {
			log.Error("API server shutdown error: %v", err)
		}
	}

	// Clean up socket file (no-op for Windows named pipes)
	if m.socketPath != "" {
		cleanupSocket(m.socketPath)
	}

	m.wg.Wait()

	if m.registry != nil {
		if err := m.registry.Close(); err != nil {
			log.Error("Plugin registry close error: %v", err)
		}
	}

	if m.storage != nil {
		if err := m.storage.Close(); err != nil {
			log.Error("Storage close error: %v", err)
		}
	}

	return nil
}

// APIHandler returns the management API HTTP handler.
// Mounted on the proxy server when --listen-address is non-loopback (Docker mode).
func (m *Manager) APIHandler() http.Handler {
	if m == nil || m.apiServer == nil {
		return http.NotFoundHandler()
	}
	return m.apiServer.Handler()
}

// GetInterceptor returns the interceptor
func (m *Manager) GetInterceptor() *Interceptor {
	if m == nil {
		return nil
	}
	return m.interceptor
}

// GetRegistry returns the plugin registry
func (m *Manager) GetRegistry() *plugin.Registry {
	if m == nil {
		return nil
	}
	return m.registry
}

// GetStorage returns the storage recorder
func (m *Manager) GetStorage() telemetry.Recorder {
	if m == nil {
		return nil
	}
	return m.storage
}

// GetGlobalManager returns the global manager
func GetGlobalManager() *Manager {
	globalManagerMu.RLock()
	defer globalManagerMu.RUnlock()
	return globalManager
}

// NewManagerForTest creates a lightweight manager with an interceptor only.
// No API server, no cleanup goroutines. Intended for unit tests.
func NewManagerForTest(interceptor *Interceptor) *Manager {
	return &Manager{
		interceptor: interceptor,
		blockMode:   types.BlockModeRemove,
		stopChan:    make(chan struct{}),
	}
}

// GetInterceptionConfig returns the security interception configuration.
func GetInterceptionConfig() InterceptionConfig {
	globalManagerMu.RLock()
	m := globalManager
	globalManagerMu.RUnlock()
	if m == nil {
		return InterceptionConfig{BlockMode: types.BlockModeRemove}
	}
	return InterceptionConfig{
		BufferStreaming: m.bufferStreaming,
		MaxBufferEvents: m.maxBufferEvents,
		BufferTimeout:   m.bufferTimeout,
		BlockMode:       m.blockMode,
	}
}
