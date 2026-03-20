package security

import (
	"context"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/plugin"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// Manager coordinates security components.
// Heavy dependencies (storage, API server, cleanup) are optional —
// injected via functional options so that lightweight builds (mobile/GUI)
// don't pull in SQLite or HTTP server code.
type Manager struct {
	interceptor *Interceptor
	registry    *plugin.Registry
	blockMode   types.BlockMode

	// Optional components — nil when running as library (mobile/GUI).
	storage       telemetry.Recorder
	apiHandler    http.Handler // abstracts *APIServer via standard http.Handler
	apiHTTPServer *http.Server
	apiListener   net.Listener
	socketPath    string
	retentionDays int

	// Streaming buffering settings
	bufferStreaming bool
	maxBufferEvents int
	bufferTimeout   int

	stopChan chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// Option configures optional Manager components.
type Option func(*Manager)

// WithStorage attaches telemetry storage and seeds in-memory metrics
// from persisted events (last 24h) so stats survive daemon restarts.
func WithStorage(storage telemetry.Recorder) Option {
	return func(m *Manager) {
		m.storage = storage
	}
}

// WithAPI attaches an HTTP API server on the given listener.
// The handler is typically an http.Handler from NewAPIServer().
func WithAPI(handler http.Handler, ln net.Listener, socketPath string) Option {
	return func(m *Manager) {
		m.apiHandler = handler
		m.apiListener = ln
		m.socketPath = socketPath
	}
}

// WithRetention enables periodic data cleanup.
func WithRetention(days int) Option {
	return func(m *Manager) {
		m.retentionDays = days
	}
}

// WithBuffering configures streaming response buffering.
func WithBuffering(streaming bool, maxEvents, timeoutSec int) Option {
	return func(m *Manager) {
		m.bufferStreaming = streaming
		m.maxBufferEvents = maxEvents
		m.bufferTimeout = timeoutSec
	}
}

// NewManager creates a Manager. By default it's lightweight (no storage,
// no API, no cleanup). Use options to add daemon-specific features.
func NewManager(interceptor *Interceptor, registry *plugin.Registry, blockMode types.BlockMode, opts ...Option) *Manager {
	if blockMode == types.BlockModeUnset {
		blockMode = types.BlockModeRemove
	}
	m := &Manager{
		interceptor: interceptor,
		registry:    registry,
		blockMode:   blockMode,
		stopChan:    make(chan struct{}),
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Start launches background goroutines (API server, cleanup loop).
// No-op if no optional components are configured.
func (m *Manager) Start() {
	if m.apiHandler != nil && m.apiListener != nil {
		m.apiHTTPServer = &http.Server{
			Handler:           m.apiHandler,
			ReadHeaderTimeout: 10 * time.Second,
		}
		m.wg.Go(func() {
			if err := m.apiHTTPServer.Serve(m.apiListener); err != nil && err != http.ErrServerClosed {
				log.Error("API server error: %v", err)
			}
		})
	}

	if m.retentionDays > 0 && m.storage != nil {
		m.wg.Go(m.cleanupLoop)
	}
}

// cleanupLoop runs periodic data cleanup.
func (m *Manager) cleanupLoop() {
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

// Shutdown stops all background goroutines and releases resources.
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

// --- Accessors ---

// GetInterceptor returns the interceptor.
func (m *Manager) GetInterceptor() *Interceptor {
	if m == nil {
		return nil
	}
	return m.interceptor
}

// InterceptionCfg returns the security interception configuration.
func (m *Manager) InterceptionCfg() InterceptionConfig {
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

// GetRegistry returns the plugin registry.
func (m *Manager) GetRegistry() *plugin.Registry {
	if m == nil {
		return nil
	}
	return m.registry
}

// GetStorage returns the storage recorder.
func (m *Manager) GetStorage() telemetry.Recorder {
	if m == nil {
		return nil
	}
	return m.storage
}

// SetAPI attaches an HTTP API server after construction.
// Used when the API server needs a reference to the manager itself.
func (m *Manager) SetAPI(handler http.Handler, ln net.Listener, socketPath string) {
	m.apiHandler = handler
	m.apiListener = ln
	m.socketPath = socketPath
}

// APIHandler returns the management API HTTP handler.
func (m *Manager) APIHandler() http.Handler {
	if m == nil || m.apiHandler == nil {
		return http.NotFoundHandler()
	}
	return m.apiHandler
}

// NewManagerForTest creates a lightweight manager for unit tests.
func NewManagerForTest(interceptor *Interceptor) *Manager {
	return &Manager{
		interceptor: interceptor,
		blockMode:   types.BlockModeRemove,
		stopChan:    make(chan struct{}),
	}
}
