//go:build !libcrust

package security

import (
	"context"
	"fmt"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/plugin"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// Config holds daemon manager configuration.
type Config struct {
	DBPath          string
	DBKey           string
	SocketPath      string
	SecurityEnabled bool
	RetentionDays   int
	BufferStreaming bool
	MaxBufferEvents int
	BufferTimeout   int
	BlockMode       types.BlockMode
	Engine          rules.RuleEvaluator
}

// Init initializes a full-featured manager for the daemon.
// Creates storage, interceptor, plugin registry, API server, and cleanup loop.
func Init(cfg Config) (*Manager, error) {
	// Initialize storage
	storage, err := telemetry.NewStorage(cfg.DBPath, cfg.DBKey)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize storage: %w", err)
	}
	telemetry.SetGlobalStorage(storage)

	// Seed metrics from persistent storage
	seedCtx, seedCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer seedCancel()
	if counts, err := storage.GetLayerCounts(seedCtx); err == nil {
		em := eventlog.GetMetrics()
		for _, lc := range counts {
			em.Seed(lc.Layer, lc.Blocked, lc.Count)
		}
	}

	// Initial cleanup
	if cfg.RetentionDays > 0 {
		if deleted, err := storage.CleanupOldData(context.Background(), cfg.RetentionDays); err != nil {
			log.Warn("Initial cleanup failed: %v", err)
		} else if deleted > 0 {
			log.Info("Initial cleanup: removed %d old records", deleted)
		}
	}

	// Plugin registry
	pool := plugin.NewPool(0, 0)
	registry := plugin.NewRegistry(pool)
	if sp, err := plugin.NewSandboxPlugin(); err == nil {
		if regErr := registry.Register(sp, nil); regErr != nil {
			log.Warn("sandbox plugin registration failed: %v", regErr)
		} else {
			log.Info("sandbox plugin registered (binary: %s)", sp.BinaryPath())
		}
	} else {
		log.Info("sandbox plugin not available: %v", err)
	}

	// Interceptor
	var interceptor *Interceptor
	if cfg.SecurityEnabled && cfg.Engine != nil {
		interceptor = NewInterceptor(cfg.Engine, storage)
	}

	// Create manager first (API server needs manager reference for plugin stats).
	m := NewManager(interceptor, registry, cfg.BlockMode,
		WithStorage(storage),
		WithRetention(cfg.RetentionDays),
		WithBuffering(cfg.BufferStreaming, cfg.MaxBufferEvents, cfg.BufferTimeout),
	)

	// API server — created after manager so it can reference m.GetRegistry().
	apiServer := NewAPIServer(storage, interceptor, cfg.Engine, m)
	ln, err := apiListener(cfg.SocketPath)
	if err != nil {
		storage.Close()
		return nil, fmt.Errorf("failed to create API listener: %w", err)
	}
	m.SetAPI(apiServer.Handler(), ln, cfg.SocketPath)
	m.Start()

	initEventSink(storage)

	return m, nil
}
