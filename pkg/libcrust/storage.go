//go:build libcrust

package libcrust

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/telemetry"
)

// storageState holds the initialized storage and stats service.
var storage struct {
	mu    sync.Mutex
	db    *telemetry.Storage
	stats *telemetry.StatsService
}

// storageSink implements eventlog.Sink by writing to telemetry storage.
type storageSink struct{}

func (storageSink) LogEvent(event eventlog.Event) {
	s := getStorage()
	if s == nil {
		return
	}

	layer := event.Layer
	if layer == "" {
		layer = eventlog.LayerProxyResponse
	}

	tcLog := telemetry.ToolCallLog{
		TraceID:       event.TraceID,
		SessionID:     event.SessionID,
		ToolName:      event.ToolName,
		ToolArguments: event.Arguments,
		APIType:       event.APIType,
		Model:         event.Model,
		WasBlocked:    event.WasBlocked,
		BlockedByRule: event.RuleName,
		Layer:         layer,
		Protocol:      event.Protocol,
		Direction:     event.Direction,
		Method:        event.Method,
		BlockType:     event.BlockType,
	}

	_ = s.LogToolCall(ctx(), tcLog)
}

func getStorage() *telemetry.Storage {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.db
}

func getStatsService() *telemetry.StatsService {
	storage.mu.Lock()
	defer storage.mu.Unlock()
	return storage.stats
}

// InitStorage opens the SQLite database and wires event recording.
// dbPath is the path to the database file (e.g. "~/.crust/telemetry.db").
// encryptionKey may be empty to skip encryption.
// The rule engine (Init) must be called first.
func InitStorage(dbPath string, encryptionKey string) error {
	storage.mu.Lock()
	defer storage.mu.Unlock()

	// Close existing storage if any.
	if storage.db != nil {
		_ = storage.db.Close()
		storage.db = nil
		storage.stats = nil
	}

	// Ensure parent directory exists.
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("create db dir: %w", err)
	}

	db, err := telemetry.NewStorage(dbPath, encryptionKey)
	if err != nil {
		return fmt.Errorf("open storage: %w", err)
	}

	storage.db = db
	storage.stats = telemetry.NewStatsService(db)

	// Set as global storage for telemetry provider.
	telemetry.SetGlobalStorage(db)

	// Wire event sink so eventlog.Record() persists to SQLite.
	eventlog.SetSink(storageSink{})

	// Update the interceptor's storage if already initialized.
	i := security.GetGlobalInterceptor()
	if i != nil {
		i.SetStorage(db)
	}

	return nil
}

// CloseStorage shuts down the database. Safe to call if not initialized.
func CloseStorage() {
	storage.mu.Lock()
	defer storage.mu.Unlock()

	if storage.db != nil {
		_ = storage.db.Close()
		storage.db = nil
		storage.stats = nil
	}
}
