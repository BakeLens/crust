package telemetry

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BakeLens/crust/internal/logger"
	"github.com/BakeLens/crust/internal/telemetry/db"
	"github.com/BakeLens/crust/internal/types"
	_ "github.com/mutecomm/go-sqlcipher/v4" // SQLCipher driver for encrypted SQLite
)

var log = logger.New("telemetry")

// Storage handles SQLite/SQLCipher database operations
type Storage struct {
	conn      *sql.DB
	queries   *db.Queries
	encrypted bool
}

// MinEncryptionKeyLength is the minimum required length for encryption keys
const MinEncryptionKeyLength = 16

// NewStorage creates a new storage instance with optional encryption
func NewStorage(dbPath string, encryptionKey string) (*Storage, error) {
	// Build connection string with parameters
	params := url.Values{}
	params.Set("_busy_timeout", "5000")
	params.Set("_journal_mode", "WAL")
	params.Set("_foreign_keys", "1")

	// SECURITY FIX: Pass encryption key via connection string parameter
	// instead of PRAGMA statement to prevent SQL injection
	if encryptionKey != "" {
		// SECURITY: Validate encryption key strength
		if len(encryptionKey) < MinEncryptionKeyLength {
			return nil, fmt.Errorf("encryption key must be at least %d characters", MinEncryptionKeyLength)
		}
		params.Set("_pragma_key", encryptionKey)
	}

	dsn := dbPath + "?" + params.Encode()

	conn, err := openAndPing(dsn)
	if err != nil && dbPath != ":memory:" && conn != nil {
		// Stale WAL/SHM files from a crashed process can prevent SQLite
		// from opening on Windows ("The segment is already unlocked").
		// Close the broken handle, remove only the -wal and -shm files
		// (NOT the main .db), then retry. The -wal/-shm are regenerated
		// automatically by SQLite; removing them is safe when no other
		// process holds the database open. Data committed to the WAL but
		// not yet checkpointed may be lost, but this only happens after
		// an unclean shutdown where the WAL is already corrupted.
		conn.Close()
		walRemoved := removeStaleWALFiles(dbPath)
		if walRemoved {
			log.Warn("Removed stale WAL/SHM files after failed open, retrying")
			conn, err = openAndPing(dsn)
		}
	}
	if err != nil {
		if conn != nil {
			conn.Close()
		}
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Verify encryption is working by running a simple query
	encrypted := false
	if encryptionKey != "" {
		var result int
		if err := conn.QueryRowContext(context.Background(), "SELECT 1").Scan(&result); err != nil {
			conn.Close()
			return nil, fmt.Errorf("encryption key verification failed: %w", err)
		}
		encrypted = true
		log.Info("Database encryption enabled")
	}

	s := &Storage{
		conn:      conn,
		queries:   db.New(conn),
		encrypted: encrypted,
	}

	if err := s.initSchema(); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to initialize schema: %w", err)
	}

	return s, nil
}

// openAndPing opens a SQLite connection and pings it to verify it works.
func openAndPing(dsn string) (*sql.DB, error) {
	conn, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return nil, err
	}
	conn.SetMaxOpenConns(1)
	if err := conn.PingContext(context.Background()); err != nil {
		return conn, err
	}
	return conn, nil
}

// removeStaleWALFiles removes leftover -wal and -shm files for the given DB.
// These are safe to remove when no process holds the database open; SQLite
// regenerates them on next connection. Returns true if any files were removed.
func removeStaleWALFiles(dbPath string) bool {
	removed := false
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Remove(dbPath + suffix); err == nil {
			removed = true
		}
	}
	return removed
}

// IsEncrypted returns whether the database is encrypted
func (s *Storage) IsEncrypted() bool {
	return s.encrypted
}

// Close closes the database connection
func (s *Storage) Close() error {
	return s.conn.Close()
}

// DB returns the underlying database connection
func (s *Storage) DB() *sql.DB {
	return s.conn
}

// Queries returns the sqlc queries interface
func (s *Storage) Queries() *db.Queries {
	return s.queries
}

func (s *Storage) initSchema() error {
	// Read schema from embedded file or inline
	schemaFile := "internal/telemetry/schema.sql"
	schema, err := os.ReadFile(schemaFile)
	if err != nil {
		// Fallback to inline schema if file not found
		schema = []byte(inlineSchema)
	}

	_, err = s.conn.ExecContext(context.Background(), string(schema))
	if err != nil {
		return err
	}

	// Run migrations for existing databases
	s.runMigrations()
	return nil
}

// runMigrations applies incremental schema changes for existing databases.
// Each migration is idempotent — safe to run multiple times.
func (s *Storage) runMigrations() {
	ctx := context.Background()
	migrations := []string{
		// v0.x: Add layer column to tool_call_logs for per-layer telemetry tracking
		`ALTER TABLE tool_call_logs ADD COLUMN layer TEXT DEFAULT 'L1'`,
	}
	for _, m := range migrations {
		_, err := s.conn.ExecContext(ctx, m)
		if err != nil {
			// "duplicate column name" means migration already applied — ignore
			if !strings.Contains(err.Error(), "duplicate column") {
				log.Debug("Migration skipped: %v", err)
			}
		}
	}
}

// inlineSchema is a fallback if schema.sql is not found
const inlineSchema = `
CREATE TABLE IF NOT EXISTS traces (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_id TEXT NOT NULL UNIQUE,
	session_id TEXT,
	start_time DATETIME,
	end_time DATETIME,
	metadata BLOB DEFAULT '{}',
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_traces_trace_id ON traces(trace_id);
CREATE INDEX IF NOT EXISTS idx_traces_session_id ON traces(session_id);
CREATE INDEX IF NOT EXISTS idx_traces_start_time ON traces(start_time);

CREATE TABLE IF NOT EXISTS spans (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	trace_rowid INTEGER REFERENCES traces(id) ON DELETE CASCADE,
	span_id TEXT NOT NULL,
	parent_span_id TEXT,
	name TEXT NOT NULL,
	span_kind TEXT,
	start_time DATETIME,
	end_time DATETIME,
	attributes BLOB DEFAULT '{}',
	events BLOB DEFAULT '[]',
	input_tokens INTEGER DEFAULT 0,
	output_tokens INTEGER DEFAULT 0,
	status_code TEXT DEFAULT 'UNSET',
	status_message TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_spans_trace_rowid ON spans(trace_rowid);
CREATE INDEX IF NOT EXISTS idx_spans_span_id ON spans(span_id);
CREATE INDEX IF NOT EXISTS idx_spans_parent_span_id ON spans(parent_span_id);
CREATE INDEX IF NOT EXISTS idx_spans_start_time ON spans(start_time);
CREATE INDEX IF NOT EXISTS idx_spans_span_kind ON spans(span_kind);

CREATE TABLE IF NOT EXISTS tool_call_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
	trace_id TEXT NOT NULL,
	session_id TEXT,
	tool_name TEXT NOT NULL,
	tool_arguments TEXT,
	api_type TEXT,
	was_blocked BOOLEAN DEFAULT FALSE,
	blocked_by_rule TEXT,
	model TEXT,
	layer TEXT DEFAULT 'L1'
);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_timestamp ON tool_call_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_trace_id ON tool_call_logs(trace_id);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_tool_name ON tool_call_logs(tool_name);
CREATE INDEX IF NOT EXISTS idx_tool_call_logs_was_blocked ON tool_call_logs(was_blocked);
`

// =============================================================================
// API Types (wrappers over db types with non-nullable fields for JSON)
// =============================================================================

// Trace represents a trace record (wraps db.Trace for compatibility)
type Trace struct {
	ID        int64           `json:"id"`
	TraceID   types.TraceID   `json:"trace_id"`
	SessionID types.SessionID `json:"session_id,omitempty"`
	StartTime time.Time       `json:"start_time"`
	EndTime   time.Time       `json:"end_time"`
	Metadata  json.RawMessage `json:"metadata,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// Span represents a span record (wraps db.Span for compatibility)
type Span struct {
	ID            int64           `json:"id"`
	TraceRowID    int64           `json:"trace_rowid"`
	SpanID        types.SpanID    `json:"span_id"`
	ParentSpanID  types.SpanID    `json:"parent_span_id,omitempty"`
	Name          string          `json:"name"`
	SpanKind      string          `json:"span_kind"`
	StartTime     time.Time       `json:"start_time"`
	EndTime       time.Time       `json:"end_time"`
	Attributes    json.RawMessage `json:"attributes,omitempty"`
	Events        json.RawMessage `json:"events,omitempty"`
	InputTokens   int64           `json:"input_tokens"`
	OutputTokens  int64           `json:"output_tokens"`
	StatusCode    string          `json:"status_code"`
	StatusMessage string          `json:"status_message,omitempty"`
	CreatedAt     time.Time       `json:"created_at"`
}

// ToolCallLog represents a logged tool call
type ToolCallLog struct {
	ID            int64           `json:"id"`
	Timestamp     time.Time       `json:"timestamp"`
	TraceID       types.TraceID   `json:"trace_id"`
	SessionID     types.SessionID `json:"session_id,omitempty"`
	ToolName      string          `json:"tool_name"`
	ToolArguments json.RawMessage `json:"tool_arguments,omitempty"`
	APIType       types.APIType   `json:"api_type"`
	WasBlocked    bool            `json:"was_blocked"`
	BlockedByRule string          `json:"blocked_by_rule,omitempty"`
	Model         string          `json:"model,omitempty"`
	Layer         string          `json:"layer,omitempty"`
}

// =============================================================================
// Trace Operations (using sqlc)
// =============================================================================

// GetOrCreateTrace gets an existing trace or creates a new one.
// Uses INSERT ... ON CONFLICT to avoid TOCTOU races between concurrent goroutines.
func (s *Storage) GetOrCreateTrace(ctx context.Context, traceID types.TraceID, sessionID types.SessionID) (*Trace, error) {
	now := time.Now().UTC()

	// Atomic upsert — no TOCTOU race
	_, err := s.queries.UpsertTrace(ctx, db.UpsertTraceParams{
		TraceID:   traceID.String(),
		SessionID: strPtr(sessionID.String()),
		StartTime: &now,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to upsert trace: %w", err)
	}

	// Fetch the canonical row (may have been created by another goroutine)
	dbTrace, err := s.queries.GetTraceByID(ctx, traceID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get trace after upsert: %w", err)
	}

	return dbTraceToTrace(&dbTrace), nil
}

// UpdateTraceEndTime updates the end time of a trace
func (s *Storage) UpdateTraceEndTime(ctx context.Context, traceID types.TraceID, endTime time.Time) error {
	t := endTime.UTC()
	return s.queries.UpdateTraceEndTime(ctx, db.UpdateTraceEndTimeParams{
		TraceID: traceID.String(),
		EndTime: &t,
	})
}

// spanToInsertParams converts a Span to the db insert parameters.
func spanToInsertParams(span *Span) db.InsertSpanParams {
	return db.InsertSpanParams{
		TraceRowid:    new(span.TraceRowID),
		SpanID:        span.SpanID.String(),
		ParentSpanID:  strPtr(span.ParentSpanID.String()),
		Name:          span.Name,
		SpanKind:      strPtr(span.SpanKind),
		StartTime:     timePtr(span.StartTime),
		EndTime:       timePtr(span.EndTime),
		Attributes:    span.Attributes,
		Events:        span.Events,
		InputTokens:   new(span.InputTokens),
		OutputTokens:  new(span.OutputTokens),
		StatusCode:    strPtr(span.StatusCode),
		StatusMessage: strPtr(span.StatusMessage),
	}
}

// InsertSpan inserts a new span
func (s *Storage) InsertSpan(ctx context.Context, span *Span) error {
	id, err := s.queries.InsertSpan(ctx, spanToInsertParams(span))
	if err != nil {
		return fmt.Errorf("failed to insert span: %w", err)
	}

	span.ID = id
	return nil
}

// RecordSpanTx atomically records a trace, main span, tool spans, and updates
// the trace end time in a single transaction. This prevents partial writes
// (e.g., trace without spans) if an error occurs mid-sequence.
func (s *Storage) RecordSpanTx(ctx context.Context, traceID types.TraceID, sessionID types.SessionID, mainSpan *Span, toolSpans []*Span) error {
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after commit

	qtx := s.queries.WithTx(tx)

	// 1. Upsert trace
	now := time.Now().UTC()
	_, err = qtx.UpsertTrace(ctx, db.UpsertTraceParams{
		TraceID:   traceID.String(),
		SessionID: strPtr(sessionID.String()),
		StartTime: &now,
	})
	if err != nil {
		return fmt.Errorf("upsert trace: %w", err)
	}

	// Get trace rowid for span FK
	dbTrace, err := qtx.GetTraceByID(ctx, traceID.String())
	if err != nil {
		return fmt.Errorf("get trace: %w", err)
	}

	// 2. Insert main span
	mainSpan.TraceRowID = dbTrace.ID
	spanID, err := qtx.InsertSpan(ctx, spanToInsertParams(mainSpan))
	if err != nil {
		return fmt.Errorf("insert span: %w", err)
	}
	mainSpan.ID = spanID

	// 3. Insert tool spans
	for _, ts := range toolSpans {
		ts.TraceRowID = dbTrace.ID
		_, err = qtx.InsertSpan(ctx, spanToInsertParams(ts))
		if err != nil {
			return fmt.Errorf("insert tool span %s: %w", ts.Name, err)
		}
	}

	// 4. Update trace end time
	endTime := time.Now().UTC()
	err = qtx.UpdateTraceEndTime(ctx, db.UpdateTraceEndTimeParams{
		TraceID: traceID.String(),
		EndTime: &endTime,
	})
	if err != nil {
		return fmt.Errorf("update trace end time: %w", err)
	}

	return tx.Commit()
}

// GetTraceSpans returns all spans for a trace
func (s *Storage) GetTraceSpans(ctx context.Context, traceID types.TraceID) ([]Span, error) {
	dbSpans, err := s.queries.GetTraceSpans(ctx, traceID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to query spans: %w", err)
	}

	spans := make([]Span, len(dbSpans))
	for i, dbSpan := range dbSpans {
		spans[i] = dbSpanToSpan(&dbSpan)
	}

	return spans, nil
}

// ListRecentTraces returns recent traces
func (s *Storage) ListRecentTraces(ctx context.Context, limit int) ([]Trace, error) {
	if limit <= 0 {
		limit = 100
	}

	dbTraces, err := s.queries.ListRecentTraces(ctx, int64(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to query traces: %w", err)
	}

	traces := make([]Trace, len(dbTraces))
	for i, dbTrace := range dbTraces {
		traces[i] = *dbTraceToTrace(&dbTrace)
	}

	return traces, nil
}

// TraceStats holds aggregate trace and span statistics.
type TraceStats struct {
	TotalTraces       int64            `json:"total_traces"`
	TotalSpans        int64            `json:"total_spans"`
	TotalInputTokens  int64            `json:"total_input_tokens"`
	TotalOutputTokens int64            `json:"total_output_tokens"`
	SpansByKind       map[string]int64 `json:"spans_by_kind,omitempty"`
}

// GetTraceStats returns trace and span statistics.
func (s *Storage) GetTraceStats(ctx context.Context) (*TraceStats, error) {
	stats := &TraceStats{}

	traceCount, err := s.queries.GetTraceCount(ctx)
	if err != nil {
		log.Warn("Failed to get trace count: %v", err)
	}
	stats.TotalTraces = traceCount

	spanCount, err := s.queries.GetSpanCount(ctx)
	if err != nil {
		log.Warn("Failed to get span count: %v", err)
	}
	stats.TotalSpans = spanCount

	tokenTotals, err := s.queries.GetTokenTotals(ctx)
	if err != nil {
		log.Warn("Failed to get token totals: %v", err)
	}
	if v, ok := tokenTotals.TotalInput.(int64); ok {
		stats.TotalInputTokens = v
	}
	if v, ok := tokenTotals.TotalOutput.(int64); ok {
		stats.TotalOutputTokens = v
	}

	spansByKind, err := s.queries.GetSpansByKind(ctx)
	if err == nil {
		stats.SpansByKind = make(map[string]int64)
		for _, row := range spansByKind {
			if row.SpanKind != nil {
				stats.SpansByKind[*row.SpanKind] = row.Count
			}
		}
	}

	return stats, nil
}

// =============================================================================
// Session Queries (raw SQL — aggregations not suited to sqlc)
// =============================================================================

// SessionSummary holds aggregate stats for one conversation session.
type SessionSummary struct {
	SessionID    types.SessionID `json:"session_id"`
	Model        string          `json:"model"`
	TotalCalls   int64           `json:"total_calls"`
	BlockedCalls int64           `json:"blocked_calls"`
	FirstSeen    time.Time       `json:"first_seen"`
	LastSeen     time.Time       `json:"last_seen"`
}

// sqliteDateFormats lists the datetime formats SQLite uses for text-stored timestamps,
// tried in order when parsing aggregate function results (MIN/MAX return strings).
var sqliteDateFormats = []string{
	"2006-01-02T15:04:05.999999999Z07:00",
	"2006-01-02T15:04:05Z07:00",
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05",
}

// parseSQLiteTime parses a SQLite datetime string into a time.Time.
func parseSQLiteTime(s string) time.Time {
	for _, layout := range sqliteDateFormats {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC()
		}
	}
	return time.Time{}
}

// GetSessions returns recent sessions aggregated from tool_call_logs, ordered by
// most-recently-active first. Each row corresponds to one unique session_id.
func (s *Storage) GetSessions(ctx context.Context, minutes int, limit int) ([]SessionSummary, error) {
	if minutes <= 0 {
		minutes = 60
	} else if minutes > MaxRecentMinutes {
		minutes = MaxRecentMinutes
	}
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.conn.QueryContext(ctx, `
		SELECT
			session_id,
			model,
			COUNT(*) AS total_calls,
			COALESCE(SUM(CASE WHEN was_blocked THEN 1 ELSE 0 END), 0) AS blocked_calls,
			MIN(timestamp) AS first_seen,
			MAX(timestamp) AS last_seen
		FROM tool_call_logs
		WHERE session_id IS NOT NULL
		  AND timestamp > datetime('now', ?)
		GROUP BY session_id
		ORDER BY last_seen DESC
		LIMIT ?
	`, fmt.Sprintf("-%d minutes", minutes), int64(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to query sessions: %w", err)
	}
	defer rows.Close()

	var sessions []SessionSummary
	for rows.Next() {
		var ss SessionSummary
		var sessionIDStr string
		var model *string
		// Aggregate functions (MIN/MAX) return strings in SQLite — scan as string, parse manually.
		var firstSeenStr, lastSeenStr string
		if err := rows.Scan(&sessionIDStr, &model, &ss.TotalCalls, &ss.BlockedCalls, &firstSeenStr, &lastSeenStr); err != nil {
			return nil, fmt.Errorf("failed to scan session row: %w", err)
		}
		ss.SessionID = types.SessionID(sessionIDStr)
		ss.Model = derefStr(model)
		ss.FirstSeen = parseSQLiteTime(firstSeenStr)
		ss.LastSeen = parseSQLiteTime(lastSeenStr)
		sessions = append(sessions, ss)
	}
	return sessions, rows.Err()
}

// GetSessionEvents returns the most recent tool call events for a specific session,
// ordered newest-first.
func (s *Storage) GetSessionEvents(ctx context.Context, sessionID types.SessionID, limit int) ([]ToolCallLog, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := s.conn.QueryContext(ctx, `
		SELECT id, timestamp, trace_id, session_id, tool_name, tool_arguments,
		       api_type, was_blocked, blocked_by_rule, model, layer
		FROM tool_call_logs
		WHERE session_id = ?
		ORDER BY timestamp DESC
		LIMIT ?
	`, sessionID.String(), int64(limit))
	if err != nil {
		return nil, fmt.Errorf("failed to query session events: %w", err)
	}
	defer rows.Close()

	var logs []ToolCallLog
	for rows.Next() {
		var l ToolCallLog
		var ts *time.Time
		var traceIDStr, sessionIDStr string
		var argsStr, apiType, blockedByRule, model, layer *string
		var wasBlocked *bool
		if err := rows.Scan(
			&l.ID, &ts, &traceIDStr, &sessionIDStr,
			&l.ToolName, &argsStr, &apiType, &wasBlocked,
			&blockedByRule, &model, &layer,
		); err != nil {
			return nil, fmt.Errorf("failed to scan log row: %w", err)
		}
		l.TraceID = types.TraceID(traceIDStr)
		l.SessionID = types.SessionID(sessionIDStr)
		l.Timestamp = derefTime(ts)
		if argsStr != nil {
			l.ToolArguments = json.RawMessage(*argsStr)
		}
		if parsed, err := types.ParseAPIType(derefStr(apiType)); err == nil {
			l.APIType = parsed
		}
		l.WasBlocked = derefBool(wasBlocked)
		l.BlockedByRule = derefStr(blockedByRule)
		l.Model = derefStr(model)
		l.Layer = derefStr(layer)
		logs = append(logs, l)
	}
	return logs, rows.Err()
}

// =============================================================================
// Tool Call Logging (using sqlc)
// =============================================================================

// LogToolCall logs a tool call
func (s *Storage) LogToolCall(ctx context.Context, toolLog ToolCallLog) error {
	var argsStr *string
	if toolLog.ToolArguments != nil {
		str := string(toolLog.ToolArguments)
		argsStr = &str
	}

	layer := toolLog.Layer
	if layer == "" {
		layer = "L1" // default to Layer 1 for backwards compatibility
	}

	return s.queries.LogToolCall(ctx, db.LogToolCallParams{
		TraceID:       toolLog.TraceID.String(),
		SessionID:     strPtr(toolLog.SessionID.String()),
		ToolName:      toolLog.ToolName,
		ToolArguments: argsStr,
		ApiType:       strPtr(toolLog.APIType.String()),
		WasBlocked:    &toolLog.WasBlocked,
		BlockedByRule: strPtr(toolLog.BlockedByRule),
		Model:         strPtr(toolLog.Model),
		Layer:         &layer,
	})
}

// MaxRecentMinutes is the maximum time window for recent logs (7 days)
const MaxRecentMinutes = 10080

// GetRecentLogs returns recent tool call logs
func (s *Storage) GetRecentLogs(ctx context.Context, minutes int, limit int) ([]ToolCallLog, error) {
	if limit <= 0 {
		limit = 100
	}

	// SECURITY FIX: Validate minutes parameter
	if minutes <= 0 {
		minutes = 60
	} else if minutes > MaxRecentMinutes {
		minutes = MaxRecentMinutes
	}

	dbLogs, err := s.queries.GetRecentToolCallLogs(ctx, db.GetRecentToolCallLogsParams{
		Datetime: fmt.Sprintf("-%d minutes", minutes),
		Limit:    int64(limit),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get recent logs: %w", err)
	}

	logs := make([]ToolCallLog, len(dbLogs))
	for i, dbLog := range dbLogs {
		logs[i] = dbToolCallLogToToolCallLog(&dbLog)
	}

	return logs, nil
}

// MaxRetentionDays is the maximum allowed retention period
const MaxRetentionDays = 36500 // 100 years

// CleanupOldData deletes data older than the specified number of days
func (s *Storage) CleanupOldData(ctx context.Context, days int) (int64, error) {
	if days <= 0 {
		return 0, nil
	}

	// SECURITY FIX: Validate days parameter to prevent integer overflow
	if days > MaxRetentionDays {
		days = MaxRetentionDays
	}

	timeOffset := fmt.Sprintf("-%d days", days)

	// Use a transaction for atomic cleanup across all tables
	tx, err := s.conn.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("failed to begin cleanup transaction: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck // rollback is a no-op after commit

	qtx := s.queries.WithTx(tx)
	var totalDeleted int64

	// Delete old tool call logs
	result, err := qtx.DeleteOldToolCallLogs(ctx, timeOffset)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old tool call logs: %w", err)
	}
	deleted, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected for tool call logs: %w", err)
	}
	totalDeleted += deleted

	// Delete old spans
	result, err = qtx.DeleteOldSpans(ctx, timeOffset)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old spans: %w", err)
	}
	deleted, err = result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected for spans: %w", err)
	}
	totalDeleted += deleted

	// Delete old traces
	result, err = qtx.DeleteOldTraces(ctx, timeOffset)
	if err != nil {
		return 0, fmt.Errorf("failed to delete old traces: %w", err)
	}
	deleted, err = result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("failed to get rows affected for traces: %w", err)
	}
	totalDeleted += deleted

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("failed to commit cleanup transaction: %w", err)
	}

	if totalDeleted > 0 {
		log.Info("Cleaned up %d old records (retention: %d days)", totalDeleted, days)
	}

	return totalDeleted, nil
}

// =============================================================================
// Helper Functions
// =============================================================================

func strPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func timePtr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	return &t
}

func derefStr(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func derefInt64(i *int64) int64 {
	if i == nil {
		return 0
	}
	return *i
}

func derefTime(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

func derefBool(b *bool) bool {
	if b == nil {
		return false
	}
	return *b
}

func dbTraceToTrace(t *db.Trace) *Trace {
	return &Trace{
		ID:        t.ID,
		TraceID:   types.TraceID(t.TraceID),
		SessionID: types.SessionID(derefStr(t.SessionID)),
		StartTime: derefTime(t.StartTime),
		EndTime:   derefTime(t.EndTime),
		Metadata:  t.Metadata,
		CreatedAt: derefTime(t.CreatedAt),
	}
}

func dbSpanToSpan(s *db.Span) Span {
	return Span{
		ID:            s.ID,
		TraceRowID:    derefInt64(s.TraceRowid),
		SpanID:        types.SpanID(s.SpanID),
		ParentSpanID:  types.SpanID(derefStr(s.ParentSpanID)),
		Name:          s.Name,
		SpanKind:      derefStr(s.SpanKind),
		StartTime:     derefTime(s.StartTime),
		EndTime:       derefTime(s.EndTime),
		Attributes:    s.Attributes,
		Events:        s.Events,
		InputTokens:   derefInt64(s.InputTokens),
		OutputTokens:  derefInt64(s.OutputTokens),
		StatusCode:    derefStr(s.StatusCode),
		StatusMessage: derefStr(s.StatusMessage),
		CreatedAt:     derefTime(s.CreatedAt),
	}
}

func dbToolCallLogToToolCallLog(l *db.ToolCallLog) ToolCallLog {
	var args json.RawMessage
	if l.ToolArguments != nil {
		args = json.RawMessage(*l.ToolArguments)
	}

	return ToolCallLog{
		ID:            l.ID,
		Timestamp:     derefTime(l.Timestamp),
		TraceID:       types.TraceID(l.TraceID),
		SessionID:     types.SessionID(derefStr(l.SessionID)),
		ToolName:      l.ToolName,
		ToolArguments: args,
		APIType: func() types.APIType {
			if parsed, err := types.ParseAPIType(derefStr(l.ApiType)); err == nil {
				return parsed
			}
			return types.APITypeUnknown
		}(),
		WasBlocked:    derefBool(l.WasBlocked),
		BlockedByRule: derefStr(l.BlockedByRule),
		Model:         derefStr(l.Model),
		Layer:         derefStr(l.Layer),
	}
}

// Ensure io is used (for interface compliance)
var _ io.Closer = (*Storage)(nil)
