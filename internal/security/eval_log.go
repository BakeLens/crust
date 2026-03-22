package security

import (
	"context"
	"encoding/json"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/telemetry"
)

// EvalLog is an in-memory ring buffer that records recent tool call evaluations.
// It implements RecentLogQuerier for reload re-evaluation without requiring
// a database (used by libcrust and other lightweight embeddings).
type EvalLog struct {
	mu      sync.Mutex
	entries []evalEntry
	cap     int
	pos     int // next write position (circular)
	full    bool
}

type evalEntry struct {
	timestamp time.Time
	toolName  string
	args      json.RawMessage
	blocked   bool
}

// NewEvalLog creates an in-memory evaluation log with the given capacity.
func NewEvalLog(capacity int) *EvalLog {
	if capacity <= 0 {
		capacity = 500
	}
	return &EvalLog{
		entries: make([]evalEntry, capacity),
		cap:     capacity,
	}
}

// Record adds a tool call evaluation result to the ring buffer.
func (l *EvalLog) Record(call rules.ToolCall, blocked bool) {
	l.mu.Lock()
	l.entries[l.pos] = evalEntry{
		timestamp: time.Now(),
		toolName:  call.Name,
		args:      call.Arguments,
		blocked:   blocked,
	}
	l.pos = (l.pos + 1) % l.cap
	if l.pos == 0 {
		l.full = true
	}
	l.mu.Unlock()
}

// GetRecentLogs implements RecentLogQuerier. Returns entries from the last
// `minutes` minutes, up to `limit` entries, newest first.
func (l *EvalLog) GetRecentLogs(_ context.Context, minutes int, limit int) ([]telemetry.ToolCallLog, error) {
	cutoff := time.Now().Add(-time.Duration(minutes) * time.Minute)
	if limit <= 0 {
		limit = 500
	}

	l.mu.Lock()
	// Collect entries from ring buffer in reverse chronological order
	count := l.cap
	if !l.full {
		count = l.pos
	}

	var result []telemetry.ToolCallLog
	for i := 0; i < count && len(result) < limit; i++ {
		idx := (l.pos - 1 - i + l.cap) % l.cap
		e := l.entries[idx]
		if e.timestamp.IsZero() || e.timestamp.Before(cutoff) {
			break // ring buffer entries are chronological; stop at cutoff
		}
		result = append(result, telemetry.ToolCallLog{
			Timestamp:     e.timestamp,
			ToolName:      e.toolName,
			ToolArguments: e.args,
			WasBlocked:    e.blocked,
		})
	}
	l.mu.Unlock()

	return result, nil
}
