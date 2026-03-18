//go:build libcrust

package libcrust

import (
	"context"
	"encoding/json"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/telemetry"
)

// ctx returns a background context for database queries.
func ctx() context.Context { return context.Background() }

// GetEvents returns recent security events as a JSON string.
// minutes: time window (default 60, max 10080). limit: max rows (default 100).
// blockedOnly: if true, only return events where was_blocked=1.
func GetEvents(minutes int, limit int, blockedOnly bool) string {
	s := getStorage()
	if s == nil {
		return "[]"
	}

	var logs []telemetry.ToolCallLog
	var err error
	if blockedOnly {
		logs, err = s.GetRecentBlockedLogs(ctx(), minutes, limit)
	} else {
		logs, err = s.GetRecentLogs(ctx(), minutes, limit)
	}
	if err != nil {
		return errJSON(err)
	}
	if logs == nil {
		return "[]"
	}
	return mustJSON(logs)
}

// GetSecurityStats returns in-memory session metrics as a JSON string.
func GetSecurityStats() string {
	m := eventlog.GetMetrics()
	return mustJSON(m.GetStats())
}

// GetStats24h returns blocked/total counts for the last 24 hours from SQLite.
// Unlike GetSecurityStats (in-memory), this always reflects the current sliding window.
func GetStats24h() string {
	s := getStorage()
	if s == nil {
		return `{"blocked":0,"total":0}`
	}
	st, err := s.Get24hStats(ctx())
	if err != nil {
		return `{"blocked":0,"total":0}`
	}
	return mustJSON(st)
}

// ClearEvents deletes all tool call logs from the database and resets in-memory metrics.
func ClearEvents() error {
	s := getStorage()
	if s == nil {
		return nil
	}
	_, err := s.ClearAllEvents(ctx())
	if err != nil {
		return err
	}
	eventlog.GetMetrics().Reset()
	return nil
}

// --- helpers ---

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return `{"error":"marshal failed"}`
	}
	return string(b)
}

func errJSON(err error) string {
	return `{"error":` + mustJSON(err.Error()) + `}`
}
