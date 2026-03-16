//go:build libcrust

package libcrust

import (
	"context"
	"encoding/json"

	"github.com/BakeLens/crust/internal/eventlog"
)

// ctx returns a background context for database queries.
func ctx() context.Context { return context.Background() }

// GetEvents returns recent security events as a JSON string.
// minutes: time window (default 60, max 10080). limit: max rows (default 100).
func GetEvents(minutes int, limit int) string {
	s := getStorage()
	if s == nil {
		return "[]"
	}

	logs, err := s.GetRecentLogs(ctx(), minutes, limit)
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
