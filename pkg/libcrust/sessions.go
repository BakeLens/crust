//go:build libcrust

package libcrust

import (
	"github.com/BakeLens/crust/internal/types"
)

// GetSessions returns recent sessions aggregated from events as a JSON array.
// minutes: time window (default 60). limit: max rows (default 50).
func GetSessions(minutes int, limit int) string {
	s := getStorage()
	if s == nil {
		return "[]"
	}

	sessions, err := s.GetSessions(ctx(), minutes, limit)
	if err != nil {
		return errJSON(err)
	}
	if sessions == nil {
		return "[]"
	}
	return mustJSON(sessions)
}

// GetSessionEvents returns tool call events for a specific session as JSON.
// limit: max rows (default 50).
func GetSessionEvents(sessionID string, limit int) string {
	s := getStorage()
	if s == nil {
		return "[]"
	}

	events, err := s.GetSessionEvents(ctx(), types.SessionID(sessionID), limit)
	if err != nil {
		return errJSON(err)
	}
	if events == nil {
		return "[]"
	}
	return mustJSON(events)
}
