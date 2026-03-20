package monitor

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/BakeLens/crust/internal/telemetry"
)

const sessionTrackInterval = 10 * time.Second

// storageProvider is the interface for session queries. Matches telemetry.Storage.
// Using an interface allows testing without a real database.
type storageProvider interface {
	GetSessions(ctx context.Context, minutes int, limit int) ([]telemetry.SessionSummary, error)
}

// runSessionTracker polls for session changes every 10 seconds.
// Emits ChangeSession only when the session list differs from the previous poll.
func (m *Monitor) runSessionTracker(prev string) {
	defer m.wg.Done()
	ticker := time.NewTicker(sessionTrackInterval)
	defer ticker.Stop()

	for {
		select {
		case <-m.stop:
			return
		case <-ticker.C:
			sessions := m.getCurrentSessions()
			curr := sessionIDs(sessions)
			if curr != prev {
				m.emit(ChangeSession, sessions)
				prev = curr
			}
		}
	}
}

// getCurrentSessions returns recent sessions from storage.
// Returns nil if storage is not available.
func (m *Monitor) getCurrentSessions() []telemetry.SessionSummary {
	if m.storage == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sessions, err := m.storage.GetSessions(ctx, 5, 50)
	if err != nil {
		log.Debug("session query failed: %v", err)
		return nil
	}
	return sessions
}

// sessionIDs returns a stable string key of session IDs for diff comparison.
func sessionIDs(sessions []telemetry.SessionSummary) string {
	if len(sessions) == 0 {
		return ""
	}
	ids := make([]string, len(sessions))
	for i, s := range sessions {
		ids[i] = string(s.SessionID)
	}
	sort.Strings(ids)
	return strings.Join(ids, ",")
}
