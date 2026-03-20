package mcpgateway

import (
	"sync"
	"time"
)

// maxSessionIDLen is the maximum allowed length for an MCP session ID.
const maxSessionIDLen = 256

// maxSessions is the upper bound on tracked sessions to prevent unbounded growth.
const maxSessions = 10_000

// sessionTTL is how long a session remains valid without activity.
const sessionTTL = 24 * time.Hour

// SessionStore tracks active MCP sessions by their session IDs.
type SessionStore struct {
	mu           sync.RWMutex
	sessions     map[string]time.Time
	stop         chan struct{}
	once         sync.Once
	now          func() time.Time // clock for timestamps; defaults to time.Now
	reapInterval time.Duration    // how often to check for expired sessions
}

// NewSessionStore creates a new session store with a background reaper.
func NewSessionStore() *SessionStore {
	return newSessionStore(time.Now, 5*time.Minute)
}

func newSessionStore(now func() time.Time, reapInterval time.Duration) *SessionStore {
	s := &SessionStore{
		sessions:     make(map[string]time.Time),
		stop:         make(chan struct{}),
		now:          now,
		reapInterval: reapInterval,
	}
	go s.reapLoop()
	return s
}

// Track records a session ID. If the ID exceeds maxSessionIDLen or the store
// is at capacity, the call is ignored.
func (s *SessionStore) Track(id string) {
	if id == "" || len(id) > maxSessionIDLen {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	// Allow update of existing sessions even at capacity.
	if _, exists := s.sessions[id]; !exists && len(s.sessions) >= maxSessions {
		return
	}
	s.sessions[id] = s.now()
}

// Remove deletes a session ID from the store.
func (s *SessionStore) Remove(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, id)
}

// Exists reports whether a session ID is tracked.
func (s *SessionStore) Exists(id string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.sessions[id]
	return ok
}

// Close stops the background reaper goroutine.
func (s *SessionStore) Close() {
	s.once.Do(func() { close(s.stop) })
}

// reapLoop periodically removes expired sessions.
func (s *SessionStore) reapLoop() {
	ticker := time.NewTicker(s.reapInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.stop:
			return
		case now := <-ticker.C:
			s.mu.Lock()
			for id, ts := range s.sessions {
				if now.Sub(ts) > sessionTTL {
					delete(s.sessions, id)
				}
			}
			s.mu.Unlock()
		}
	}
}
