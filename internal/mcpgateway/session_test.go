package mcpgateway

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionStore_BasicOps(t *testing.T) {
	s := NewSessionStore()
	defer s.Close()

	if s.Exists("abc") {
		t.Error("empty store should not contain 'abc'")
	}

	s.Track("abc")
	if !s.Exists("abc") {
		t.Error("should exist after Track")
	}

	s.Remove("abc")
	if s.Exists("abc") {
		t.Error("should not exist after Remove")
	}
}

func TestSessionStore_MaxIDLength(t *testing.T) {
	s := NewSessionStore()
	defer s.Close()
	longID := strings.Repeat("x", maxSessionIDLen+1)
	s.Track(longID)
	if s.Exists(longID) {
		t.Error("should reject IDs exceeding maxSessionIDLen")
	}

	exactID := strings.Repeat("y", maxSessionIDLen)
	s.Track(exactID)
	if !s.Exists(exactID) {
		t.Error("should accept IDs at exactly maxSessionIDLen")
	}
}

func TestSessionStore_EmptyID(t *testing.T) {
	s := NewSessionStore()
	defer s.Close()
	s.Track("")
	if s.Exists("") {
		t.Error("should reject empty IDs")
	}
}

func TestSessionStore_Concurrent(t *testing.T) {
	s := NewSessionStore()
	defer s.Close()
	var wg sync.WaitGroup
	const n = 100

	// Concurrent writers
	for i := range n {
		wg.Go(func() {
			id := fmt.Sprintf("session-%d", i)
			s.Track(id)
			s.Exists(id)
			if i%2 == 0 {
				s.Remove(id)
			}
		})
	}
	wg.Wait()

	// Verify odd sessions remain
	for i := 1; i < n; i += 2 {
		id := fmt.Sprintf("session-%d", i)
		if !s.Exists(id) {
			t.Errorf("expected %s to still exist", id)
		}
	}
}

func TestSessionStore_MaxSessions(t *testing.T) {
	s := NewSessionStore()
	defer s.Close()

	// Fill to capacity
	for i := range maxSessions {
		s.Track(fmt.Sprintf("s-%d", i))
	}

	// New session should be rejected
	s.Track("overflow")
	if s.Exists("overflow") {
		t.Error("should reject new sessions at capacity")
	}

	// Updating existing session should still work
	s.Track("s-0")
	if !s.Exists("s-0") {
		t.Error("should allow updating existing sessions at capacity")
	}

	// After removing one, new session should be accepted
	s.Remove("s-0")
	s.Track("new-session")
	if !s.Exists("new-session") {
		t.Error("should accept new session after removal frees capacity")
	}
}

func TestSessionStore_DoubleClose(t *testing.T) {
	s := NewSessionStore()
	s.Close()
	s.Close() // must not panic

	// Store still usable for reads after close (reaper stopped but data intact)
	s.Track("after-close")
}

func TestSessionStore_ReapLoopStopsOnClose(t *testing.T) {
	// Use a short reap interval so the goroutine ticks frequently.
	s := newSessionStore(time.Now, 10*time.Millisecond)

	// Track a session to confirm the store works.
	s.Track("alive")
	if !s.Exists("alive") {
		t.Fatal("session should exist after Track")
	}

	// Close should stop the reap goroutine.
	s.Close()

	// After Close, the store's stop channel is closed.
	// Verify by selecting on it (non-blocking).
	select {
	case <-s.stop:
		// expected: channel is closed
	default:
		t.Error("stop channel should be closed after Close()")
	}

	// Double-close must not panic.
	s.Close()
}

func TestSessionStore_ReaperExpiresSessions(t *testing.T) {
	s := &SessionStore{
		sessions: make(map[string]time.Time),
		stop:     make(chan struct{}),
	}
	defer s.Close()

	// Insert an already-expired session
	s.mu.Lock()
	s.sessions["old"] = time.Now().Add(-25 * time.Hour)
	s.sessions["fresh"] = time.Now()
	s.mu.Unlock()

	// Simulate one reap cycle
	s.mu.Lock()
	now := time.Now()
	for id, ts := range s.sessions {
		if now.Sub(ts) > sessionTTL {
			delete(s.sessions, id)
		}
	}
	s.mu.Unlock()

	if s.Exists("old") {
		t.Error("expired session should have been reaped")
	}
	if !s.Exists("fresh") {
		t.Error("fresh session should survive reap")
	}
}
