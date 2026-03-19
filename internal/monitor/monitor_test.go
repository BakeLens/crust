package monitor

import (
	"encoding/json"
	"sync/atomic"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/eventlog"
	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

// TestNew verifies New() returns a non-nil Monitor with open channels.
func TestNew(t *testing.T) {
	m := New()
	if m == nil {
		t.Fatal("New() returned nil")
	}
	if m.changes == nil {
		t.Fatal("changes channel is nil")
	}
	if m.stop == nil {
		t.Fatal("stop channel is nil")
	}
	// Verify the changes channel is open and buffered.
	if cap(m.changes) != changeBufSize {
		t.Fatalf("changes channel capacity = %d, want %d", cap(m.changes), changeBufSize)
	}
}

// TestStartMonitor_InitialEmission verifies that Start() emits 3 initial
// changes with kinds agents, protect, and session.
func TestStartMonitor_InitialEmission(t *testing.T) {
	m := New()
	m.Start()
	defer m.Stop()

	// Collect the 3 initial changes with a timeout.
	var got []ChangeKind
	timeout := time.After(5 * time.Second)
	for range 3 {
		select {
		case ch := <-m.Changes():
			got = append(got, ch.Kind)
		case <-timeout:
			t.Fatalf("timed out after receiving %d/%d initial changes", len(got), 3)
		}
	}

	// The initial emission order is agents, protect, session (see emitInitialState).
	want := []ChangeKind{ChangeAgents, ChangeProtect, ChangeSession}
	if len(got) != len(want) {
		t.Fatalf("got %d changes, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("change[%d].Kind = %q, want %q", i, got[i], want[i])
		}
	}
}

// TestAgentSnapshotsEqual tests the snapshot comparison function.
func TestAgentSnapshotsEqual(t *testing.T) {
	tests := []struct {
		name string
		a, b []agentSnapshot
		want bool
	}{
		{
			name: "both nil",
			a:    nil,
			b:    nil,
			want: true,
		},
		{
			name: "both empty",
			a:    []agentSnapshot{},
			b:    []agentSnapshot{},
			want: true,
		},
		{
			name: "nil vs empty",
			a:    nil,
			b:    []agentSnapshot{},
			want: true,
		},
		{
			name: "equal single",
			a:    []agentSnapshot{{Name: "claude", Status: "running", PIDs: "100"}},
			b:    []agentSnapshot{{Name: "claude", Status: "running", PIDs: "100"}},
			want: true,
		},
		{
			name: "different length",
			a:    []agentSnapshot{{Name: "claude"}},
			b:    []agentSnapshot{{Name: "claude"}, {Name: "cursor"}},
			want: false,
		},
		{
			name: "different name",
			a:    []agentSnapshot{{Name: "claude", Status: "running"}},
			b:    []agentSnapshot{{Name: "cursor", Status: "running"}},
			want: false,
		},
		{
			name: "different status",
			a:    []agentSnapshot{{Name: "claude", Status: "running"}},
			b:    []agentSnapshot{{Name: "claude", Status: "stopped"}},
			want: false,
		},
		{
			name: "different pids",
			a:    []agentSnapshot{{Name: "claude", PIDs: "1,2"}},
			b:    []agentSnapshot{{Name: "claude", PIDs: "1,3"}},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := agentSnapshotsEqual(tt.a, tt.b)
			if got != tt.want {
				t.Errorf("agentSnapshotsEqual() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestSortedPIDs tests PID string generation.
func TestSortedPIDs(t *testing.T) {
	tests := []struct {
		name string
		pids []int
		want string
	}{
		{name: "nil", pids: nil, want: ""},
		{name: "empty", pids: []int{}, want: ""},
		{name: "single", pids: []int{42}, want: "42"},
		{name: "already sorted", pids: []int{1, 2, 3}, want: "1,2,3"},
		{name: "unsorted", pids: []int{300, 100, 200}, want: "100,200,300"},
		{name: "duplicates", pids: []int{5, 5, 3}, want: "3,5,5"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedPIDs(tt.pids)
			if got != tt.want {
				t.Errorf("sortedPIDs(%v) = %q, want %q", tt.pids, got, tt.want)
			}
		})
	}
}

// TestSessionIDs tests session ID string generation.
func TestSessionIDs(t *testing.T) {
	tests := []struct {
		name     string
		sessions []telemetry.SessionSummary
		want     string
	}{
		{name: "nil", sessions: nil, want: ""},
		{name: "empty", sessions: []telemetry.SessionSummary{}, want: ""},
		{
			name: "single",
			sessions: []telemetry.SessionSummary{
				{SessionID: types.SessionID("abc")},
			},
			want: "abc",
		},
		{
			name: "multiple sorted",
			sessions: []telemetry.SessionSummary{
				{SessionID: types.SessionID("zzz")},
				{SessionID: types.SessionID("aaa")},
				{SessionID: types.SessionID("mmm")},
			},
			want: "aaa,mmm,zzz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sessionIDs(tt.sessions)
			if got != tt.want {
				t.Errorf("sessionIDs() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestStopMonitor_ClosesChannel verifies that Stop() after Start()
// closes the Changes() channel.
func TestStopMonitor_ClosesChannel(t *testing.T) {
	m := New()
	m.Start()
	m.Stop()

	// Drain any remaining changes, then verify channel is closed.
	for range m.Changes() {
		// drain
	}

	// Reading from a closed channel should return zero value immediately.
	select {
	case _, ok := <-m.Changes():
		if ok {
			t.Error("expected channel to be closed, but got a value")
		}
	case <-time.After(time.Second):
		t.Error("timed out waiting for closed channel")
	}
}

// TestStopMonitor_Idempotent verifies calling Stop() twice does not panic.
func TestStopMonitor_Idempotent(t *testing.T) {
	m := New()
	m.Start()

	// Both calls should succeed without panic.
	m.Stop()
	m.Stop()
}

// --- E2E Tests ---

// TestMonitor_EventRelay_E2E initializes eventlog, starts the monitor,
// records an event via eventlog.Record(), and verifies it appears as a
// Change{Kind: "event"} on the Changes() channel.
func TestMonitor_EventRelay_E2E(t *testing.T) {
	m := New()
	m.Start()
	defer m.Stop()

	// Drain the 3 initial state emissions (agents, protect, session).
	timeout := time.After(5 * time.Second)
	for range 3 {
		select {
		case <-m.Changes():
		case <-timeout:
			t.Fatal("timed out draining initial state")
		}
	}

	// Record an event via eventlog — the event relay goroutine should pick it up.
	// No delay needed: Start() subscribes to eventlog synchronously.
	eventlog.Record(eventlog.Event{
		Layer:      eventlog.LayerHook,
		ToolName:   "Read",
		WasBlocked: true,
		RuleName:   "test-rule",
		Protocol:   "test",
	})

	// Wait for the event change to arrive.
	timer := time.After(5 * time.Second)
	for {
		select {
		case ch, ok := <-m.Changes():
			if !ok {
				t.Fatal("changes channel closed unexpectedly")
			}
			if ch.Kind == ChangeEvent {
				// Verify the payload contains the tool name.
				var payload map[string]any
				if err := json.Unmarshal(ch.Payload, &payload); err != nil {
					t.Fatalf("failed to unmarshal event payload: %v", err)
				}
				if payload["tool_name"] != "Read" {
					t.Errorf("tool_name = %v, want %q", payload["tool_name"], "Read")
				}
				if payload["was_blocked"] != true {
					t.Errorf("was_blocked = %v, want true", payload["was_blocked"])
				}
				return // success
			}
			// Other change kinds (agent scan, etc.) — keep reading.
		case <-timer:
			t.Fatal("timed out waiting for event change after eventlog.Record()")
		}
	}
}

// TestMonitor_ProtectWatcher_E2E sets a protect state func, starts the
// monitor, changes the state, and verifies a "protect" change appears
// reflecting the new state.
func TestMonitor_ProtectWatcher_E2E(t *testing.T) {
	// Start with protect inactive. Use atomic for cross-goroutine visibility.
	var active atomic.Bool
	SetProtectStateFunc(func() (bool, int) {
		return active.Load(), 0
	})
	defer SetProtectStateFunc(nil)

	m := New()
	m.Start()
	defer m.Stop()

	// Drain the 3 initial state emissions.
	timeout := time.After(5 * time.Second)
	for range 3 {
		select {
		case <-m.Changes():
		case <-timeout:
			t.Fatal("timed out draining initial state")
		}
	}

	// Change protect state — the watcher polls every 1s, so we should
	// see a ChangeProtect within ~2 seconds.
	active.Store(true)

	timer := time.After(5 * time.Second)
	for {
		select {
		case ch, ok := <-m.Changes():
			if !ok {
				t.Fatal("changes channel closed unexpectedly")
			}
			if ch.Kind == ChangeProtect {
				var payload map[string]any
				if err := json.Unmarshal(ch.Payload, &payload); err != nil {
					t.Fatalf("failed to unmarshal protect payload: %v", err)
				}
				if payload["active"] != true {
					t.Errorf("active = %v, want true", payload["active"])
				}
				return // success
			}
			// Other change kinds — keep reading.
		case <-timer:
			t.Fatal("timed out waiting for protect change after state flip")
		}
	}
}

// TestEmit_FullChannel fills the buffer and verifies emit does not block.
func TestEmit_FullChannel(t *testing.T) {
	m := New()

	// Fill the channel buffer completely.
	payload := map[string]string{"test": "data"}
	for range changeBufSize {
		m.emit(ChangeAgents, payload)
	}

	// Verify the buffer is full.
	if len(m.changes) != changeBufSize {
		t.Fatalf("channel len = %d, want %d", len(m.changes), changeBufSize)
	}

	// This emit should not block (it drops the change instead).
	done := make(chan struct{})
	go func() {
		m.emit(ChangeAgents, payload)
		close(done)
	}()

	select {
	case <-done:
		// Success: emit returned without blocking.
	case <-time.After(time.Second):
		t.Fatal("emit blocked on full channel")
	}

	// Verify the channel still has exactly changeBufSize items (the extra was dropped).
	if len(m.changes) != changeBufSize {
		t.Fatalf("channel len after overflow = %d, want %d", len(m.changes), changeBufSize)
	}

	// Verify the buffered changes are valid JSON.
	ch := <-m.changes
	var decoded map[string]string
	if err := json.Unmarshal(ch.Payload, &decoded); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}
	if decoded["test"] != "data" {
		t.Errorf("payload[test] = %q, want %q", decoded["test"], "data")
	}
}
