// Package monitor provides a unified change stream for tracking agent
// processes, security events, sessions, and protection status changes.
//
// The Monitor runs background goroutines that detect changes and deliver
// them through a single channel. Consumers include:
//   - GUI (via CGO blocking call LibcrustNextChange)
//   - CLI TUI dashboard (via direct Go import)
//   - Security API (via SSE endpoint)
//
// Change stream protocol:
//   - On Start(), three initial changes are emitted (agents, protect, session)
//     so consumers get full state immediately.
//   - After that, changes are emitted only when a diff is detected.
//   - Security events are relayed in real-time from eventlog.Subscribe().
//
// Frequencies:
//   - Agent process scan: every 5 seconds (ps command, ~10ms)
//   - Security events: real-time (eventlog channel subscription)
//   - Session tracking: every 10 seconds (SQLite query, ~1ms)
//   - Protection status: every 1 second (in-memory read, ~0.01ms)
package monitor

import "encoding/json"

// ChangeKind identifies the type of change in the unified stream.
type ChangeKind string

const (
	// ChangeAgents indicates agent processes started, stopped, or changed status.
	ChangeAgents ChangeKind = "agents"

	// ChangeEvent indicates a security event (tool call blocked or allowed).
	ChangeEvent ChangeKind = "event"

	// ChangeSession indicates sessions appeared or went inactive.
	ChangeSession ChangeKind = "session"

	// ChangeProtect indicates protection status changed (active/inactive, patched agents).
	ChangeProtect ChangeKind = "protect"

	// ChangeConfigRedirect indicates a suspicious API endpoint redirect was
	// found in project config files (.env, .claude/settings.json).
	ChangeConfigRedirect ChangeKind = "config_redirect"
)

// AllChangeKinds lists every valid ChangeKind value. Used by FFI contract
// tests to verify the Rust side handles all kinds the Go side can produce.
var AllChangeKinds = []ChangeKind{ChangeAgents, ChangeEvent, ChangeSession, ChangeProtect, ChangeConfigRedirect}

// Change is a single item in the unified change stream.
// Kind identifies what changed; Payload contains the JSON-encoded details.
type Change struct {
	Kind    ChangeKind      `json:"kind"`
	Payload json.RawMessage `json:"payload"`
}
