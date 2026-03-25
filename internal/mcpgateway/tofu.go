package mcpgateway

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"

	"github.com/BakeLens/crust/internal/jsonrpc"
)

// TOFUPin represents a stored pin for an MCP server.
type TOFUPin struct {
	ServerName string `json:"server_name"`
	ToolsHash  string `json:"tools_hash"` // SHA-256 hex
}

// PendingApproval represents a tools/list hash mismatch awaiting user action.
type PendingApproval struct {
	ServerName string `json:"server_name"`
	OldHash    string `json:"old_hash"`
	NewHash    string `json:"new_hash"`
}

// TOFUStore provides database operations for TOFU pins.
type TOFUStore struct {
	db *sql.DB
}

// NewTOFUStore creates a new TOFUStore backed by the given database connection.
func NewTOFUStore(db *sql.DB) *TOFUStore {
	return &TOFUStore{db: db}
}

// InitSchema creates the tofu_pins table if it does not exist.
func (s *TOFUStore) InitSchema() error {
	_, err := s.db.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS tofu_pins (
		server_name TEXT PRIMARY KEY,
		tools_hash TEXT NOT NULL
	)`)
	return err
}

// GetPin retrieves the pin for the given server name. Returns nil if not found.
func (s *TOFUStore) GetPin(serverName string) (*TOFUPin, error) {
	row := s.db.QueryRowContext(context.Background(),
		`SELECT server_name, tools_hash FROM tofu_pins WHERE server_name = ?`, serverName)

	var pin TOFUPin
	err := row.Scan(&pin.ServerName, &pin.ToolsHash)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("tofu: get pin %q: %w", serverName, err)
	}
	return &pin, nil
}

// UpsertPin inserts or replaces the pin for a server.
func (s *TOFUStore) UpsertPin(pin TOFUPin) error {
	_, err := s.db.ExecContext(context.Background(),
		`INSERT INTO tofu_pins (server_name, tools_hash) VALUES (?, ?)
		 ON CONFLICT(server_name) DO UPDATE SET tools_hash = excluded.tools_hash`,
		pin.ServerName, pin.ToolsHash)
	if err != nil {
		return fmt.Errorf("tofu: upsert pin %q: %w", pin.ServerName, err)
	}
	return nil
}

// ListPins returns all stored TOFU pins ordered by server name.
func (s *TOFUStore) ListPins() ([]TOFUPin, error) {
	rows, err := s.db.QueryContext(context.Background(),
		`SELECT server_name, tools_hash FROM tofu_pins ORDER BY server_name`)
	if err != nil {
		return nil, fmt.Errorf("tofu: list pins: %w", err)
	}
	defer rows.Close()

	var pins []TOFUPin
	for rows.Next() {
		var pin TOFUPin
		if err := rows.Scan(&pin.ServerName, &pin.ToolsHash); err != nil {
			return nil, fmt.Errorf("tofu: scan pin: %w", err)
		}
		pins = append(pins, pin)
	}
	return pins, rows.Err()
}

// DeletePin removes the pin for the given server name.
func (s *TOFUStore) DeletePin(serverName string) error {
	_, err := s.db.ExecContext(context.Background(), `DELETE FROM tofu_pins WHERE server_name = ?`, serverName)
	if err != nil {
		return fmt.Errorf("tofu: delete pin %q: %w", serverName, err)
	}
	return nil
}

// TOFUTracker tracks MCP server connections and validates tools/list pins.
type TOFUTracker struct {
	store        *TOFUStore
	pendingIDs   sync.Map // request ID (string) -> method string
	serverName   atomic.Value
	fallbackName string
	mu           sync.Mutex
	pending      map[string]*PendingApproval // serverName -> pending
}

// NewInMemoryTOFUTracker creates a TOFU tracker backed by an in-memory SQLite DB.
// Pins are lost on restart — suitable for standalone CLI commands.
func NewInMemoryTOFUTracker() *TOFUTracker {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return nil
	}
	store := NewTOFUStore(db)
	if err := store.InitSchema(); err != nil {
		db.Close()
		return nil
	}
	return NewTOFUTracker(store, "")
}

// NewTOFUTracker creates a new TOFU tracker.
func NewTOFUTracker(store *TOFUStore, fallbackName string) *TOFUTracker {
	return &TOFUTracker{
		store:        store,
		fallbackName: fallbackName,
		pending:      make(map[string]*PendingApproval),
	}
}

// Store returns the underlying TOFUStore for direct pin management.
func (t *TOFUTracker) Store() *TOFUStore { return t.store }

// ObserveRequest records request IDs for initialize and tools/list methods
// so that corresponding responses can be matched later.
func (t *TOFUTracker) ObserveRequest(msg *jsonrpc.Message) {
	if msg.Method != "initialize" && msg.Method != "tools/list" {
		return
	}
	if len(msg.ID) == 0 {
		return
	}
	t.pendingIDs.Store(string(msg.ID), msg.Method)
}

// CheckResponse inspects initialize and tools/list responses.
// For initialize: extracts serverInfo.name.
// For tools/list: computes hash, checks against pin.
// Returns (block, errorMessage). block=false means forward the message.
func (t *TOFUTracker) CheckResponse(msg *jsonrpc.Message) (block bool, errMsg string) {
	if len(msg.ID) == 0 {
		return false, ""
	}

	methodVal, ok := t.pendingIDs.LoadAndDelete(string(msg.ID))
	if !ok {
		return false, ""
	}
	method := methodVal.(string)

	// Don't process error responses.
	if len(msg.Error) > 0 {
		return false, ""
	}

	switch method {
	case "initialize":
		return t.handleInitialize(msg)
	case "tools/list":
		return t.handleToolsList(msg)
	default:
		return false, ""
	}
}

// handleInitialize extracts the server name from the initialize response.
func (t *TOFUTracker) handleInitialize(msg *jsonrpc.Message) (bool, string) {
	var result struct {
		ServerInfo struct {
			Name string `json:"name"`
		} `json:"serverInfo"`
	}
	if err := json.Unmarshal(msg.Result, &result); err != nil {
		log.Warn("TOFU: failed to parse initialize result: %v", err)
		return false, ""
	}
	if result.ServerInfo.Name != "" {
		t.serverName.Store(result.ServerInfo.Name)
		log.Info("TOFU: server identified as %q", result.ServerInfo.Name)
	}
	return false, ""
}

// handleToolsList validates the tools/list hash against the stored pin.
func (t *TOFUTracker) handleToolsList(msg *jsonrpc.Message) (bool, string) {
	hash, err := CanonicalToolsHash(msg.Result)
	if err != nil {
		log.Warn("TOFU: failed to hash tools/list result: %v", err)
		return false, ""
	}

	name := t.GetServerName()

	pin, err := t.store.GetPin(name)
	if err != nil {
		log.Warn("TOFU: failed to read pin for %q: %v", name, err)
		return false, ""
	}

	// First use: auto-trust and store the pin.
	if pin == nil {
		if err := t.store.UpsertPin(TOFUPin{ServerName: name, ToolsHash: hash}); err != nil {
			log.Warn("TOFU: failed to store initial pin for %q: %v", name, err)
		} else {
			log.Info("TOFU: pinned %q (hash=%s)", name, truncateHash(hash))
		}
		return false, ""
	}

	// Pin matches: forward.
	if pin.ToolsHash == hash {
		return false, ""
	}

	// Pin mismatch: create pending approval and block.
	t.mu.Lock()
	t.pending[name] = &PendingApproval{
		ServerName: name,
		OldHash:    pin.ToolsHash,
		NewHash:    hash,
	}
	t.mu.Unlock()

	errMsg := fmt.Sprintf(
		`[Crust TOFU] Tool definitions for server %q changed (old: %s, new: %s). Approve via management API to continue.`,
		name, truncateHash(pin.ToolsHash), truncateHash(hash))
	log.Warn("TOFU: hash mismatch for %q (old=%s, new=%s)", name,
		truncateHash(pin.ToolsHash), truncateHash(hash))
	return true, errMsg
}

// GetServerName returns the current server name (from initialize or fallback).
func (t *TOFUTracker) GetServerName() string {
	if v := t.serverName.Load(); v != nil {
		if name, ok := v.(string); ok && name != "" {
			return name
		}
	}
	return t.fallbackName
}

// PendingApprovals returns all pending hash mismatches.
func (t *TOFUTracker) PendingApprovals() []PendingApproval {
	t.mu.Lock()
	defer t.mu.Unlock()

	approvals := make([]PendingApproval, 0, len(t.pending))
	for _, pa := range t.pending {
		approvals = append(approvals, *pa)
	}
	return approvals
}

// Approve accepts a pending hash change and updates the pin.
func (t *TOFUTracker) Approve(serverName string) error {
	t.mu.Lock()
	pa, ok := t.pending[serverName]
	if !ok {
		t.mu.Unlock()
		return fmt.Errorf("tofu: no pending approval for %q", serverName)
	}
	approval := *pa
	delete(t.pending, serverName)
	t.mu.Unlock()

	pin := TOFUPin{ServerName: serverName, ToolsHash: approval.NewHash}
	if err := t.store.UpsertPin(pin); err != nil {
		return fmt.Errorf("tofu: approve %q: %w", serverName, err)
	}
	log.Info("TOFU: approved hash change for %q (new=%s)", serverName, truncateHash(approval.NewHash))
	return nil
}

// Reject clears a pending approval. The server stays blocked until its
// tools/list hash matches the existing pin.
func (t *TOFUTracker) Reject(serverName string) {
	t.mu.Lock()
	delete(t.pending, serverName)
	t.mu.Unlock()
	log.Info("TOFU: rejected hash change for %q", serverName)
}

// CanonicalToolsHash computes SHA-256 of the canonical JSON tools array
// from a tools/list result payload.
func CanonicalToolsHash(result json.RawMessage) (string, error) {
	var parsed struct {
		Tools []any `json:"tools"`
	}
	if err := json.Unmarshal(result, &parsed); err != nil {
		return "", fmt.Errorf("tofu: unmarshal tools/list result: %w", err)
	}
	if parsed.Tools == nil {
		parsed.Tools = []any{}
	}

	canonical, err := canonicalJSON(parsed.Tools)
	if err != nil {
		return "", fmt.Errorf("tofu: canonicalize tools: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return hex.EncodeToString(sum[:]), nil
}

// canonicalJSON recursively sorts object keys and marshals to deterministic JSON.
func canonicalJSON(v any) ([]byte, error) {
	switch val := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf := []byte{'{'}
		for i, k := range keys {
			if i > 0 {
				buf = append(buf, ',')
			}
			keyBytes, err := json.Marshal(k)
			if err != nil {
				return nil, err
			}
			buf = append(buf, keyBytes...)
			buf = append(buf, ':')

			valBytes, err := canonicalJSON(val[k])
			if err != nil {
				return nil, err
			}
			buf = append(buf, valBytes...)
		}
		buf = append(buf, '}')
		return buf, nil

	case []any:
		buf := []byte{'['}
		for i, elem := range val {
			if i > 0 {
				buf = append(buf, ',')
			}
			elemBytes, err := canonicalJSON(elem)
			if err != nil {
				return nil, err
			}
			buf = append(buf, elemBytes...)
		}
		buf = append(buf, ']')
		return buf, nil

	default:
		return json.Marshal(val)
	}
}

// truncateHash returns the first 12 hex characters of a hash for display.
func truncateHash(h string) string {
	if len(h) > 12 {
		return h[:12] + "..."
	}
	return h
}
