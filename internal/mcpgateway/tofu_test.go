package mcpgateway

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/BakeLens/crust/internal/jsonrpc"
	_ "github.com/mutecomm/go-sqlcipher/v4"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func newTestStore(t *testing.T) *TOFUStore {
	t.Helper()
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := NewTOFUStore(db)
	if err := store.InitSchema(); err != nil {
		t.Fatal(err)
	}
	return store
}

func makeRequest(id int, method string) *jsonrpc.Message {
	return &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(fmt.Sprintf("%d", id)),
		Method:  method,
	}
}

func makeResponse(id int, result string) *jsonrpc.Message {
	return &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(fmt.Sprintf("%d", id)),
		Result:  json.RawMessage(result),
	}
}

// ---------------------------------------------------------------------------
// CanonicalToolsHash tests
// ---------------------------------------------------------------------------

func TestCanonicalToolsHash_Deterministic(t *testing.T) {
	// Same tools with different JSON key orders must produce identical hashes.
	a := `{"tools":[{"name":"read","description":"Read files","inputSchema":{}}]}`
	b := `{"tools":[{"description":"Read files","name":"read","inputSchema":{}}]}`

	hashA, err := CanonicalToolsHash(json.RawMessage(a))
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := CanonicalToolsHash(json.RawMessage(b))
	if err != nil {
		t.Fatal(err)
	}
	if hashA != hashB {
		t.Errorf("expected identical hashes, got %s vs %s", hashA, hashB)
	}
}

func TestCanonicalToolsHash_DifferentTools(t *testing.T) {
	a := `{"tools":[{"name":"read","description":"Read files"}]}`
	b := `{"tools":[{"name":"write","description":"Write files"}]}`

	hashA, err := CanonicalToolsHash(json.RawMessage(a))
	if err != nil {
		t.Fatal(err)
	}
	hashB, err := CanonicalToolsHash(json.RawMessage(b))
	if err != nil {
		t.Fatal(err)
	}
	if hashA == hashB {
		t.Errorf("expected different hashes for different tools, both got %s", hashA)
	}
}

func TestCanonicalToolsHash_EmptyTools(t *testing.T) {
	result := `{"tools":[]}`
	hash, err := CanonicalToolsHash(json.RawMessage(result))
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Error("expected non-empty hash for empty tools array")
	}
}

func TestCanonicalToolsHash_NilToolsField(t *testing.T) {
	// Result with no "tools" key should be treated as empty array.
	result := `{}`
	hash, err := CanonicalToolsHash(json.RawMessage(result))
	if err != nil {
		t.Fatal(err)
	}
	if hash == "" {
		t.Error("expected non-empty hash for nil tools field")
	}
}

// ---------------------------------------------------------------------------
// TOFUStore CRUD tests
// ---------------------------------------------------------------------------

func TestTOFUStore_CRUD(t *testing.T) {
	store := newTestStore(t)

	// GetPin returns nil for unknown server.
	pin, err := store.GetPin("test-server")
	if err != nil {
		t.Fatal(err)
	}
	if pin != nil {
		t.Fatal("expected nil pin for unknown server")
	}

	// ListPins returns empty slice.
	pins, err := store.ListPins()
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 0 {
		t.Fatalf("expected 0 pins, got %d", len(pins))
	}

	// UpsertPin + GetPin.
	if err := store.UpsertPin(TOFUPin{ServerName: "test-server", ToolsHash: "abc123"}); err != nil {
		t.Fatal(err)
	}

	pin, err = store.GetPin("test-server")
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil {
		t.Fatal("expected non-nil pin")
	}
	if pin.ToolsHash != "abc123" {
		t.Errorf("expected hash=abc123, got %q", pin.ToolsHash)
	}

	// ListPins returns 1 entry.
	pins, err = store.ListPins()
	if err != nil {
		t.Fatal(err)
	}
	if len(pins) != 1 {
		t.Fatalf("expected 1 pin, got %d", len(pins))
	}

	// UpsertPin updates existing row.
	if err := store.UpsertPin(TOFUPin{ServerName: "test-server", ToolsHash: "def456"}); err != nil {
		t.Fatal(err)
	}
	pin, err = store.GetPin("test-server")
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil {
		t.Fatal("expected non-nil pin after upsert")
	}
	if pin.ToolsHash != "def456" {
		t.Errorf("expected hash=def456, got %q", pin.ToolsHash)
	}

	// DeletePin.
	if err := store.DeletePin("test-server"); err != nil {
		t.Fatal(err)
	}
	pin, err = store.GetPin("test-server")
	if err != nil {
		t.Fatal(err)
	}
	if pin != nil {
		t.Error("expected nil pin after delete")
	}
}

// ---------------------------------------------------------------------------
// TOFUTracker tests
// ---------------------------------------------------------------------------

const toolsResultA = `{"tools":[{"name":"read","description":"Read files","inputSchema":{}}]}`
const toolsResultB = `{"tools":[{"name":"write","description":"Write files","inputSchema":{}}]}`

func TestTOFUTracker_FirstUse(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "fallback-server")

	// Send tools/list request then response.
	req := makeRequest(1, "tools/list")
	tracker.ObserveRequest(req)

	resp := makeResponse(1, toolsResultA)
	block, errMsg := tracker.CheckResponse(resp)
	if block {
		t.Errorf("first use should not block: %s", errMsg)
	}

	// Verify pin was created.
	pin, err := store.GetPin("fallback-server")
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil {
		t.Fatal("expected pin to be created on first use")
	}
}

func TestTOFUTracker_SameHash(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "server1")

	// First use: auto-pin.
	req := makeRequest(1, "tools/list")
	tracker.ObserveRequest(req)
	tracker.CheckResponse(makeResponse(1, toolsResultA))

	// Second call with same tools.
	req2 := makeRequest(2, "tools/list")
	tracker.ObserveRequest(req2)
	block, errMsg := tracker.CheckResponse(makeResponse(2, toolsResultA))
	if block {
		t.Errorf("same hash should not block: %s", errMsg)
	}
}

func TestTOFUTracker_HashMismatch(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "server1")

	// First use: auto-pin with tools A.
	req := makeRequest(1, "tools/list")
	tracker.ObserveRequest(req)
	tracker.CheckResponse(makeResponse(1, toolsResultA))

	// Second call with different tools B.
	req2 := makeRequest(2, "tools/list")
	tracker.ObserveRequest(req2)
	block, errMsg := tracker.CheckResponse(makeResponse(2, toolsResultB))
	if !block {
		t.Error("hash mismatch should block")
	}
	if errMsg == "" {
		t.Error("expected non-empty error message on mismatch")
	}

	// Verify pending approval exists.
	approvals := tracker.PendingApprovals()
	if len(approvals) != 1 {
		t.Fatalf("expected 1 pending approval, got %d", len(approvals))
	}
	if approvals[0].ServerName != "server1" {
		t.Errorf("expected server=server1, got %q", approvals[0].ServerName)
	}
}

func TestTOFUTracker_Approve(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "server1")

	// Pin tools A.
	req := makeRequest(1, "tools/list")
	tracker.ObserveRequest(req)
	tracker.CheckResponse(makeResponse(1, toolsResultA))

	// Trigger mismatch with tools B.
	req2 := makeRequest(2, "tools/list")
	tracker.ObserveRequest(req2)
	block, _ := tracker.CheckResponse(makeResponse(2, toolsResultB))
	if !block {
		t.Fatal("expected block on mismatch")
	}

	// Approve the change.
	if err := tracker.Approve("server1"); err != nil {
		t.Fatal(err)
	}

	// Pending should be cleared.
	if len(tracker.PendingApprovals()) != 0 {
		t.Error("expected no pending approvals after approve")
	}

	// Next tools/list with B should pass.
	req3 := makeRequest(3, "tools/list")
	tracker.ObserveRequest(req3)
	block, errMsg := tracker.CheckResponse(makeResponse(3, toolsResultB))
	if block {
		t.Errorf("should pass after approval: %s", errMsg)
	}

	// Verify pin is updated.
	pin, err := store.GetPin("server1")
	if err != nil {
		t.Fatal(err)
	}
	if pin == nil {
		t.Fatal("expected non-nil pin after approval")
	}
	expectedHash, _ := CanonicalToolsHash(json.RawMessage(toolsResultB))
	if pin.ToolsHash != expectedHash {
		t.Errorf("expected pin updated to new hash after approval")
	}
}

func TestTOFUTracker_Reject(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "server1")

	// Pin tools A.
	req := makeRequest(1, "tools/list")
	tracker.ObserveRequest(req)
	tracker.CheckResponse(makeResponse(1, toolsResultA))

	// Trigger mismatch with tools B.
	req2 := makeRequest(2, "tools/list")
	tracker.ObserveRequest(req2)
	tracker.CheckResponse(makeResponse(2, toolsResultB))

	// Reject.
	tracker.Reject("server1")

	// Pending should be cleared.
	if len(tracker.PendingApprovals()) != 0 {
		t.Error("expected no pending approvals after reject")
	}

	// Next tools/list with B still blocks (pin is still A).
	req3 := makeRequest(3, "tools/list")
	tracker.ObserveRequest(req3)
	block, _ := tracker.CheckResponse(makeResponse(3, toolsResultB))
	if !block {
		t.Error("should still block after reject (pin unchanged)")
	}
}

func TestTOFUTracker_InitializeExtractsServerName(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "fallback")

	// Send initialize request + response with serverInfo.name.
	req := makeRequest(1, "initialize")
	tracker.ObserveRequest(req)

	resp := makeResponse(1, `{"serverInfo":{"name":"real-server"},"capabilities":{}}`)
	block, _ := tracker.CheckResponse(resp)
	if block {
		t.Error("initialize should never block")
	}
	if got := tracker.GetServerName(); got != "real-server" {
		t.Errorf("expected server name=real-server, got %q", got)
	}
}

func TestTOFUTracker_FallbackName(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "my-fallback")

	// No initialize → should return fallback.
	if got := tracker.GetServerName(); got != "my-fallback" {
		t.Errorf("expected fallback name=my-fallback, got %q", got)
	}
}

func TestTOFUTracker_MultipleServers(t *testing.T) {
	store := newTestStore(t)

	// Tracker A with initialize → "serverA".
	trackerA := NewTOFUTracker(store, "fallbackA")
	reqInit := makeRequest(1, "initialize")
	trackerA.ObserveRequest(reqInit)
	trackerA.CheckResponse(makeResponse(1, `{"serverInfo":{"name":"serverA"}}`))

	reqTools := makeRequest(2, "tools/list")
	trackerA.ObserveRequest(reqTools)
	trackerA.CheckResponse(makeResponse(2, toolsResultA))

	// Tracker B with initialize → "serverB".
	trackerB := NewTOFUTracker(store, "fallbackB")
	reqInit2 := makeRequest(1, "initialize")
	trackerB.ObserveRequest(reqInit2)
	trackerB.CheckResponse(makeResponse(1, `{"serverInfo":{"name":"serverB"}}`))

	reqTools2 := makeRequest(2, "tools/list")
	trackerB.ObserveRequest(reqTools2)
	trackerB.CheckResponse(makeResponse(2, toolsResultB))

	// Both pins should exist independently.
	pinA, err := store.GetPin("serverA")
	if err != nil {
		t.Fatal(err)
	}
	pinB, err := store.GetPin("serverB")
	if err != nil {
		t.Fatal(err)
	}
	if pinA == nil || pinB == nil {
		t.Fatal("expected both pins to exist")
	}
	if pinA.ToolsHash == pinB.ToolsHash {
		t.Error("expected different hashes for different servers")
	}

	// Mismatch on A should not affect B.
	reqTools3 := makeRequest(3, "tools/list")
	trackerA.ObserveRequest(reqTools3)
	block, _ := trackerA.CheckResponse(makeResponse(3, toolsResultB))
	if !block {
		t.Error("expected mismatch block for serverA")
	}

	reqTools4 := makeRequest(3, "tools/list")
	trackerB.ObserveRequest(reqTools4)
	block, _ = trackerB.CheckResponse(makeResponse(3, toolsResultB))
	if block {
		t.Error("serverB should still match its own tools")
	}
}

func TestTOFUTracker_ApproveNoPending(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "server1")

	err := tracker.Approve("nonexistent")
	if err == nil {
		t.Error("expected error when approving nonexistent pending")
	}
}

func TestTOFUTracker_ErrorResponseNotTracked(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "server1")

	req := makeRequest(1, "tools/list")
	tracker.ObserveRequest(req)

	// Error response should be forwarded without pin creation.
	errResp := &jsonrpc.Message{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Error:   json.RawMessage(`{"code":-1,"message":"internal error"}`),
	}
	block, _ := tracker.CheckResponse(errResp)
	if block {
		t.Error("error response should not block")
	}

	pin, err := store.GetPin("server1")
	if err != nil {
		t.Fatal(err)
	}
	if pin != nil {
		t.Error("error response should not create a pin")
	}
}

func TestTOFUTracker_UnobservedResponseIgnored(t *testing.T) {
	store := newTestStore(t)
	tracker := NewTOFUTracker(store, "server1")

	// Response without a matching observed request ID.
	resp := makeResponse(99, toolsResultA)
	block, _ := tracker.CheckResponse(resp)
	if block {
		t.Error("unobserved response should not block")
	}
}
