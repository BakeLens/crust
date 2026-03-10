package plugin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/BakeLens/crust/internal/rules"
)

// =============================================================================
// Test helpers — mock plugins
// =============================================================================

// allowPlugin always allows.
type allowPlugin struct{ name string }

func (p *allowPlugin) Name() string                              { return p.name }
func (p *allowPlugin) Init(json.RawMessage) error                { return nil }
func (p *allowPlugin) Evaluate(context.Context, Request) *Result { return nil }
func (p *allowPlugin) Close() error                              { return nil }

// blockPlugin always blocks with the given result.
type blockPlugin struct {
	name   string
	result Result
}

func (p *blockPlugin) Name() string               { return p.name }
func (p *blockPlugin) Init(json.RawMessage) error { return nil }
func (p *blockPlugin) Evaluate(_ context.Context, _ Request) *Result {
	r := p.result
	return &r
}
func (p *blockPlugin) Close() error { return nil }

// panicPlugin panics on every Evaluate call.
type panicPlugin struct{ name string }

func (p *panicPlugin) Name() string                              { return p.name }
func (p *panicPlugin) Init(json.RawMessage) error                { return nil }
func (p *panicPlugin) Evaluate(context.Context, Request) *Result { panic("intentional panic") }
func (p *panicPlugin) Close() error                              { return nil }

// hangPlugin blocks until context is canceled.
type hangPlugin struct{ name string }

func (p *hangPlugin) Name() string               { return p.name }
func (p *hangPlugin) Init(json.RawMessage) error { return nil }
func (p *hangPlugin) Close() error               { return nil }
func (p *hangPlugin) Evaluate(ctx context.Context, _ Request) *Result {
	<-ctx.Done() // block until timeout
	return nil
}

// countPlugin counts Evaluate calls.
type countPlugin struct {
	name  string
	calls atomic.Int64
}

func (p *countPlugin) Name() string               { return p.name }
func (p *countPlugin) Init(json.RawMessage) error { return nil }
func (p *countPlugin) Close() error               { return nil }
func (p *countPlugin) Evaluate(_ context.Context, _ Request) *Result {
	p.calls.Add(1)
	return nil
}

// mutatingPlugin tries to mutate the request (for Bug 6.4 test).
type mutatingPlugin struct{ name string }

func (p *mutatingPlugin) Name() string               { return p.name }
func (p *mutatingPlugin) Init(json.RawMessage) error { return nil }
func (p *mutatingPlugin) Close() error               { return nil }
func (p *mutatingPlugin) Evaluate(_ context.Context, req Request) *Result {
	if len(req.Paths) > 0 {
		req.Paths[0] = "/etc/shadow" // try to corrupt
	}
	if len(req.Hosts) > 0 {
		req.Hosts[0] = "evil.com"
	}
	if len(req.Rules) > 0 {
		req.Rules[0].Name = "corrupted" // try to corrupt rule snapshot
	}
	return nil
}

// initFailPlugin fails Init.
type initFailPlugin struct{ name string }

func (p *initFailPlugin) Name() string                              { return p.name }
func (p *initFailPlugin) Init(json.RawMessage) error                { return errors.New("init failed") }
func (p *initFailPlugin) Evaluate(context.Context, Request) *Result { return nil }
func (p *initFailPlugin) Close() error                              { return nil }

// dynamicNamePlugin returns different names — for Bug 6.2 test.
type dynamicNamePlugin struct {
	calls atomic.Int64
}

func (p *dynamicNamePlugin) Name() string {
	n := p.calls.Add(1)
	return fmt.Sprintf("dynamic-%d", n)
}
func (p *dynamicNamePlugin) Init(json.RawMessage) error { return nil }
func (p *dynamicNamePlugin) Evaluate(_ context.Context, _ Request) *Result {
	return &Result{RuleName: "test", Severity: rules.SeverityHigh, Message: "blocked"}
}
func (p *dynamicNamePlugin) Close() error { return nil }

// ruleAwarePlugin checks rules in the request and blocks if a specific rule exists.
type ruleAwarePlugin struct {
	name         string
	requiredRule string // block if this rule is NOT present
}

func (p *ruleAwarePlugin) Name() string               { return p.name }
func (p *ruleAwarePlugin) Init(json.RawMessage) error { return nil }
func (p *ruleAwarePlugin) Close() error               { return nil }
func (p *ruleAwarePlugin) Evaluate(_ context.Context, req Request) *Result {
	for _, r := range req.Rules {
		if r.Name == p.requiredRule {
			return nil // rule exists, allow
		}
	}
	return &Result{
		RuleName: p.name + ":missing-rule",
		Severity: rules.SeverityHigh,
		Message:  fmt.Sprintf("required rule %q not found in snapshot (%d rules)", p.requiredRule, len(req.Rules)),
	}
}

// inspectPlugin records the request it received.
type inspectPlugin struct {
	name  string
	store *atomic.Value
}

func (p *inspectPlugin) Name() string               { return p.name }
func (p *inspectPlugin) Init(json.RawMessage) error { return nil }
func (p *inspectPlugin) Close() error               { return nil }
func (p *inspectPlugin) Evaluate(_ context.Context, req Request) *Result {
	p.store.Store(req)
	return nil
}

// conditionalPlugin panics until failCount >= threshold, then returns nil.
type conditionalPlugin struct {
	name      string
	failCount *atomic.Int64
	threshold int64
}

func (p *conditionalPlugin) Name() string               { return p.name }
func (p *conditionalPlugin) Init(json.RawMessage) error { return nil }
func (p *conditionalPlugin) Close() error               { return nil }
func (p *conditionalPlugin) Evaluate(_ context.Context, _ Request) *Result {
	if p.failCount.Add(1) <= p.threshold {
		panic("conditional panic")
	}
	return nil
}

// =============================================================================
// Request / Result type tests
// =============================================================================

func TestRequest_DeepCopy(t *testing.T) {
	original := Request{
		ToolName:   "Bash",
		Arguments:  json.RawMessage(`{"command":"ls"}`),
		Operation:  rules.OpExecute,
		Operations: []rules.Operation{rules.OpExecute, rules.OpRead},
		Paths:      []string{"/home/user/project"},
		Hosts:      []string{"example.com"},
		Content:    "test content",
		Rules: []RuleSnapshot{
			{Name: "rule1", Source: rules.SourceBuiltin, Severity: rules.SeverityCritical},
		},
	}

	cp := original.DeepCopy()

	// Mutate the copy.
	cp.Paths[0] = "/etc/shadow"
	cp.Hosts[0] = "evil.com"
	cp.Operations[0] = rules.OpDelete
	cp.Arguments[0] = 'X'
	cp.Rules[0].Name = "corrupted"

	// Original must be unchanged.
	if original.Paths[0] != "/home/user/project" {
		t.Errorf("DeepCopy failed: original Paths mutated: %v", original.Paths)
	}
	if original.Hosts[0] != "example.com" {
		t.Errorf("DeepCopy failed: original Hosts mutated: %v", original.Hosts)
	}
	if original.Operations[0] != rules.OpExecute {
		t.Errorf("DeepCopy failed: original Operations mutated: %v", original.Operations)
	}
	if original.Arguments[0] != '{' {
		t.Errorf("DeepCopy failed: original Arguments mutated: %v", string(original.Arguments))
	}
	if original.Rules[0].Name != "rule1" {
		t.Errorf("DeepCopy failed: original Rules mutated: %v", original.Rules)
	}
}

func TestRequest_DeepCopy_NormalizesNilSlices(t *testing.T) {
	original := Request{ToolName: "Read"}
	cp := original.DeepCopy()
	// DeepCopy normalizes nil slices to empty (matching wire protocol invariant).
	if cp.Paths == nil {
		t.Error("DeepCopy should normalize nil Paths to empty")
	}
	if cp.Hosts == nil {
		t.Error("DeepCopy should normalize nil Hosts to empty")
	}
	if cp.Operations == nil {
		t.Error("DeepCopy should normalize nil Operations to empty")
	}
	if cp.Arguments == nil {
		t.Error("DeepCopy should normalize nil Arguments to empty")
	}
	if cp.Rules == nil {
		t.Error("DeepCopy should normalize nil Rules to empty")
	}
}

func TestResult_EffectiveSeverity(t *testing.T) {
	tests := []struct {
		input rules.Severity
		want  rules.Severity
	}{
		{rules.SeverityCritical, rules.SeverityCritical},
		{rules.SeverityHigh, rules.SeverityHigh},
		{rules.SeverityWarning, rules.SeverityWarning},
		{rules.SeverityInfo, rules.SeverityInfo},
		{"banana", rules.SeverityHigh},
		{"", rules.SeverityHigh},
		{"CRITICAL", rules.SeverityHigh}, // case-sensitive
	}
	for _, tt := range tests {
		r := &Result{Severity: tt.input}
		if got := r.EffectiveSeverity(); got != tt.want {
			t.Errorf("EffectiveSeverity(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestResult_EffectiveAction(t *testing.T) {
	tests := []struct {
		input rules.Action
		want  rules.Action
	}{
		{"", rules.ActionBlock},
		{rules.ActionBlock, rules.ActionBlock},
		{rules.ActionLog, rules.ActionLog},
		{rules.ActionAlert, rules.ActionAlert},
	}
	for _, tt := range tests {
		r := &Result{Action: tt.input}
		if got := r.EffectiveAction(); got != tt.want {
			t.Errorf("EffectiveAction(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// =============================================================================
// RuleSnapshot tests
// =============================================================================

func TestRuleSnapshot_JSONRoundTrip(t *testing.T) {
	snap := RuleSnapshot{
		Name:        "protect-env",
		Description: "Block .env file access",
		Source:      rules.SourceBuiltin,
		Severity:    rules.SeverityCritical,
		Priority:    10,
		Actions:     []rules.Operation{rules.OpRead, rules.OpWrite},
		BlockPaths:  []string{"**/.env"},
		BlockExcept: []string{"**/.env.example"},
		Message:     "Cannot access .env files",
		Locked:      true,
		Enabled:     true,
		HitCount:    42,
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded RuleSnapshot
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if decoded.Name != snap.Name {
		t.Errorf("Name = %q, want %q", decoded.Name, snap.Name)
	}
	if decoded.Source != snap.Source {
		t.Errorf("Source = %q, want %q", decoded.Source, snap.Source)
	}
	if decoded.HitCount != snap.HitCount {
		t.Errorf("HitCount = %d, want %d", decoded.HitCount, snap.HitCount)
	}
	if len(decoded.BlockPaths) != 1 || decoded.BlockPaths[0] != "**/.env" {
		t.Errorf("BlockPaths = %v, want [**/.env]", decoded.BlockPaths)
	}
}

func TestRequest_RulesInJSON(t *testing.T) {
	// Verify that Request with rules serializes correctly over the wire protocol.
	req := Request{
		ToolName:  "Bash",
		Operation: rules.OpExecute,
		Command:   "ls -la",
		Rules: []RuleSnapshot{
			{Name: "r1", Source: rules.SourceBuiltin, Severity: rules.SeverityCritical, Actions: []rules.Operation{rules.OpRead}},
			{Name: "r2", Source: rules.SourceUser, Severity: rules.SeverityWarning, Actions: []rules.Operation{rules.OpWrite}},
		},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded Request
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	if len(decoded.Rules) != 2 {
		t.Fatalf("Rules count = %d, want 2", len(decoded.Rules))
	}
	if decoded.Rules[0].Name != "r1" || decoded.Rules[1].Name != "r2" {
		t.Errorf("Rules = %v", decoded.Rules)
	}
}

func TestRequest_AllFieldsPresent(t *testing.T) {
	// All fields must always be present (no omitempty) to eliminate protocol ambiguity.
	req := Request{ToolName: "Bash", Operation: rules.OpExecute, Arguments: json.RawMessage(`{}`)}
	data, _ := json.Marshal(req)
	var m map[string]any
	json.Unmarshal(data, &m)
	for _, field := range []string{"tool_name", "arguments", "operation", "operations", "command", "paths", "hosts", "content", "evasive", "rules"} {
		if _, exists := m[field]; !exists {
			t.Errorf("field %q missing from marshaled Request (no omitempty)", field)
		}
	}
}

// =============================================================================
// Wire protocol tests
// =============================================================================

func TestWireRequest_JSONFormat(t *testing.T) {
	params, _ := json.Marshal(InitParams{Name: "sandbox", Config: json.RawMessage(`{"allow":true}`)})
	req := WireRequest{Method: MethodInit, Params: params}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var decoded WireRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.Method != MethodInit {
		t.Errorf("Method = %q, want %q", decoded.Method, MethodInit)
	}
}

func TestWireResponse_AllowResult(t *testing.T) {
	// null result means allow.
	resp := WireResponse{Result: json.RawMessage("null")}
	data, _ := json.Marshal(resp)

	var decoded WireResponse
	json.Unmarshal(data, &decoded)
	if string(decoded.Result) != "null" {
		t.Errorf("Result = %s, want null", decoded.Result)
	}
}

func TestWireResponse_BlockResult(t *testing.T) {
	result, _ := json.Marshal(Result{
		RuleName: "sandbox:fs-deny",
		Severity: rules.SeverityHigh,
		Message:  "path outside sandbox",
	})
	resp := WireResponse{Result: result}
	data, _ := json.Marshal(resp)

	var decoded WireResponse
	json.Unmarshal(data, &decoded)

	var r Result
	json.Unmarshal(decoded.Result, &r)
	if r.RuleName != "sandbox:fs-deny" {
		t.Errorf("RuleName = %q, want %q", r.RuleName, "sandbox:fs-deny")
	}
}

func TestWireResponse_ErrorResult(t *testing.T) {
	resp := WireResponse{Error: "plugin crashed"}
	data, _ := json.Marshal(resp)

	var decoded WireResponse
	json.Unmarshal(data, &decoded)
	if decoded.Error != "plugin crashed" {
		t.Errorf("Error = %q, want %q", decoded.Error, "plugin crashed")
	}
}

func TestWireProtocol_EvaluateWithRules(t *testing.T) {
	// Full round-trip: Request with rules → wire → decode.
	req := Request{
		ToolName:  "Bash",
		Operation: rules.OpExecute,
		Command:   "rm -rf /etc",
		Paths:     []string{"/etc"},
		Rules: []RuleSnapshot{
			{Name: "protect-etc", Source: rules.SourceBuiltin, Severity: rules.SeverityCritical, Actions: []rules.Operation{rules.OpDelete}, BlockPaths: []string{"/etc/**"}},
		},
	}

	params, _ := json.Marshal(req)
	wireReq := WireRequest{Method: MethodEvaluate, Params: params}
	data, _ := json.Marshal(wireReq)

	// Simulate plugin receiving the request.
	var receivedWire WireRequest
	json.Unmarshal(data, &receivedWire)
	if receivedWire.Method != MethodEvaluate {
		t.Fatalf("Method = %q, want %q", receivedWire.Method, MethodEvaluate)
	}

	var receivedReq Request
	json.Unmarshal(receivedWire.Params, &receivedReq)
	if len(receivedReq.Rules) != 1 {
		t.Fatalf("Rules count = %d, want 1", len(receivedReq.Rules))
	}
	if receivedReq.Rules[0].Name != "protect-etc" {
		t.Errorf("Rule name = %q, want %q", receivedReq.Rules[0].Name, "protect-etc")
	}
	if receivedReq.Rules[0].BlockPaths[0] != "/etc/**" {
		t.Errorf("BlockPaths = %v", receivedReq.Rules[0].BlockPaths)
	}
}

// =============================================================================
// Pool tests
// =============================================================================

func TestPool_BasicExecution(t *testing.T) {
	pool := NewPool(4, 5*time.Second)
	ctx := t.Context()

	result, err := pool.Run(ctx, func(context.Context) *Result {
		return &Result{RuleName: "test", Severity: rules.SeverityHigh, Message: "blocked"}
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil || result.RuleName != "test" {
		t.Errorf("unexpected result: %v", result)
	}
}

func TestPool_PanicRecovery(t *testing.T) {
	pool := NewPool(4, 5*time.Second)
	ctx := t.Context()

	result, err := pool.Run(ctx, func(context.Context) *Result {
		panic("boom")
	})
	if err == nil {
		t.Fatal("expected error from panic")
	}
	if result != nil {
		t.Errorf("expected nil result from panic, got %v", result)
	}
	if !strings.Contains(err.Error(), "panic: boom") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestPool_Timeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(4, 5*time.Second) // fake clock — runs instantly
		result, err := pool.Run(t.Context(), func(ctx context.Context) *Result {
			<-ctx.Done()
			return nil
		})
		if !errors.Is(err, errTimeout) {
			t.Fatalf("expected errTimeout, got %v", err)
		}
		if result != nil {
			t.Errorf("expected nil result on timeout, got %v", result)
		}
	})
}

func TestPool_SlotExhaustion(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(1, time.Minute)

		blocker := make(chan struct{})
		go pool.Run(t.Context(), func(context.Context) *Result { //nolint:unparam // must match Pool.Run signature
			<-blocker
			return nil
		})
		synctest.Wait() // deterministic: goroutine has acquired the slot

		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
		defer cancel()

		_, err := pool.Run(ctx, func(context.Context) *Result { return nil })
		if !errors.Is(err, errPoolExhausted) {
			t.Fatalf("expected errPoolExhausted, got %v", err)
		}

		close(blocker)
	})
}

func TestPool_ConcurrentExecution(t *testing.T) {
	pool := NewPool(4, 5*time.Second)
	ctx := t.Context()
	var running atomic.Int64
	var maxRunning atomic.Int64

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			pool.Run(ctx, func(context.Context) *Result {
				cur := running.Add(1)
				defer running.Add(-1)
				for {
					old := maxRunning.Load()
					if cur <= old || maxRunning.CompareAndSwap(old, cur) {
						break
					}
				}
				time.Sleep(10 * time.Millisecond)
				return nil
			})
		})
	}
	wg.Wait()

	if peak := maxRunning.Load(); peak > 4 {
		t.Errorf("pool allowed %d concurrent executions, max should be 4", peak)
	}
}

func TestPool_CooperativeTimeout_NoGoroutineLeak(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		pool := NewPool(4, 5*time.Second) // fake clock — runs instantly
		var completed atomic.Bool

		_, err := pool.Run(t.Context(), func(ctx context.Context) *Result {
			<-ctx.Done()
			completed.Store(true)
			return nil
		})
		if !errors.Is(err, errTimeout) {
			t.Fatalf("expected errTimeout, got %v", err)
		}
		synctest.Wait() // deterministic: goroutine has finished
		if !completed.Load() {
			t.Error("goroutine should have completed after ctx cancellation")
		}
	})
}

func TestPool_ParentCancelReturnsContextCanceled(t *testing.T) {
	pool := NewPool(4, 5*time.Second)
	ctx, cancel := context.WithCancel(t.Context())

	// Start a long-running function, then cancel the parent context.
	// Pool.Run should return context.Canceled, not errTimeout.
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()

	_, err := pool.Run(ctx, func(ctx context.Context) *Result {
		<-ctx.Done() // blocks until parent cancel
		return nil
	})
	if !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}

// =============================================================================
// Registry tests
// =============================================================================

func TestRegistry_Register(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	err := reg.Register(&allowPlugin{name: "test"}, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if names := reg.List(); len(names) != 1 || names[0] != "test" {
		t.Errorf("List = %v, want [test]", names)
	}
}

func TestRegistry_RegisterDuplicateName(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "dup"}, nil)
	err := reg.Register(&allowPlugin{name: "dup"}, nil)
	if err == nil {
		t.Fatal("expected error for duplicate name")
	}
}

func TestRegistry_RegisterEmptyName(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	err := reg.Register(&allowPlugin{name: ""}, nil)
	if err == nil {
		t.Fatal("expected error for empty name")
	}
}

func TestRegistry_RegisterInitFail(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	err := reg.Register(&initFailPlugin{name: "bad"}, nil)
	if err == nil {
		t.Fatal("expected error from Init failure")
	}
	if reg.Len() != 0 {
		t.Error("failed plugin should not be registered")
	}
}

func TestRegistry_EvaluateAllow(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&allowPlugin{name: "p2"}, nil)
	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (allow), got %v", result)
	}
}

func TestRegistry_EvaluateBlock(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&blockPlugin{
		name:   "blocker",
		result: Result{RuleName: "test:block", Severity: rules.SeverityHigh, Message: "denied"},
	}, nil)
	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result == nil {
		t.Fatal("expected block result")
	}
	if result.Plugin != "blocker" {
		t.Errorf("Plugin = %q, want %q", result.Plugin, "blocker")
	}
}

func TestRegistry_FirstBlockWins(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&blockPlugin{name: "first",
		result: Result{RuleName: "first:block", Severity: rules.SeverityHigh, Message: "first"},
	}, nil)
	reg.Register(&blockPlugin{name: "second",
		result: Result{RuleName: "second:block", Severity: rules.SeverityHigh, Message: "second"},
	}, nil)

	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result == nil || result.Plugin != "first" {
		t.Errorf("expected first plugin to win, got %v", result)
	}
}

// TestRegistry_ShortCircuitDoesNotCountAsFailure verifies that when one plugin
// blocks and cancels the eval context, the remaining plugins do not accumulate
// failures (which could incorrectly trigger the circuit breaker).
func TestRegistry_ShortCircuitDoesNotCountAsFailure(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&blockPlugin{name: "fast-blocker",
		result: Result{RuleName: "fast:block", Severity: rules.SeverityHigh, Message: "blocked"},
	}, nil)
	reg.Register(&hangPlugin{name: "slow-allow"}, nil)

	// Evaluate multiple times — slow-allow gets canceled each time.
	// Without the fix, each cancel would count as a timeout failure,
	// eventually disabling slow-allow via the circuit breaker.
	ctx := t.Context()
	for range maxConsecutiveFailures + 2 {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	for _, s := range stats {
		if s.Name == "slow-allow" && s.Disabled {
			t.Error("slow-allow should NOT be disabled — cancellation is not a failure")
		}
	}
}

// =============================================================================
// Rule-aware plugin tests
// =============================================================================

func TestRegistry_PluginReceivesRules(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	var store atomic.Value
	reg.Register(&inspectPlugin{name: "inspector", store: &store}, nil)
	ruleSnaps := []RuleSnapshot{
		{Name: "protect-env", Source: rules.SourceBuiltin, Severity: rules.SeverityCritical, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"**/.env"}, Locked: true, Enabled: true},
		{Name: "protect-ssh", Source: rules.SourceBuiltin, Severity: rules.SeverityCritical, Actions: []rules.Operation{rules.OpRead}, BlockPaths: []string{"$HOME/.ssh/id_*"}, Locked: true, Enabled: true},
		{Name: "user-custom", Source: rules.SourceUser, Severity: rules.SeverityWarning, Actions: []rules.Operation{rules.OpWrite}, BlockPaths: []string{"/tmp/secret"}, Enabled: true},
	}

	reg.Evaluate(t.Context(), Request{
		ToolName:  "Read",
		Operation: rules.OpRead,
		Paths:     []string{"/home/user/.env"},
		Rules:     ruleSnaps,
	})

	seen := store.Load().(Request)
	if len(seen.Rules) != 3 {
		t.Fatalf("plugin received %d rules, want 3", len(seen.Rules))
	}
	if seen.Rules[0].Name != "protect-env" {
		t.Errorf("first rule = %q, want %q", seen.Rules[0].Name, "protect-env")
	}
	if !seen.Rules[0].Locked {
		t.Error("protect-env should be locked")
	}
	if seen.Rules[2].Source != rules.SourceUser {
		t.Errorf("third rule source = %q, want %q", seen.Rules[2].Source, rules.SourceUser)
	}
}

func TestRegistry_RuleAwarePlugin_BlocksWhenRuleMissing(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&ruleAwarePlugin{name: "policy", requiredRule: "protect-env"}, nil)
	// Without rules — should block.
	result := reg.Evaluate(t.Context(), Request{ToolName: "Read", Rules: nil})
	if result == nil {
		t.Fatal("expected block when required rule is missing")
	}
	if result.RuleName != "policy:missing-rule" {
		t.Errorf("RuleName = %q, want %q", result.RuleName, "policy:missing-rule")
	}
}

func TestRegistry_RuleAwarePlugin_AllowsWhenRulePresent(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&ruleAwarePlugin{name: "policy", requiredRule: "protect-env"}, nil)
	result := reg.Evaluate(t.Context(), Request{
		ToolName: "Read",
		Rules:    []RuleSnapshot{{Name: "protect-env"}},
	})
	if result != nil {
		t.Errorf("expected allow when required rule exists, got %v", result)
	}
}

func TestRegistry_RuleSnapshotProperties(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	var store atomic.Value
	reg.Register(&inspectPlugin{name: "inspector", store: &store}, nil)
	reg.Evaluate(t.Context(), Request{
		ToolName: "Bash",
		Rules: []RuleSnapshot{
			{
				Name:        "protect-etc",
				Description: "Block /etc access",
				Source:      rules.SourceBuiltin,
				Severity:    rules.SeverityCritical,
				Priority:    10,
				Actions:     []rules.Operation{rules.OpRead, rules.OpWrite, rules.OpDelete},
				BlockPaths:  []string{"/etc/**"},
				BlockExcept: []string{"/etc/hostname"},
				BlockHosts:  nil,
				Message:     "Cannot modify system files",
				Locked:      true,
				Enabled:     true,
				HitCount:    99,
			},
		},
	})

	seen := store.Load().(Request)
	r := seen.Rules[0]
	if r.Description != "Block /etc access" {
		t.Errorf("Description = %q", r.Description)
	}
	if r.Priority != 10 {
		t.Errorf("Priority = %d", r.Priority)
	}
	if len(r.Actions) != 3 {
		t.Errorf("Actions = %v", r.Actions)
	}
	if len(r.BlockExcept) != 1 || r.BlockExcept[0] != "/etc/hostname" {
		t.Errorf("BlockExcept = %v", r.BlockExcept)
	}
	if r.HitCount != 99 {
		t.Errorf("HitCount = %d", r.HitCount)
	}
}

// =============================================================================
// Crash isolation tests
// =============================================================================

func TestRegistry_PanicRecovery(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(counter, nil)
	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (fail-open after panic), got %v", result)
	}
	if counter.calls.Load() != 1 {
		t.Errorf("counter plugin should have been called once, got %d", counter.calls.Load())
	}
}

func TestRegistry_TimeoutRecovery(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&hangPlugin{name: "hanger"}, nil)
	reg.Register(counter, nil)
	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (fail-open after timeout), got %v", result)
	}
	if counter.calls.Load() != 1 {
		t.Error("counter plugin should have been called after timeout")
	}
}

// =============================================================================
// Circuit breaker tests
// =============================================================================

func TestRegistry_CircuitBreaker_DisableAfterFailures(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(counter, nil)
	ctx := t.Context()
	for range maxConsecutiveFailures {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	if !stats[0].Disabled {
		t.Error("plugin should be disabled after max failures")
	}
	if stats[0].TotalPanics != int64(maxConsecutiveFailures) {
		t.Errorf("total panics = %d, want %d", stats[0].TotalPanics, maxConsecutiveFailures)
	}

	counterBefore := counter.calls.Load()
	reg.Evaluate(ctx, Request{ToolName: "Bash"})
	if counter.calls.Load() != counterBefore+1 {
		t.Error("counter should still be called when crasher is disabled")
	}
}

func TestRegistry_CircuitBreaker_SuccessResetsCounter(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	failCount := &atomic.Int64{}
	plugin := &conditionalPlugin{
		name:      "flaky",
		failCount: failCount,
		threshold: int64(maxConsecutiveFailures - 1),
	}
	reg.Register(plugin, nil)
	ctx := t.Context()
	for range maxConsecutiveFailures - 1 {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	if stats[0].Disabled {
		t.Error("plugin should NOT be disabled yet")
	}

	reg.Evaluate(ctx, Request{ToolName: "Bash"})

	stats = reg.Stats()
	if stats[0].Failures != 0 {
		t.Errorf("failures should be reset to 0 after success, got %d", stats[0].Failures)
	}
}

func TestRegistry_CircuitBreaker_ExponentialBackoff(t *testing.T) {
	if d := cooldownFor(1); d != circuitResetInterval {
		t.Errorf("cycle 1 cooldown = %v, want %v", d, circuitResetInterval)
	}
	if d := cooldownFor(2); d != circuitResetInterval*2 {
		t.Errorf("cycle 2 cooldown = %v, want %v", d, circuitResetInterval*2)
	}
	if d := cooldownFor(3); d != circuitResetInterval*4 {
		t.Errorf("cycle 3 cooldown = %v, want %v", d, circuitResetInterval*4)
	}
	if d := cooldownFor(100); d != time.Hour {
		t.Errorf("cycle 100 cooldown = %v, want %v", d, time.Hour)
	}
}

func TestRegistry_CircuitBreaker_PermanentDisable(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	reg.Register(&panicPlugin{name: "crasher"}, nil)
	ctx := t.Context()

	reg.mu.RLock()
	s := reg.states[0]
	reg.mu.RUnlock()

	s.disableCycles.Store(int64(maxDisableCycles))
	s.disabled.Store(true)
	s.disabledAt.Store(0)

	reg.Evaluate(ctx, Request{ToolName: "Bash"})

	stats := reg.Stats()
	if !stats[0].Permanent {
		t.Error("plugin should be permanently disabled")
	}
	if !stats[0].Disabled {
		t.Error("plugin should still be disabled")
	}
}

func TestRegistry_CircuitBreaker_ConcurrentReEnable(t *testing.T) {
	pool := NewPool(8, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	counter := &countPlugin{name: "counter"}
	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(counter, nil)
	ctx := t.Context()
	for range maxConsecutiveFailures {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	reg.mu.RLock()
	s := reg.states[0]
	reg.mu.RUnlock()
	s.disabledAt.Store(time.Now().Add(-circuitResetInterval * 2).UnixNano())

	var wg sync.WaitGroup
	for range 20 {
		wg.Go(func() {
			reg.Evaluate(ctx, Request{ToolName: "Bash"})
		})
	}
	wg.Wait()

	stats := reg.Stats()
	if !stats[0].Disabled {
		t.Log("plugin re-enabled (race benign in this test)")
	}
}

// =============================================================================
// Bug 6.2: Plugin Name() spoofing
// =============================================================================

func TestRegistry_NameCachedAtRegistration(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	dp := &dynamicNamePlugin{}
	err := reg.Register(dp, nil)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result == nil {
		t.Fatal("expected block result")
	}
	if result.Plugin != "dynamic-1" {
		t.Errorf("Plugin = %q, want %q (cached at registration)", result.Plugin, "dynamic-1")
	}
}

// =============================================================================
// Bug 6.4: Request slice mutation across plugins
// =============================================================================

func TestRegistry_RequestIsolationBetweenPlugins(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	var secondSaw atomic.Value
	reg.Register(&mutatingPlugin{name: "mutator"}, nil)
	reg.Register(&inspectPlugin{name: "inspector", store: &secondSaw}, nil)
	req := Request{
		ToolName: "Bash",
		Paths:    []string{"/home/user/safe"},
		Hosts:    []string{"good.com"},
		Rules:    []RuleSnapshot{{Name: "rule1"}},
	}
	reg.Evaluate(t.Context(), req)

	seen := secondSaw.Load().(Request)
	if len(seen.Paths) > 0 && seen.Paths[0] != "/home/user/safe" {
		t.Errorf("second plugin saw mutated path: %v", seen.Paths)
	}
	if len(seen.Hosts) > 0 && seen.Hosts[0] != "good.com" {
		t.Errorf("second plugin saw mutated host: %v", seen.Hosts)
	}
	if len(seen.Rules) > 0 && seen.Rules[0].Name != "rule1" {
		t.Errorf("second plugin saw mutated rule: %v", seen.Rules)
	}
}

// =============================================================================
// Bug 5.2: Invalid severity validation
// =============================================================================

func TestRegistry_InvalidSeverityDefaultsToHigh(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&blockPlugin{name: "bad-severity",
		result: Result{RuleName: "test", Severity: "banana", Message: "test"},
	}, nil)

	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result == nil {
		t.Fatal("expected block result")
	}
	if result.Severity != rules.SeverityHigh {
		t.Errorf("Severity = %q, want %q (default for invalid)", result.Severity, rules.SeverityHigh)
	}
}

// =============================================================================
// Bug 7.5: Close/Evaluate race
// =============================================================================

func TestRegistry_CloseRejectsNewEvaluate(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))

	counter := &countPlugin{name: "counter"}
	reg.Register(counter, nil)
	reg.Close()

	result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil after Close, got %v", result)
	}

	err := reg.Register(&allowPlugin{name: "late"}, nil)
	if err == nil {
		t.Error("expected error registering after Close")
	}
}

// =============================================================================
// Concurrent stress tests
// =============================================================================

func TestRegistry_ConcurrentEvaluate(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&blockPlugin{
		name:   "p2",
		result: Result{RuleName: "test", Severity: rules.SeverityHigh, Message: "block"},
	}, nil)

	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			result := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
			if result == nil || result.Plugin != "p2" {
				t.Errorf("unexpected result: %v", result)
			}
		})
	}
	wg.Wait()
}

func TestRegistry_ConcurrentEvaluateWithPanics(t *testing.T) {
	pool := NewPool(8, 5*time.Second)
	reg := NewRegistry(pool)
	defer reg.Close()

	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(&allowPlugin{name: "healthy"}, nil)
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
		})
	}
	wg.Wait()

	stats := reg.Stats()
	if stats[0].TotalPanics == 0 {
		t.Error("expected panics to be recorded")
	}
}

// =============================================================================
// Stats / diagnostics tests
// =============================================================================

func TestRegistry_Stats(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	reg.Register(&panicPlugin{name: "crasher"}, nil)
	reg.Register(&allowPlugin{name: "healthy"}, nil)
	ctx := t.Context()
	for range 5 {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	if len(stats) != 2 {
		t.Fatalf("expected 2 stats entries, got %d", len(stats))
	}

	crasher := stats[0]
	if crasher.Name != "crasher" {
		t.Errorf("name = %q, want %q", crasher.Name, "crasher")
	}
	if crasher.TotalPanics < int64(maxConsecutiveFailures) {
		t.Errorf("total panics = %d, want >= %d", crasher.TotalPanics, maxConsecutiveFailures)
	}
	if !crasher.Disabled {
		t.Error("crasher should be disabled")
	}

	healthy := stats[1]
	if healthy.Disabled {
		t.Error("healthy plugin should not be disabled")
	}
}

// =============================================================================
// ProcessPlugin unit tests (without spawning a real process)
// =============================================================================

func TestProcessPlugin_Name(t *testing.T) {
	p := NewProcessPlugin(context.Background(), "sandbox", "/usr/bin/sandbox-plugin")
	if p.Name() != "sandbox" {
		t.Errorf("Name() = %q, want %q", p.Name(), "sandbox")
	}
}

func TestProcessPlugin_InitFailsWithBadPath(t *testing.T) {
	p := NewProcessPlugin(context.Background(), "bad", "/nonexistent/plugin")
	err := p.Init(nil)
	if err == nil {
		t.Fatal("expected error for nonexistent plugin binary")
	}
}

func TestProcessPlugin_EvaluateWhenNotStarted(t *testing.T) {
	p := &ProcessPlugin{name: "dead", ctx: context.Background()}
	// Should fail-open when process is not running.
	result := p.Evaluate(t.Context(), Request{ToolName: "Bash"})
	if result != nil {
		t.Errorf("expected nil (fail-open) when process not running, got %v", result)
	}
}

// =============================================================================
// Bug #4: DeepCopy RuleSnapshot inner slices share backing arrays
// =============================================================================

func TestDeepCopy_RuleSnapshotInnerSlices(t *testing.T) {
	original := Request{
		ToolName: "Bash",
		Rules: []RuleSnapshot{
			{
				Name:        "protect-env",
				Actions:     []rules.Operation{rules.OpRead, rules.OpWrite},
				BlockPaths:  []string{"/etc", "/var"},
				BlockExcept: []string{"/etc/hostname"},
				BlockHosts:  []string{"evil.com", "bad.com"},
			},
		},
	}

	cp := original.DeepCopy()

	// Mutate all inner slices in the copy.
	cp.Rules[0].Actions[0] = rules.Operation("CORRUPTED")
	cp.Rules[0].Actions[1] = rules.Operation("CORRUPTED")
	cp.Rules[0].BlockPaths[0] = "CORRUPTED"
	cp.Rules[0].BlockExcept[0] = "CORRUPTED"
	cp.Rules[0].BlockHosts[0] = "CORRUPTED"

	// Original inner slices must be unaffected.
	if original.Rules[0].Actions[0] != rules.OpRead {
		t.Errorf("DeepCopy: original Actions[0] corrupted: got %q, want %q", original.Rules[0].Actions[0], rules.OpRead)
	}
	if original.Rules[0].Actions[1] != rules.OpWrite {
		t.Errorf("DeepCopy: original Actions[1] corrupted: got %q, want %q", original.Rules[0].Actions[1], rules.OpWrite)
	}
	if original.Rules[0].BlockPaths[0] != "/etc" {
		t.Errorf("DeepCopy: original BlockPaths[0] corrupted: got %q, want %q", original.Rules[0].BlockPaths[0], "/etc")
	}
	if original.Rules[0].BlockExcept[0] != "/etc/hostname" {
		t.Errorf("DeepCopy: original BlockExcept[0] corrupted: got %q, want %q", original.Rules[0].BlockExcept[0], "/etc/hostname")
	}
	if original.Rules[0].BlockHosts[0] != "evil.com" {
		t.Errorf("DeepCopy: original BlockHosts[0] corrupted: got %q, want %q", original.Rules[0].BlockHosts[0], "evil.com")
	}
}

// =============================================================================
// Bug #8: Action validation — invalid actions pass through as-is
// =============================================================================

func TestResult_ActionValidation(t *testing.T) {
	tests := []struct {
		input rules.Action
		want  rules.Action
	}{
		// Valid actions.
		{rules.ActionBlock, rules.ActionBlock},
		{rules.ActionLog, rules.ActionLog},
		{rules.ActionAlert, rules.ActionAlert},
		{"", rules.ActionBlock}, // empty defaults to "block"

		// Invalid actions — EffectiveAction defaults to "block".
		{"allow", rules.ActionBlock},
		{"banana", rules.ActionBlock},
		{"BLOCK", rules.ActionBlock},
		{"Block", rules.ActionBlock},
		{"LOG", rules.ActionBlock},
		{"deny", rules.ActionBlock},
	}
	for _, tt := range tests {
		r := &Result{Action: tt.input}
		got := r.EffectiveAction()
		if got != tt.want {
			t.Errorf("EffectiveAction(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

// =============================================================================
// Pool.Size edge cases
// =============================================================================

func TestPool_Size(t *testing.T) {
	tests := []struct {
		name string
		size int
		want int
	}{
		{"explicit size", 4, 4},
		{"size 1", 1, 1},
		{"large size", 128, 128},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pool := NewPool(tt.size, time.Second)
			if got := pool.Size(); got != tt.want {
				t.Errorf("Size() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestPool_Size_DefaultsWhenZeroOrNegative(t *testing.T) {
	pool := NewPool(0, time.Second)
	if pool.Size() <= 0 {
		t.Errorf("Size() = %d, want > 0 for default", pool.Size())
	}
	pool2 := NewPool(-1, time.Second)
	if pool2.Size() <= 0 {
		t.Errorf("Size() = %d, want > 0 for default", pool2.Size())
	}
}

// =============================================================================
// Registry.Len edge cases
// =============================================================================

func TestRegistry_Len(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))
	defer reg.Close()

	if reg.Len() != 0 {
		t.Errorf("Len() = %d, want 0 for empty registry", reg.Len())
	}

	reg.Register(&allowPlugin{name: "a"}, nil)
	if reg.Len() != 1 {
		t.Errorf("Len() = %d, want 1", reg.Len())
	}

	reg.Register(&allowPlugin{name: "b"}, nil)
	reg.Register(&allowPlugin{name: "c"}, nil)
	if reg.Len() != 3 {
		t.Errorf("Len() = %d, want 3", reg.Len())
	}

	// Failed registration should not increase count.
	reg.Register(&initFailPlugin{name: "bad"}, nil)
	if reg.Len() != 3 {
		t.Errorf("Len() = %d, want 3 after failed registration", reg.Len())
	}

	// Duplicate name should not increase count.
	reg.Register(&allowPlugin{name: "a"}, nil)
	if reg.Len() != 3 {
		t.Errorf("Len() = %d, want 3 after duplicate registration", reg.Len())
	}
}

// =============================================================================
// cooldownFor edge cases
// =============================================================================

func TestCooldownFor_EdgeCases(t *testing.T) {
	tests := []struct {
		name   string
		cycles int64
		want   time.Duration
	}{
		{"zero cycles", 0, circuitResetInterval},
		{"negative cycles", -1, circuitResetInterval},
		{"cycle 1", 1, circuitResetInterval},
		{"cycle 2", 2, circuitResetInterval * 2},
		{"cycle 3", 3, circuitResetInterval * 4},
		{"cycle 4", 4, circuitResetInterval * 8},
		{"maxDisableCycles", int64(maxDisableCycles), cooldownFor(int64(maxDisableCycles))},
		{"very large (50)", 50, time.Hour},   // capped at 1 hour
		{"very large (100)", 100, time.Hour}, // capped at 1 hour
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cooldownFor(tt.cycles)
			if got != tt.want {
				t.Errorf("cooldownFor(%d) = %v, want %v", tt.cycles, got, tt.want)
			}
			// Invariant: cooldown must never exceed 1 hour.
			if got > time.Hour {
				t.Errorf("cooldownFor(%d) = %v, exceeds 1 hour cap", tt.cycles, got)
			}
			// Invariant: cooldown must always be positive.
			if got <= 0 {
				t.Errorf("cooldownFor(%d) = %v, must be positive", tt.cycles, got)
			}
		})
	}
}

// =============================================================================
// Benchmarks
// =============================================================================

func BenchmarkRegistry_Evaluate_Allow(b *testing.B) {
	reg := NewRegistry(NewPool(8, 5*time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	reg.Register(&allowPlugin{name: "p2"}, nil)
	req := Request{
		ToolName:  "Bash",
		Operation: rules.OpExecute,
		Paths:     []string{"/home/user/project/main.go"},
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reg.Evaluate(ctx, req)
	}
}

func BenchmarkRegistry_Evaluate_AllowWithRules(b *testing.B) {
	reg := NewRegistry(NewPool(8, 5*time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	ruleSnaps := make([]RuleSnapshot, 50) // typical rule count
	for i := range ruleSnaps {
		ruleSnaps[i] = RuleSnapshot{
			Name:     fmt.Sprintf("rule-%d", i),
			Source:   rules.SourceBuiltin,
			Severity: rules.SeverityCritical,
			Actions:  []rules.Operation{rules.OpRead, rules.OpWrite},
		}
	}

	req := Request{
		ToolName:  "Bash",
		Operation: rules.OpExecute,
		Paths:     []string{"/home/user/project/main.go"},
		Rules:     ruleSnaps,
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reg.Evaluate(ctx, req)
	}
}

func BenchmarkRegistry_Evaluate_Block(b *testing.B) {
	reg := NewRegistry(NewPool(8, 5*time.Second))
	defer reg.Close()

	reg.Register(&blockPlugin{name: "blocker",
		result: Result{RuleName: "test", Severity: rules.SeverityHigh, Message: "denied"},
	}, nil)

	req := Request{
		ToolName:  "Bash",
		Operation: rules.OpExecute,
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		reg.Evaluate(ctx, req)
	}
}

func BenchmarkPool_Run(b *testing.B) {
	pool := NewPool(8, 5*time.Second)
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		pool.Run(ctx, func(context.Context) *Result { return nil })
	}
}

func BenchmarkRegistry_Evaluate_Parallel(b *testing.B) {
	reg := NewRegistry(NewPool(8, 5*time.Second))
	defer reg.Close()

	reg.Register(&allowPlugin{name: "p1"}, nil)
	req := Request{
		ToolName:  "Bash",
		Operation: rules.OpExecute,
	}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			reg.Evaluate(ctx, req)
		}
	})
}

// =============================================================================
// Bug: Close/Evaluate race — Close must wait for in-flight Evaluate calls
// =============================================================================

// slowPlugin sleeps for a duration then returns a result.
type slowPlugin struct {
	name    string
	delay   time.Duration
	result  Result
	closed  atomic.Bool
	evalRan atomic.Bool
}

func (p *slowPlugin) Name() string               { return p.name }
func (p *slowPlugin) Init(json.RawMessage) error { return nil }
func (p *slowPlugin) Close() error               { p.closed.Store(true); return nil }
func (p *slowPlugin) Evaluate(_ context.Context, _ Request) *Result {
	p.evalRan.Store(true)
	time.Sleep(p.delay)
	// If Close() ran before Evaluate finished, the plugin is in an invalid state.
	if p.closed.Load() {
		panic("Evaluate called on closed plugin")
	}
	r := p.result
	return &r
}

func TestRegistry_CloseWaitsForInFlightEvaluate(t *testing.T) {
	reg := NewRegistry(NewPool(4, 5*time.Second))

	sp := &slowPlugin{
		name:   "slow",
		delay:  100 * time.Millisecond,
		result: Result{RuleName: "slow:block", Severity: rules.SeverityHigh, Message: "slow"},
	}
	reg.Register(sp, nil)

	// Start Evaluate in a goroutine — it will take 100ms.
	var wg sync.WaitGroup
	var result *Result
	wg.Go(func() {
		result = reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
	})

	// Give Evaluate a head start to acquire the RLock.
	time.Sleep(10 * time.Millisecond)

	// Close should block until Evaluate finishes (not close the plugin mid-evaluation).
	reg.Close()

	wg.Wait()

	if !sp.evalRan.Load() {
		t.Error("plugin Evaluate should have run")
	}
	// The key assertion: no panic from slowPlugin.Evaluate means Close waited.
	if result == nil {
		t.Error("expected non-nil result from slow plugin")
	}
}

// =============================================================================
// Bug: nil slices marshal as null instead of []
// =============================================================================

func TestRequest_NilSlicesMarshalAsEmptyArrays(t *testing.T) {
	req := Request{
		ToolName: "Bash",
		// All slice fields left nil.
	}
	data, err := json.Marshal(&req)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, field := range []string{"operations", "paths", "hosts", "rules"} {
		v, ok := raw[field]
		if !ok {
			t.Errorf("field %q missing from JSON", field)
			continue
		}
		if string(v) == "null" {
			t.Errorf("field %q is null, want [] (empty array)", field)
		}
	}
}

func TestRuleSnapshot_NilSlicesMarshalAsEmptyArrays(t *testing.T) {
	snap := RuleSnapshot{Name: "test"}
	data, err := json.Marshal(&snap)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var raw map[string]json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	for _, field := range []string{"actions", "block_paths", "block_except", "block_hosts"} {
		v, ok := raw[field]
		if !ok {
			t.Errorf("field %q missing from JSON", field)
			continue
		}
		if string(v) == "null" {
			t.Errorf("field %q is null, want [] (empty array)", field)
		}
	}
}

// =============================================================================
// Bug: Stats reads disableCycles twice non-atomically
// =============================================================================

func TestRegistry_StatsConsistency(t *testing.T) {
	pool := NewPool(4, 50*time.Millisecond)
	reg := NewRegistry(pool)
	defer reg.Close()

	reg.Register(&panicPlugin{name: "crasher"}, nil)
	ctx := t.Context()

	// Drive to exactly maxConsecutiveFailures to disable.
	for range maxConsecutiveFailures {
		reg.Evaluate(ctx, Request{ToolName: "Bash"})
	}

	stats := reg.Stats()
	if len(stats) == 0 {
		t.Fatal("expected stats")
	}
	s := stats[0]

	// Permanent must be consistent with DisableCycles.
	wantPermanent := s.DisableCycles >= maxDisableCycles
	if s.Permanent != wantPermanent {
		t.Errorf("Stats inconsistency: DisableCycles=%d, Permanent=%v (want %v)",
			s.DisableCycles, s.Permanent, wantPermanent)
	}
}

// =============================================================================
// Result.Validate tests
// =============================================================================

func TestResult_Validate(t *testing.T) {
	tests := []struct {
		name    string
		result  Result
		wantErr bool
	}{
		{
			name:    "valid result",
			result:  Result{RuleName: "test:rule", Message: "blocked"},
			wantErr: false,
		},
		{
			name:    "empty rule_name",
			result:  Result{RuleName: "", Message: "blocked"},
			wantErr: true,
		},
		{
			name:    "empty message",
			result:  Result{RuleName: "test:rule", Message: ""},
			wantErr: true,
		},
		{
			name:    "both empty",
			result:  Result{},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.result.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestRegistry_RejectsInvalidResult(t *testing.T) {
	tests := []struct {
		name   string
		result Result
	}{
		{
			name:   "empty rule_name",
			result: Result{RuleName: "", Severity: rules.SeverityHigh, Message: "blocked"},
		},
		{
			name:   "empty message",
			result: Result{RuleName: "test:rule", Severity: rules.SeverityHigh, Message: ""},
		},
		{
			name:   "both empty",
			result: Result{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reg := NewRegistry(NewPool(4, 5*time.Second))
			defer reg.Close()

			reg.Register(&blockPlugin{name: "invalid", result: tt.result}, nil)
			got := reg.Evaluate(t.Context(), Request{ToolName: "Bash"})
			if got != nil {
				t.Errorf("expected nil (invalid result discarded), got %+v", got)
			}
		})
	}
}

func TestDeepCopy_NormalizesRuleSnapshotInnerSlices(t *testing.T) {
	// RuleSnapshot inner slices should be normalized to empty after DeepCopy.
	req := Request{
		ToolName: "Bash",
		Rules: []RuleSnapshot{{
			Name: "test",
			// All inner slices nil
		}},
	}
	cp := req.DeepCopy()
	rs := cp.Rules[0]
	if rs.Actions == nil {
		t.Error("expected Actions to be non-nil after DeepCopy")
	}
	if rs.BlockPaths == nil {
		t.Error("expected BlockPaths to be non-nil after DeepCopy")
	}
	if rs.BlockExcept == nil {
		t.Error("expected BlockExcept to be non-nil after DeepCopy")
	}
	if rs.BlockHosts == nil {
		t.Error("expected BlockHosts to be non-nil after DeepCopy")
	}
}
