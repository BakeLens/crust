//go:build libcrust

package libcrust

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestInitAndEvaluate(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	if n := RuleCount(); n == 0 {
		t.Fatal("expected builtin rules to be loaded")
	}

	// Allowed tool call — reading a temp file
	result := Evaluate("read_file", `{"path":"/tmp/test.txt"}`)
	var m map[string]any
	if err := json.Unmarshal([]byte(result), &m); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if m["matched"] == true {
		t.Errorf("expected /tmp/test.txt to be allowed, got: %s", result)
	}

	// Blocked tool call — writing to /etc/crontab (builtin protect-persistence)
	result = Evaluate("write_file", `{"file_path":"/etc/crontab","content":"* * * * * evil"}`)
	if err := json.Unmarshal([]byte(result), &m); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if m["matched"] != true {
		t.Errorf("expected /etc/crontab write to be blocked, got: %s", result)
	}
}

func TestInitWithYAML(t *testing.T) {
	yaml := `
rules:
  - name: block-secrets
    message: Secret file access blocked
    actions: [read, write]
    block: "/etc/shadow"
`
	if err := InitWithYAML(yaml); err != nil {
		t.Fatalf("InitWithYAML failed: %v", err)
	}
	defer Shutdown()

	if n := RuleCount(); n == 0 {
		t.Fatal("expected rules to be loaded")
	}

	// Verify custom rule blocks /etc/shadow
	result := Evaluate("read_file", `{"path":"/etc/shadow"}`)
	var m map[string]any
	if err := json.Unmarshal([]byte(result), &m); err != nil {
		t.Fatalf("bad JSON: %v", err)
	}
	if m["matched"] != true {
		t.Errorf("expected /etc/shadow to be blocked, got: %s", result)
	}
}

func TestInterceptResponse(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Simple Anthropic response with a benign tool call
	body := `{"content":[{"type":"tool_use","id":"t1","name":"read_file","input":{"path":"/tmp/test.txt"}}]}`
	result := InterceptResponse(body, "anthropic", "remove")
	if !strings.Contains(result, "read_file") {
		t.Errorf("expected allowed tool call in output: %s", result)
	}
}

func TestEvaluateBeforeInit(t *testing.T) {
	Shutdown() // ensure clean state
	result := Evaluate("test", `{}`)
	if !strings.Contains(result, "not initialized") {
		t.Errorf("expected not-initialized error, got: %s", result)
	}
}

func TestValidateYAML(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Valid YAML
	valid := `
rules:
  - name: test-rule
    message: test
    actions: [read, write]
    block: "/secret/**"
`
	if msg := ValidateYAML(valid); msg != "" {
		t.Errorf("expected valid, got: %s", msg)
	}

	// Invalid YAML
	invalid := `not: valid: yaml: [`
	if msg := ValidateYAML(invalid); msg == "" {
		t.Error("expected error for invalid YAML")
	}
}

func TestGetVersion(t *testing.T) {
	v := GetVersion()
	if v == "" {
		t.Error("expected non-empty version")
	}
}

func TestDoubleInitClosesOldEngine(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("first Init failed: %v", err)
	}
	n1 := RuleCount()

	// Second init should succeed without leaking.
	if err := Init(""); err != nil {
		t.Fatalf("second Init failed: %v", err)
	}
	defer Shutdown()

	if n := RuleCount(); n != n1 {
		t.Errorf("rule count changed after re-init: %d vs %d", n, n1)
	}
}

func TestEvaluateMalformedJSON(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Should not panic on invalid JSON.
	result := Evaluate("read_file", "not{json")
	if result == "" {
		t.Error("expected non-empty result for malformed JSON")
	}
}

func TestRuleCountBeforeInit(t *testing.T) {
	Shutdown()
	if n := RuleCount(); n != 0 {
		t.Errorf("expected 0 rules before init, got %d", n)
	}
}

func TestValidateYAMLBeforeInit(t *testing.T) {
	Shutdown()
	msg := ValidateYAML("rules: []")
	if !strings.Contains(msg, "not initialized") {
		t.Errorf("expected not-initialized error, got: %s", msg)
	}
}

func TestInterceptResponseBeforeInit(t *testing.T) {
	Shutdown()
	body := `{"content":[]}`
	result := InterceptResponse(body, "anthropic", "remove")
	// Should return original body when not initialized.
	if result != body {
		t.Errorf("expected passthrough, got: %s", result)
	}
}

func TestConcurrentEvaluateAndShutdown(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}

	var wg sync.WaitGroup
	// Spawn concurrent evaluators.
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				Evaluate("read_file", `{"path":"/tmp/test.txt"}`)
			}
		}()
	}
	// Shutdown while evaluators are running.
	Shutdown()
	wg.Wait()
}

func TestStartStopProxy(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Start proxy on a random port.
	if err := StartProxy(0, "https://api.anthropic.com", "", "anthropic"); err != nil {
		t.Fatalf("StartProxy failed: %v", err)
	}
	defer StopProxy()

	addr := ProxyAddress()
	if addr == "" {
		t.Fatal("expected non-empty proxy address")
	}

	// Verify it's listening by connecting.
	resp, err := http.Get("http://" + addr + "/health-check-nonexistent")
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	_ = resp.Body.Close()
	// We expect a 502 (upstream unreachable) or similar, not a connection error.
}

func TestStartProxyDoubleStart(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	if err := StartProxy(0, "https://api.anthropic.com", "", "anthropic"); err != nil {
		t.Fatalf("StartProxy failed: %v", err)
	}
	defer StopProxy()

	// Second start should fail.
	if err := StartProxy(0, "https://api.openai.com", "", "openai"); err == nil {
		t.Error("expected error on double start")
	}
}

func TestStopProxyIdempotent(t *testing.T) {
	StopProxy() // should not panic when not running
	StopProxy() // second call should not panic either
}

func TestProxyAddressWhenNotRunning(t *testing.T) {
	StopProxy()
	if addr := ProxyAddress(); addr != "" {
		t.Errorf("expected empty address when proxy not running, got: %s", addr)
	}
}

func TestStartProxyInvalidURL(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	if err := StartProxy(0, "not-a-url", "", ""); err == nil {
		t.Error("expected error for invalid upstream URL")
	}
}

func TestStreamInterceptionSupported(t *testing.T) {
	if StreamInterceptionSupported() {
		t.Error("expected streaming interception to be unsupported for now")
	}
}

func TestProxyInterceptsBlockedToolCall(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Start a fake upstream that returns a response with a malicious tool call.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Anthropic response with a tool call that writes to /etc/crontab.
		resp := `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"write_file","input":{"file_path":"/etc/crontab","content":"* * * * * evil"}}]}`
		w.Write([]byte(resp))
	}))
	defer upstream.Close()

	if err := StartProxy(0, upstream.URL, "", "anthropic"); err != nil {
		t.Fatalf("StartProxy failed: %v", err)
	}
	defer StopProxy()

	// Send a request through the proxy.
	reqBody := `{"model":"claude-3","messages":[{"role":"user","content":"test"}]}`
	resp, err := http.Post(
		"http://"+ProxyAddress()+"/v1/messages",
		"application/json",
		strings.NewReader(reqBody),
	)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The malicious tool call should have been removed.
	if strings.Contains(string(body), "/etc/crontab") {
		t.Errorf("expected /etc/crontab tool call to be blocked, got: %s", string(body))
	}
}

func TestProxyPassesThroughAllowedToolCall(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	defer Shutdown()

	// Fake upstream returning a benign tool call.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"read_file","input":{"path":"/tmp/test.txt"}}]}`
		w.Write([]byte(resp))
	}))
	defer upstream.Close()

	if err := StartProxy(0, upstream.URL, "", "anthropic"); err != nil {
		t.Fatalf("StartProxy failed: %v", err)
	}
	defer StopProxy()

	reqBody := `{"model":"claude-3","messages":[{"role":"user","content":"test"}]}`
	resp, err := http.Post(
		"http://"+ProxyAddress()+"/v1/messages",
		"application/json",
		strings.NewReader(reqBody),
	)
	if err != nil {
		t.Fatalf("request through proxy failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The benign tool call should pass through.
	if !strings.Contains(string(body), "read_file") {
		t.Errorf("expected read_file tool call to pass through, got: %s", string(body))
	}
}

func TestShutdownIsIdempotent(t *testing.T) {
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	Shutdown()
	Shutdown() // second call should not panic
	Shutdown() // third call should not panic
}

func TestFullLifecycleUnderLoad(t *testing.T) {
	// Phase 1: Init with builtin rules
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	builtinCount := RuleCount()
	if builtinCount == 0 {
		t.Fatal("expected builtin rules")
	}

	// Phase 2: Concurrent evaluations while adding rules
	var wg sync.WaitGroup
	for range 5 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				Evaluate("read_file", `{"path":"/tmp/test.txt"}`)
			}
		}()
	}

	// Phase 3: Add custom rules mid-flight
	yaml := `
rules:
  - name: lifecycle-test-rule
    message: Lifecycle test
    actions: [write]
    block: "/tmp/lifecycle-blocked/**"
`
	if err := AddRulesYAML(yaml); err != nil {
		t.Fatalf("AddRulesYAML failed: %v", err)
	}

	wg.Wait()

	// Phase 4: Verify new rule is active
	if RuleCount() <= builtinCount {
		t.Errorf("expected more rules after AddRulesYAML: %d <= %d", RuleCount(), builtinCount)
	}
	result := Evaluate("write_file", `{"file_path":"/tmp/lifecycle-blocked/data.txt","content":"test"}`)
	if !strings.Contains(result, `"matched":true`) {
		t.Errorf("expected blocked, got: %s", result)
	}

	// Phase 5: Intercept a response
	body := `{"content":[{"type":"tool_use","id":"t1","name":"write_file","input":{"file_path":"/tmp/lifecycle-blocked/x","content":"y"}}]}`
	intercepted := InterceptResponse(body, "anthropic", "remove")
	if !strings.Contains(intercepted, "blocked") {
		t.Errorf("expected blocked in interception, got: %s", intercepted)
	}

	// Phase 6: Shutdown and reinit
	Shutdown()
	if RuleCount() != 0 {
		t.Error("expected 0 rules after shutdown")
	}

	if err := Init(""); err != nil {
		t.Fatalf("Re-init failed: %v", err)
	}
	defer Shutdown()

	// Custom rule should be gone after reinit
	result = Evaluate("write_file", `{"file_path":"/tmp/lifecycle-blocked/data.txt","content":"test"}`)
	if strings.Contains(result, `"matched":true`) {
		t.Error("custom rule should not persist after shutdown+reinit")
	}
}
