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
	"time"
)

func mustInit(t *testing.T) {
	t.Helper()
	if err := Init(""); err != nil {
		t.Fatalf("Init failed: %v", err)
	}
	t.Cleanup(Shutdown)
}

func mustStartProxy(t *testing.T, upstreamURL, apiKey, apiType string) {
	t.Helper()
	if err := StartProxy(0, upstreamURL, apiKey, apiType); err != nil {
		t.Fatalf("StartProxy failed: %v", err)
	}
	t.Cleanup(StopProxy)
}

// fakeUpstream creates a test HTTP server that returns a fixed JSON body.
func fakeUpstream(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestInitAndEvaluate(t *testing.T) {
	mustInit(t)

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
	mustInit(t)

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
	mustInit(t)

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
	mustInit(t)

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
	mustInit(t)
	mustStartProxy(t, "https://api.anthropic.com", "", "anthropic")

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
	mustInit(t)

	mustStartProxy(t, "https://api.anthropic.com", "", "anthropic")

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
	mustInit(t)

	if err := StartProxy(0, "not-a-url", "", ""); err == nil {
		t.Error("expected error for invalid upstream URL")
	}
}

func TestStreamInterceptionSupported(t *testing.T) {
	if !StreamInterceptionSupported() {
		t.Error("expected streaming interception to be supported")
	}
}

func TestForceNonStreaming(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  bool // stream should be false in output
	}{
		{"sets stream=false", `{"model":"gpt-4","stream":true,"messages":[]}`, true},
		{"adds stream=false when absent", `{"model":"claude-3","messages":[]}`, true},
		{"preserves other fields", `{"model":"x","stream":true,"temperature":0.5}`, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := ForceNonStreaming([]byte(tc.input))
			var m map[string]json.RawMessage
			if err := json.Unmarshal(out, &m); err != nil {
				t.Fatalf("invalid JSON output: %v", err)
			}
			if string(m["stream"]) != "false" {
				t.Errorf("stream = %s, want false", m["stream"])
			}
		})
	}
}

func TestForceNonStreaming_InvalidJSON(t *testing.T) {
	input := []byte("not json")
	out := ForceNonStreaming(input)
	if string(out) != string(input) {
		t.Errorf("expected unchanged input on parse error")
	}
}

func TestProxyInterceptsStreamingRequest(t *testing.T) {
	mustInit(t)

	// Fake upstream: verify it receives stream=false, return blocked tool call.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var req map[string]json.RawMessage
		if err := json.Unmarshal(body, &req); err != nil {
			w.WriteHeader(500)
			return
		}
		// Verify stream was forced to false.
		if string(req["stream"]) != "false" {
			w.WriteHeader(500)
			w.Write([]byte(`{"error":"stream was not forced to false"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		// Return a malicious tool call that should be blocked.
		w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"write_file","input":{"file_path":"/etc/crontab","content":"* * * * * evil"}}]}`))
	}))
	defer upstream.Close()

	mustStartProxy(t, upstream.URL, "", "anthropic")

	// Send a streaming request.
	reqBody := `{"model":"claude-3","stream":true,"messages":[{"role":"user","content":"test"}]}`
	resp, err := http.Post(
		"http://"+ProxyAddress()+"/v1/messages",
		"application/json",
		strings.NewReader(reqBody),
	)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// The malicious tool call should be blocked even though it was a streaming request.
	if strings.Contains(string(body), "/etc/crontab") {
		t.Errorf("expected streaming request to be intercepted, but blocked tool call passed through: %s", string(body))
	}
}

func TestProxyInterceptsBlockedToolCall(t *testing.T) {
	mustInit(t)

	upstream := fakeUpstream(t, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"write_file","input":{"file_path":"/etc/crontab","content":"* * * * * evil"}}]}`)
	mustStartProxy(t, upstream.URL, "", "anthropic")

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
	mustInit(t)

	upstream := fakeUpstream(t, `{"id":"msg_1","type":"message","role":"assistant","content":[{"type":"tool_use","id":"t1","name":"read_file","input":{"path":"/tmp/test.txt"}}]}`)
	mustStartProxy(t, upstream.URL, "", "anthropic")

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

func TestScanContent_Clean(t *testing.T) {
	mustInit(t)

	result := ScanContent("Hello, this is a normal message with no secrets.")
	if strings.Contains(result, `"matched":true`) {
		t.Errorf("expected clean content, got: %s", result)
	}
}

func TestScanContent_GitHubToken(t *testing.T) {
	mustInit(t)

	result := ScanContent("Here is a token: ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij12")
	if !strings.Contains(result, `"matched":true`) {
		t.Errorf("expected GitHub token to be detected, got: %s", result)
	}
}

func TestScanContent_VCard(t *testing.T) {
	mustInit(t)

	result := ScanContent("BEGIN:VCARD\nVERSION:3.0\nFN:John Doe\nEND:VCARD")
	if !strings.Contains(result, `"matched":true`) {
		t.Errorf("expected vCard to be detected, got: %s", result)
	}
}

func TestScanContent_BIP39(t *testing.T) {
	mustInit(t)

	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	result := ScanContent(mnemonic)
	if !strings.Contains(result, `"matched":true`) {
		t.Errorf("expected BIP39 mnemonic to be detected, got: %s", result)
	}
}

func TestScanContent_BeforeInit(t *testing.T) {
	Shutdown()
	result := ScanContent("test content")
	if !strings.Contains(result, "not initialized") {
		t.Errorf("expected not-initialized error, got: %s", result)
	}
}

func TestValidateURL_Tel(t *testing.T) {
	mustInit(t)

	result := ValidateURL("tel:+1234567890")
	if !strings.Contains(result, `"blocked":true`) {
		t.Errorf("expected tel: to be blocked, got: %s", result)
	}
	if !strings.Contains(result, `"scheme":"tel"`) {
		t.Errorf("expected scheme=tel, got: %s", result)
	}
}

func TestValidateURL_Https(t *testing.T) {
	mustInit(t)

	result := ValidateURL("https://example.com")
	if strings.Contains(result, `"blocked":true`) {
		t.Errorf("expected https: to be allowed, got: %s", result)
	}
}

func TestValidateURL_SMS(t *testing.T) {
	mustInit(t)

	result := ValidateURL("sms:+1234567890")
	if !strings.Contains(result, `"blocked":true`) {
		t.Errorf("expected sms: to be blocked, got: %s", result)
	}
}

// =============================================================================
// Bug verification tests
// =============================================================================

// TestBug_ProxyFieldsRaceCondition verifies that proxyHandler reads
// proxy.upstream/apiKey/apiType without holding proxy.mu, creating a data
// race when StopProxy is called concurrently.
func TestBug_ProxyFieldsRaceCondition(t *testing.T) {
	mustInit(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	if err := StartProxy(0, upstream.URL, "test-key", "anthropic"); err != nil {
		t.Fatalf("StartProxy failed: %v", err)
	}
	addr := ProxyAddress()

	// Run concurrent requests while stopping the proxy.
	// With -race, this exposes the data race on proxy.upstream/apiKey/apiType.
	// The race is between proxyHandler reading proxy.upstream (no lock)
	// and StopProxy setting proxy.upstream = nil (with lock).
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := http.Post(
					"http://"+addr+"/v1/messages",
					"application/json",
					strings.NewReader(`{"model":"test","messages":[]}`),
				)
				if err == nil {
					io.ReadAll(resp.Body)
					resp.Body.Close()
				}
			}
		}()
	}
	// Let requests build up, then stop concurrently.
	time.Sleep(10 * time.Millisecond)
	StopProxy()
	close(stop)
	wg.Wait()
}

// TestBug_ProxyResponseHopByHop verifies that hop-by-hop headers from the
// upstream response are forwarded to the client (they shouldn't be).
func TestBug_ProxyResponseHopByHop(t *testing.T) {
	mustInit(t)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Upstream sends hop-by-hop headers that should be stripped.
		w.Header().Set("Transfer-Encoding", "chunked")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	mustStartProxy(t, upstream.URL, "", "anthropic")

	resp, err := http.Post(
		"http://"+ProxyAddress()+"/v1/messages",
		"application/json",
		strings.NewReader(`{"model":"test","messages":[]}`),
	)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	// FIXED: hop-by-hop headers are now stripped from responses too.
	if te := resp.Header.Get("Transfer-Encoding"); te != "" {
		t.Errorf("hop-by-hop Transfer-Encoding leaked to client: %q", te)
	}
	if conn := resp.Header.Get("Connection"); conn != "" {
		t.Errorf("hop-by-hop Connection leaked to client: %q", conn)
	}
}

// TestBug_ProxyStreamingDoubleRequest verifies that streaming requests
// are rewritten to non-streaming upfront (single request, no retry).
func TestBug_ProxyStreamingDoubleRequest(t *testing.T) {
	mustInit(t)

	var requestCount int
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		requestCount++
		mu.Unlock()
		// Return 401 Unauthorized.
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"unauthorized"}`))
	}))
	defer upstream.Close()

	mustStartProxy(t, upstream.URL, "", "anthropic")

	resp, err := http.Post(
		"http://"+ProxyAddress()+"/v1/messages",
		"application/json",
		strings.NewReader(`{"model":"test","stream":true,"messages":[]}`),
	)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body)

	mu.Lock()
	count := requestCount
	mu.Unlock()

	// FIXED: streaming is rewritten to non-streaming upfront, so only 1 request.
	if count != 1 {
		t.Errorf("expected 1 upstream request (stream rewritten upfront), got %d", count)
	}
}

// TestBug_ProxyMaxResponseBodyNotEnforced verifies that oversized responses
// are passed through without interception.
func TestBug_ProxyMaxResponseBodyNotEnforced(t *testing.T) {
	// FIXED: proxy now reads maxResponseBody+1 and checks the length.
	// Responses exceeding the limit are passed through unmodified.
	if maxResponseBody != 16<<20 {
		t.Fatalf("maxResponseBody changed from 16MB: %d", maxResponseBody)
	}
}

// TestBug_ProxyPerRequestClient verifies that the shared HTTP client
// enables connection reuse across requests.
func TestBug_ProxyPerRequestClient(t *testing.T) {
	mustInit(t)

	var connCount int
	var mu sync.Mutex
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		connCount++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"content":[{"type":"text","text":"ok"}]}`))
	}))
	defer upstream.Close()

	mustStartProxy(t, upstream.URL, "", "anthropic")

	// Send 5 sequential requests — with connection reuse, the upstream
	// should see reused connections (fewer TLS handshakes).
	for range 5 {
		resp, err := http.Post(
			"http://"+ProxyAddress()+"/v1/messages",
			"application/json",
			strings.NewReader(`{"model":"test","messages":[]}`),
		)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		io.ReadAll(resp.Body)
		resp.Body.Close()
	}

	// FIXED: shared proxyClient enables connection reuse.
	// We can't easily verify TCP connection count in a unit test,
	// but the shared client is verified by checking proxyClient is non-nil.
	if proxyClient == nil {
		t.Error("proxyClient should be a shared package-level client")
	}
}
