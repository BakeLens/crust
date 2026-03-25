package mcpgateway

import (
	"bufio"
	"crypto/sha1"
	"encoding/base64"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/testutil"
)

// wsAcceptKey computes the Sec-WebSocket-Accept value per RFC 6455 §4.2.2.
func wsAcceptKey(key string) string {
	const magic = "258EAFA5-E914-47DA-95CA-5AB5DC76E5B3"
	h := sha1.New()
	h.Write([]byte(key + magic))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// newEchoWSUpstream creates a test HTTP server that accepts WebSocket upgrades
// and echoes all data back. It uses raw HTTP hijacking to avoid external deps.
func newEchoWSUpstream(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isWebSocketUpgrade(r) {
			http.Error(w, "not a websocket upgrade", http.StatusBadRequest)
			return
		}

		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack not supported", http.StatusInternalServerError)
			return
		}

		key := r.Header.Get("Sec-WebSocket-Key")
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		// Send upgrade response.
		resp := "HTTP/1.1 101 Switching Protocols\r\n" +
			"Upgrade: websocket\r\n" +
			"Connection: Upgrade\r\n" +
			"Sec-WebSocket-Accept: " + wsAcceptKey(key) + "\r\n\r\n"
		_, _ = conn.Write([]byte(resp))

		// Echo loop: read and write back raw bytes.
		b := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			n, err := buf.Read(b)
			if n > 0 {
				_, _ = conn.Write(b[:n])
			}
			if err != nil {
				return
			}
		}
	}))
}

func TestWebSocket_UpgradeProxied(t *testing.T) {
	upstream := newEchoWSUpstream(t)
	defer upstream.Close()

	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstream.URL, engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Start the gateway on a real listener (httptest.NewRecorder doesn't support Hijack).
	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	// Dial the gateway and send a WebSocket upgrade.
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gwSrv.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	wsKey := "dGhlIHNhbXBsZSBub25jZQ==" // test key from RFC 6455
	upgrade := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: " + wsKey + "\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	_, err = conn.Write([]byte(upgrade))
	if err != nil {
		t.Fatal(err)
	}

	// Read the upgrade response.
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading upgrade response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}
	if !strings.EqualFold(resp.Header.Get("Upgrade"), "websocket") {
		t.Errorf("missing Upgrade: websocket header")
	}

	accept := resp.Header.Get("Sec-WebSocket-Accept")
	if accept != wsAcceptKey(wsKey) {
		t.Errorf("Sec-WebSocket-Accept = %q, want %q", accept, wsAcceptKey(wsKey))
	}
}

func TestWebSocket_CrossOriginBlocked(t *testing.T) {
	upstream := newEchoWSUpstream(t)
	defer upstream.Close()

	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstream.URL, engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gwSrv.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send upgrade with cross-origin header — should be blocked.
	upgrade := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Origin: https://evil.com\r\n\r\n"
	_, err = conn.Write([]byte(upgrade))
	if err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin WebSocket: status = %d, want 403", resp.StatusCode)
	}
}

func TestWebSocket_LocalhostOriginAllowed(t *testing.T) {
	upstream := newEchoWSUpstream(t)
	defer upstream.Close()

	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstream.URL, engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gwSrv.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Send upgrade with localhost origin — should be allowed.
	upgrade := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Origin: http://localhost:3000\r\n\r\n"
	_, err = conn.Write([]byte(upgrade))
	if err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Errorf("localhost origin WebSocket: status = %d, want 101", resp.StatusCode)
	}
}

func TestWebSocket_DNSRebindingBlocked(t *testing.T) {
	upstream := newEchoWSUpstream(t)
	defer upstream.Close()

	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstream.URL, engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gwSrv.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// DNS rebinding attack via nip.io.
	upgrade := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Origin: http://127.0.0.1.nip.io\r\n\r\n"
	_, err = conn.Write([]byte(upgrade))
	if err != nil {
		t.Fatal(err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("DNS rebinding WebSocket: status = %d, want 403", resp.StatusCode)
	}
}

func TestWebSocket_DataEcho(t *testing.T) {
	upstream := newEchoWSUpstream(t)
	defer upstream.Close()

	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstream.URL, engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gwSrv.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	// Complete WebSocket upgrade.
	upgrade := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	_, _ = conn.Write([]byte(upgrade))

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("upgrade response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status = %d, want 101", resp.StatusCode)
	}

	// Send raw bytes and verify they echo back.
	payload := []byte("hello websocket proxy")
	_, err = conn.Write(payload)
	if err != nil {
		t.Fatalf("write payload: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, len(payload))
	n, err := io.ReadFull(reader, buf)
	if err != nil {
		t.Fatalf("read echo: %v (got %d bytes)", err, n)
	}
	if string(buf) != string(payload) {
		t.Errorf("echo = %q, want %q", buf, payload)
	}
}

func TestWebSocket_UpstreamUnreachable(t *testing.T) {
	// Point gateway at a port that is not listening.
	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway("http://127.0.0.1:1", engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gwSrv.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	upgrade := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	_, _ = conn.Write([]byte(upgrade))

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("upstream unreachable: status = %d, want 502", resp.StatusCode)
	}
}

func TestWebSocket_UpstreamRejectsUpgrade(t *testing.T) {
	// Upstream that returns 403 instead of 101.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forbidden", http.StatusForbidden)
	}))
	defer upstream.Close()

	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstream.URL, engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()

	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(gwSrv.URL, "http://"), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	upgrade := "GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n\r\n"
	_, _ = conn.Write([]byte(upgrade))

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		t.Fatalf("reading response: %v", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusBadGateway {
		t.Errorf("upstream rejected: status = %d, want 502", resp.StatusCode)
	}
}

// --- E2E Tests ---
// These use real listeners and full HTTP stack (not httptest.NewRecorder).
// Skipped with -short.

// dialAndUpgrade connects to addr, sends a WebSocket upgrade with optional
// headers, and returns the connection, response, and buffered reader.
func dialAndUpgrade(t *testing.T, addr string, extraHeaders map[string]string) (net.Conn, *http.Response) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}

	var upgrade strings.Builder
	upgrade.WriteString("GET / HTTP/1.1\r\n" +
		"Host: localhost\r\n" +
		"Upgrade: websocket\r\n" +
		"Connection: Upgrade\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n")
	for k, v := range extraHeaders {
		upgrade.WriteString(k + ": " + v + "\r\n")
	}
	upgrade.WriteString("\r\n")
	_, err = conn.Write([]byte(upgrade.String()))
	if err != nil {
		conn.Close()
		t.Fatalf("write upgrade: %v", err)
	}

	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		conn.Close()
		t.Fatalf("read response: %v", err)
	}
	return conn, resp
}

// TestWebSocketE2E_BrowserHijackDefense simulates the CVE-2026-25253 attack:
// a malicious website tries to hijack a local WebSocket server via the browser.
// Crust should block cross-origin connections while allowing legitimate ones.
func TestWebSocketE2E_BrowserHijackDefense(t *testing.T) {
	if testing.Short() {
		t.Skip("E2E: skipped in -short mode")
	}

	upstream := newEchoWSUpstream(t)
	defer upstream.Close()

	engine := testutil.NewEngine(t)
	gw, err := NewHTTPGateway(upstream.URL, engine, nil)
	if err != nil {
		t.Fatal(err)
	}

	gwSrv := httptest.NewServer(gw)
	defer gwSrv.Close()
	addr := strings.TrimPrefix(gwSrv.URL, "http://")

	// 1. Attacker: browser JS from evil.com opens ws://localhost — BLOCKED
	t.Run("attacker_cross_origin", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin": "https://evil.com",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker cross-origin: status = %d, want 403", resp.StatusCode)
		}
	})

	// 2. Attacker: Sec-Fetch-Site: cross-site (unforgeable browser signal) — BLOCKED
	t.Run("attacker_sec_fetch_site", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin":         "http://localhost:3000",
			"Sec-Fetch-Site": "cross-site",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker sec-fetch-site: status = %d, want 403", resp.StatusCode)
		}
	})

	// 3. Attacker: DNS rebinding via nip.io — BLOCKED
	t.Run("attacker_dns_rebinding", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin": "http://127.0.0.1.nip.io:3000",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker dns rebinding: status = %d, want 403", resp.StatusCode)
		}
	})

	// 4. Attacker: null origin (sandboxed iframe) — BLOCKED
	t.Run("attacker_null_origin", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin": "null",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker null origin: status = %d, want 403", resp.StatusCode)
		}
	})

	// 5. Attacker: gatewayUrl redirect — browser with Referer but no Origin — BLOCKED
	t.Run("attacker_referer_only", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Referer": "https://evil.com/exploit?gatewayUrl=ws://localhost:3000",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker referer: status = %d, want 403", resp.StatusCode)
		}
	})

	// 6. Attacker: sslip.io DNS rebinding variant — BLOCKED
	t.Run("attacker_sslip_rebinding", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin": "http://127.0.0.1.sslip.io",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker sslip.io: status = %d, want 403", resp.StatusCode)
		}
	})

	// 7. Attacker: localtest.me DNS rebinding variant — BLOCKED
	t.Run("attacker_localtest_rebinding", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin": "http://localtest.me:3000",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker localtest.me: status = %d, want 403", resp.StatusCode)
		}
	})

	// 8. Attacker: lvh.me DNS rebinding variant — BLOCKED
	t.Run("attacker_lvh_rebinding", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin": "http://lvh.me:3000",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("attacker lvh.me: status = %d, want 403", resp.StatusCode)
		}
	})

	// 9. Legitimate: SDK client (no Origin) — ALLOWED + multi-round data
	t.Run("legitimate_sdk_client", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, nil)
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("SDK client: status = %d, want 101", resp.StatusCode)
		}

		// Verify bidirectional data flow with multiple rounds.
		for i, msg := range []string{"init", "tool_call", "shutdown"} {
			_, err := conn.Write([]byte(msg))
			if err != nil {
				t.Fatalf("round %d write: %v", i, err)
			}
			conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, len(msg))
			_, err = io.ReadFull(bufio.NewReader(conn), buf)
			if err != nil {
				t.Fatalf("round %d read: %v", i, err)
			}
			if string(buf) != msg {
				t.Errorf("round %d: echo = %q, want %q", i, buf, msg)
			}
		}
	})

	// 10. Legitimate: localhost origin (Control UI) — ALLOWED + data flows
	t.Run("legitimate_localhost_ui", func(t *testing.T) {
		conn, resp := dialAndUpgrade(t, addr, map[string]string{
			"Origin": "http://localhost:8080",
		})
		defer conn.Close()
		resp.Body.Close()
		if resp.StatusCode != http.StatusSwitchingProtocols {
			t.Fatalf("localhost UI: status = %d, want 101", resp.StatusCode)
		}

		payload := []byte("authenticated_command")
		_, err := conn.Write(payload)
		if err != nil {
			t.Fatalf("write: %v", err)
		}
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, len(payload))
		_, err = io.ReadFull(bufio.NewReader(conn), buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if string(buf) != string(payload) {
			t.Errorf("echo = %q, want %q", buf, payload)
		}
	})
}

func TestIsWebSocketUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		upgrade    string
		connection string
		want       bool
	}{
		{"valid", "websocket", "Upgrade", true},
		{"case insensitive", "WebSocket", "upgrade", true},
		{"keep-alive,upgrade", "websocket", "keep-alive, Upgrade", true},
		{"no upgrade header", "", "Upgrade", false},
		{"no connection header", "websocket", "", false},
		{"wrong upgrade", "h2c", "Upgrade", false},
		{"empty", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			if tt.upgrade != "" {
				r.Header.Set("Upgrade", tt.upgrade)
			}
			if tt.connection != "" {
				r.Header.Set("Connection", tt.connection)
			}
			if got := isWebSocketUpgrade(r); got != tt.want {
				t.Errorf("isWebSocketUpgrade() = %v, want %v", got, tt.want)
			}
		})
	}
}
