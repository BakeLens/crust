//go:build unix && !libcrust

package daemon

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/BakeLens/crust/internal/httpproxy"
	"github.com/BakeLens/crust/internal/rules"
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/types"
)

// shortTempDir creates a temp dir under /tmp to stay within the 103-byte
// Unix socket sun_path limit on macOS (t.TempDir() paths are too long).
func shortTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "crust-") //nolint:usetesting // socket path length
	if err != nil {
		t.Fatalf("shortTempDir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

type testDaemon struct {
	manager    *security.Manager
	proxyAddr  string
	socketPath string
}

func setupTestDaemon(t *testing.T) *testDaemon {
	t.Helper()

	tmpDir := shortTempDir(t)
	socketPath := filepath.Join(tmpDir, "t.sock")

	// Rules engine with builtin rules, empty user dir.
	rulesDir := filepath.Join(tmpDir, "rules")
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		t.Fatalf("mkdir rules: %v", err)
	}
	engine, err := rules.NewEngine(context.Background(), rules.EngineConfig{
		UserRulesDir: rulesDir,
		DisableDLP:   true, // not needed for lifecycle tests
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	// Security manager via Init.
	cfg := security.Config{
		DBPath:          ":memory:",
		SocketPath:      socketPath,
		SecurityEnabled: true,
		BlockMode:       types.BlockModeRemove,
		Engine:          engine,
	}
	mgr, err := security.Init(cfg)
	if err != nil {
		t.Fatalf("security.Init: %v", err)
	}

	// Mock upstream — echoes back a fixed JSON body.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_test","type":"message","role":"assistant","content":[{"type":"text","text":"hello from upstream"}]}`))
	}))
	t.Cleanup(upstream.Close)

	// Proxy handler.
	proxy, err := httpproxy.NewProxy(
		upstream.URL, "test-key", 30*time.Second,
		nil,   // no user providers
		false, // autoMode
		mgr.GetInterceptor(),
		mgr.InterceptionCfg(),
		nil, // no telemetry provider
	)
	if err != nil {
		t.Fatalf("NewProxy: %v", err)
	}

	// HTTP mux replicating server.go setup.
	mux := http.NewServeMux()
	mux.Handle("/", proxy)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})

	// Ephemeral TCP listener.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen tcp: %v", err)
	}
	srv := &http.Server{Handler: mux}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })

	td := &testDaemon{
		manager:    mgr,
		proxyAddr:  ln.Addr().String(),
		socketPath: socketPath,
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = mgr.Shutdown(ctx)
	})

	return td
}

func TestDaemonE2E(t *testing.T) {
	td := setupTestDaemon(t)

	t.Run("HealthCheck_ProxyPort", func(t *testing.T) {
		resp, err := http.Get("http://" + td.proxyAddr + "/health")
		if err != nil {
			t.Fatalf("GET /health: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "OK" {
			t.Fatalf("expected body %q, got %q", "OK", string(body))
		}
	})

	t.Run("HealthCheck_UnixSocket", func(t *testing.T) {
		client := &http.Client{
			Transport: security.APITransport(td.socketPath),
			Timeout:   5 * time.Second,
		}
		resp, err := client.Get("http://crust/health")
		if err != nil {
			t.Fatalf("GET /health via socket: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if string(body) != "OK" {
			t.Fatalf("expected body %q, got %q", "OK", string(body))
		}
	})

	t.Run("ProxyForwards_MockUpstream", func(t *testing.T) {
		reqBody := `{"model":"test-model","messages":[{"role":"user","content":"hi"}]}`
		resp, err := http.Post(
			"http://"+td.proxyAddr+"/v1/messages",
			"application/json",
			strings.NewReader(reqBody),
		)
		if err != nil {
			t.Fatalf("POST /v1/messages: %v", err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if !strings.Contains(string(body), "hello from upstream") {
			t.Fatalf("expected upstream response in body, got: %s", string(body))
		}
	})

	t.Run("GracefulShutdown_CleansSocket", func(t *testing.T) {
		// Verify socket exists before shutdown.
		if _, err := os.Stat(td.socketPath); err != nil {
			t.Fatalf("socket should exist before shutdown: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := td.manager.Shutdown(ctx); err != nil {
			t.Fatalf("Shutdown: %v", err)
		}

		// Socket file should be gone.
		if _, err := os.Stat(td.socketPath); !os.IsNotExist(err) {
			t.Fatalf("socket should be removed after shutdown, err=%v", err)
		}
	})
}
