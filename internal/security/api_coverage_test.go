//go:build unix

package security

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/telemetry"
	"github.com/BakeLens/crust/internal/types"
)

func TestAPIPrefixes(t *testing.T) {
	prefixes := APIPrefixes()
	if len(prefixes) != 3 {
		t.Fatalf("APIPrefixes() returned %d prefixes, want 3", len(prefixes))
	}

	want := []string{"/api/security/", "/api/telemetry/", "/api/crust/"}
	for i, got := range prefixes {
		if got != want[i] {
			t.Errorf("APIPrefixes()[%d] = %q, want %q", i, got, want[i])
		}
	}
}

func TestInitSSE(t *testing.T) {
	w := httptest.NewRecorder()
	ok := initSSE(w)
	if !ok {
		t.Fatal("initSSE returned false")
	}

	resp := w.Result()
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "text/event-stream")
	}
	if cc := resp.Header.Get("Cache-Control"); cc != "no-cache" {
		t.Errorf("Cache-Control = %q, want %q", cc, "no-cache")
	}
	if conn := resp.Header.Get("Connection"); conn != "keep-alive" {
		t.Errorf("Connection = %q, want %q", conn, "keep-alive")
	}

	body := w.Body.String()
	if !strings.HasPrefix(body, ":connected\n\n") {
		t.Errorf("body = %q, want prefix %q", body, ":connected\n\n")
	}
}

func TestSSEKeepalive(t *testing.T) {
	w := httptest.NewRecorder()
	ok := sseKeepalive(w)
	if !ok {
		t.Fatal("sseKeepalive returned false")
	}

	body := w.Body.String()
	if body != ":keepalive\n\n" {
		t.Errorf("body = %q, want %q", body, ":keepalive\n\n")
	}
}

func TestQueryInt(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		key        string
		defaultVal int
		maxVal     int
		want       int
	}{
		{"empty value returns default", "", "limit", 50, 200, 50},
		{"valid value", "limit=100", "limit", 50, 200, 100},
		{"invalid non-numeric", "limit=abc", "limit", 50, 200, 50},
		{"over max clamped", "limit=999", "limit", 50, 200, 200},
		{"zero returns default", "limit=0", "limit", 50, 200, 50},
		{"negative returns default", "limit=-5", "limit", 50, 200, 50},
		{"exactly max", "limit=200", "limit", 50, 200, 200},
		{"one", "limit=1", "limit", 50, 200, 1},
		{"missing key returns default", "other=10", "limit", 50, 200, 50},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/?"+tt.query, nil)
			got := queryInt(r, tt.key, tt.defaultVal, tt.maxVal)
			if got != tt.want {
				t.Errorf("queryInt() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestInterceptor_SetStorage(t *testing.T) {
	i := NewInterceptor(nil, nil)
	if s := i.GetStorage(); s != nil {
		t.Errorf("initial storage should be nil, got %v", s)
	}

	// Create a mock recorder.
	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	i.SetStorage(storage)
	if s := i.GetStorage(); s == nil {
		t.Error("storage should be non-nil after SetStorage")
	}

	// SetStorage with nil should be a no-op (keeps previous value).
	i.SetStorage(nil)
	if s := i.GetStorage(); s == nil {
		t.Error("storage should remain non-nil after SetStorage(nil)")
	}
}

func TestWithStorage_Option(t *testing.T) {
	storage, err := telemetry.NewStorage(":memory:", "")
	if err != nil {
		t.Fatalf("NewStorage: %v", err)
	}
	defer storage.Close()

	m := NewManager(nil, nil, types.BlockModeRemove, WithStorage(storage))
	defer m.Shutdown(t.Context())

	if m.GetStorage() == nil {
		t.Error("WithStorage option should set storage on manager")
	}
}

func TestWithRetention_Option(t *testing.T) {
	m := NewManager(nil, nil, types.BlockModeRemove, WithRetention(30))
	defer m.Shutdown(t.Context())

	if m.retentionDays != 30 {
		t.Errorf("retentionDays = %d, want 30", m.retentionDays)
	}
}

func TestWithBuffering_Option(t *testing.T) {
	m := NewManager(nil, nil, types.BlockModeRemove,
		WithBuffering(true, 100, 60),
	)
	defer m.Shutdown(t.Context())

	cfg := m.InterceptionCfg()
	if !cfg.BufferStreaming {
		t.Error("BufferStreaming should be true")
	}
	if cfg.MaxBufferEvents != 100 {
		t.Errorf("MaxBufferEvents = %d, want 100", cfg.MaxBufferEvents)
	}
	if cfg.BufferTimeout != 60 {
		t.Errorf("BufferTimeout = %d, want 60", cfg.BufferTimeout)
	}
}
