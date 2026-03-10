package dashboard

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// newTestServer returns an httptest.Server that handles management API routes.
func newTestServer(status any, stats any, sessions any, events any) *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("OK"))
	})
	mux.HandleFunc("/api/security/status", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(status)
	})
	mux.HandleFunc("/api/security/stats", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(stats)
	})
	mux.HandleFunc("/api/telemetry/sessions", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(sessions)
	})
	mux.HandleFunc("/api/telemetry/sessions/", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(events)
	})
	return httptest.NewServer(mux)
}

func TestFetchStatus(t *testing.T) {
	srv := newTestServer(
		map[string]any{"enabled": true, "rules_count": 21},
		SecurityStats{TotalToolCalls: 100, BlockedCalls: 5, AllowedCalls: 95},
		nil, nil,
	)
	defer srv.Close()

	tests := []struct {
		name   string
		client *http.Client
	}{
		{"server client", srv.Client()},
		{"plain client", &http.Client{}}, // same as remote TCP client
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := FetchStatus(tt.client, srv.URL, srv.URL, 42, "/tmp/test.log")

			if !data.Running {
				t.Error("expected Running=true")
			}
			if data.PID != 42 {
				t.Errorf("PID = %d, want 42", data.PID)
			}
			if !data.Healthy {
				t.Error("expected Healthy=true")
			}
			if !data.Enabled {
				t.Error("expected Enabled=true")
			}
			if data.RuleCount != 21 {
				t.Errorf("RuleCount = %d, want 21", data.RuleCount)
			}
			if data.Stats.TotalToolCalls != 100 {
				t.Errorf("TotalToolCalls = %d, want 100", data.Stats.TotalToolCalls)
			}
			if data.Stats.BlockedCalls != 5 {
				t.Errorf("BlockedCalls = %d, want 5", data.Stats.BlockedCalls)
			}
		})
	}
}

func TestFetchServerDown(t *testing.T) {
	client := &http.Client{}
	down := "http://127.0.0.1:1"

	t.Run("status", func(t *testing.T) {
		data := FetchStatus(client, down, down, 0, "")
		if data.Healthy || data.Enabled || data.RuleCount != 0 {
			t.Errorf("expected zero values, got %+v", data)
		}
	})
	t.Run("sessions", func(t *testing.T) {
		if result := FetchSessions(client, down); result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})
	t.Run("events", func(t *testing.T) {
		if result := FetchSessionEvents(client, down, "s1"); result != nil {
			t.Errorf("expected nil, got %v", result)
		}
	})
}

func TestFetchSessions(t *testing.T) {
	sessions := []SessionSummary{
		{SessionID: "s1", Model: "claude-3", TotalCalls: 10, BlockedCalls: 1},
		{SessionID: "s2", Model: "gpt-4", TotalCalls: 5, BlockedCalls: 0},
	}
	srv := newTestServer(nil, nil, sessions, nil)
	defer srv.Close()

	result := FetchSessions(&http.Client{}, srv.URL)
	if len(result) != 2 {
		t.Fatalf("got %d sessions, want 2", len(result))
	}
	if result[0].SessionID != "s1" {
		t.Errorf("sessions[0].SessionID = %q, want s1", result[0].SessionID)
	}
	if result[1].Model != "gpt-4" {
		t.Errorf("sessions[1].Model = %q, want gpt-4", result[1].Model)
	}
}

func TestFetchSessionEvents(t *testing.T) {
	events := []SessionEvent{
		{ToolName: "read_file", WasBlocked: false, Layer: "proxy_response"},
		{ToolName: "bash", WasBlocked: true, BlockedByRule: "block-rm-rf", Layer: "proxy_response"},
	}
	srv := newTestServer(nil, nil, nil, events)
	defer srv.Close()

	result := FetchSessionEvents(&http.Client{}, srv.URL, "s1")
	if len(result) != 2 {
		t.Fatalf("got %d events, want 2", len(result))
	}
	if result[0].ToolName != "read_file" {
		t.Errorf("events[0].ToolName = %q, want read_file", result[0].ToolName)
	}
	if !result[1].WasBlocked {
		t.Error("expected events[1].WasBlocked=true")
	}
	if result[1].BlockedByRule != "block-rm-rf" {
		t.Errorf("events[1].BlockedByRule = %q, want block-rm-rf", result[1].BlockedByRule)
	}
}

func TestRenderPlain(t *testing.T) {
	tests := []struct {
		name string
		data StatusData
		want []string
	}{
		{
			"running with stats",
			StatusData{
				Running: true, PID: 1234, Healthy: true, Enabled: true,
				RuleCount: 21, LogFile: "/tmp/crust.log",
				Stats: SecurityStats{TotalToolCalls: 100, BlockedCalls: 10, AllowedCalls: 90},
			},
			[]string{"PID 1234", "healthy", "enabled", "21 loaded", "10 tool calls", "/tmp/crust.log"},
		},
		{
			"not running",
			StatusData{Running: false},
			[]string{"not running"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out := RenderPlain(tt.data)
			for _, want := range tt.want {
				if !strings.Contains(out, want) {
					t.Errorf("RenderPlain missing %q in:\n%s", want, out)
				}
			}
		})
	}
}
