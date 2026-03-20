package httpproxy

import (
	"net/http"
	"strings"
	"testing"
)

func TestCopyHeaders_Basic(t *testing.T) {
	src := http.Header{
		"Content-Type":   []string{"application/json"},
		"Authorization":  []string{"Bearer token"},
		"X-Request-Id":   []string{"req-123"},
		"X-Multi-Values": []string{"val1", "val2"},
	}
	dst := http.Header{}

	copyHeaders(dst, src)

	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type not copied")
	}
	if dst.Get("Authorization") != "Bearer token" {
		t.Error("Authorization not copied")
	}
	if dst.Get("X-Request-Id") != "req-123" {
		t.Error("X-Request-Id not copied")
	}
	// Multi-valued header
	if vals := dst.Values("X-Multi-Values"); len(vals) != 2 || vals[0] != "val1" || vals[1] != "val2" {
		t.Errorf("Multi-valued header not copied correctly: %v", vals)
	}
}

func TestCopyHeaders_AllStaticHopByHop(t *testing.T) {
	src := http.Header{
		"Content-Type": []string{"application/json"},
	}
	// Add all static hop-by-hop headers
	for k := range hopByHopHeaders {
		src.Set(k, "should-be-stripped")
	}
	dst := http.Header{}

	copyHeaders(dst, src)

	for k := range hopByHopHeaders {
		if dst.Get(k) != "" {
			t.Errorf("hop-by-hop header %q leaked to dst", k)
		}
	}
	if dst.Get("Content-Type") != "application/json" {
		t.Error("non-hop-by-hop header not copied")
	}
}

func TestCopyHeaders_ConnectionListed(t *testing.T) {
	src := http.Header{
		"Connection":   []string{"keep-alive, X-Custom-Hop"},
		"X-Custom-Hop": []string{"should-be-stripped"},
		"X-Regular":    []string{"should-pass"},
	}
	dst := http.Header{}

	copyHeaders(dst, src)

	if dst.Get("X-Custom-Hop") != "" {
		t.Error("Connection-listed X-Custom-Hop leaked to dst")
	}
	if dst.Get("Connection") != "" {
		t.Error("Connection header leaked to dst")
	}
	if dst.Get("X-Regular") != "should-pass" {
		t.Error("non-Connection-listed header not copied")
	}
}

func TestCopyHeaders_MultipleConnectionValues(t *testing.T) {
	src := http.Header{
		"Connection":   []string{"keep-alive, X-Hop-A", "X-Hop-B"},
		"X-Hop-A":      []string{"a"},
		"X-Hop-B":      []string{"b"},
		"Content-Type": []string{"text/plain"},
	}
	dst := http.Header{}

	copyHeaders(dst, src)

	if dst.Get("X-Hop-A") != "" {
		t.Error("X-Hop-A (from first Connection value) leaked")
	}
	if dst.Get("X-Hop-B") != "" {
		t.Error("X-Hop-B (from second Connection value) leaked")
	}
	if dst.Get("Content-Type") != "text/plain" {
		t.Error("Content-Type not copied")
	}
}

func TestCopyHeaders_EmptyConnectionEntries(t *testing.T) {
	src := http.Header{
		"Connection":   []string{",,,"},
		"Content-Type": []string{"application/json"},
	}
	dst := http.Header{}

	copyHeaders(dst, src)

	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should pass through despite empty Connection entries")
	}
	if dst.Get("Connection") != "" {
		t.Error("Connection header leaked to dst")
	}
}

func TestStripHopByHopHeaders_Basic(t *testing.T) {
	h := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer token"},
		"Connection":    []string{"keep-alive"},
		"Keep-Alive":    []string{"timeout=5"},
		"Trailer":       []string{"X-Checksum"},
	}

	stripHopByHopHeaders(h)

	if h.Get("Connection") != "" {
		t.Error("Connection not stripped")
	}
	if h.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive not stripped")
	}
	if h.Get("Trailer") != "" {
		t.Error("Trailer not stripped")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should survive")
	}
	if h.Get("Authorization") != "Bearer token" {
		t.Error("Authorization should survive")
	}
}

func TestStripHopByHopHeaders_ConnectionListed(t *testing.T) {
	h := http.Header{
		"Connection":       []string{"keep-alive, X-Internal-Trace"},
		"X-Internal-Trace": []string{"trace-123"},
		"Content-Type":     []string{"application/json"},
	}

	stripHopByHopHeaders(h)

	if h.Get("X-Internal-Trace") != "" {
		t.Error("Connection-listed X-Internal-Trace not stripped")
	}
	if h.Get("Connection") != "" {
		t.Error("Connection not stripped")
	}
	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should survive")
	}
}

// --- Fuzz targets ---

func FuzzCopyHeaders(f *testing.F) {
	// Seeds: typical Connection values
	f.Add("keep-alive")
	f.Add("keep-alive, X-Custom-Hop")
	f.Add("X-A, X-B, X-C")
	f.Add(",,,")
	f.Add("")
	f.Add("keep-alive, , X-Custom, ")
	f.Add(strings.Repeat("X-Header, ", 100))

	f.Fuzz(func(t *testing.T, connValue string) {
		src := http.Header{
			"Connection":   []string{connValue},
			"Content-Type": []string{"application/json"},
			"X-Custom":     []string{"value"},
		}
		dst := http.Header{}

		// Must not panic
		copyHeaders(dst, src)

		// Connection must never appear in dst
		if dst.Get("Connection") != "" {
			t.Error("Connection leaked to dst")
		}

		// All static hop-by-hop must never appear
		for k := range hopByHopHeaders {
			if dst.Get(k) != "" {
				t.Errorf("hop-by-hop %q leaked to dst", k)
			}
		}
	})
}

func FuzzStripHopByHopHeaders(f *testing.F) {
	f.Add("keep-alive")
	f.Add("keep-alive, X-Custom")
	f.Add(",,,")
	f.Add("")
	f.Add(strings.Repeat("X-Hdr, ", 50))

	f.Fuzz(func(t *testing.T, connValue string) {
		h := http.Header{
			"Connection":   []string{connValue},
			"Content-Type": []string{"application/json"},
		}

		// Must not panic
		stripHopByHopHeaders(h)

		// All static hop-by-hop must be gone
		for k := range hopByHopHeaders {
			if h.Get(k) != "" {
				t.Errorf("hop-by-hop %q not stripped", k)
			}
		}
	})
}

// --- Benchmarks ---

func BenchmarkCopyHeaders(b *testing.B) {
	b.ReportAllocs()
	src := http.Header{
		"Content-Type":                []string{"application/json"},
		"Content-Length":              []string{"1234"},
		"X-Request-Id":                []string{"req-abc123"},
		"X-Trace-Id":                  []string{"trace-xyz"},
		"Cache-Control":               []string{"no-cache"},
		"Date":                        []string{"Wed, 19 Feb 2026 12:00:00 GMT"},
		"Server":                      []string{"nginx/1.24"},
		"Vary":                        []string{"Accept-Encoding"},
		"X-Ratelimit-Remaining":       []string{"99"},
		"Strict-Transport-Security":   []string{"max-age=31536000"},
		"Connection":                  []string{"keep-alive"},
		"Keep-Alive":                  []string{"timeout=5"},
		"Access-Control-Allow-Origin": []string{"*"},
		"X-Custom-A":                  []string{"a"},
		"X-Custom-B":                  []string{"b"},
	}

	for b.Loop() {
		dst := http.Header{}
		copyHeaders(dst, src)
	}
}

func BenchmarkStripHopByHopHeaders(b *testing.B) {
	b.ReportAllocs()
	base := http.Header{
		"Content-Type":  []string{"application/json"},
		"Authorization": []string{"Bearer token"},
		"Connection":    []string{"keep-alive, X-Internal"},
		"X-Internal":    []string{"debug"},
		"Keep-Alive":    []string{"timeout=5"},
		"Trailer":       []string{"X-Checksum"},
		"X-Api-Key":     []string{"key-123"},
		"Accept":        []string{"application/json"},
		"User-Agent":    []string{"go-http-client/2.0"},
		"Host":          []string{"api.example.com"},
	}

	for b.Loop() {
		// Clone to avoid mutating base
		h := base.Clone()
		stripHopByHopHeaders(h)
	}
}
