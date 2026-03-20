package proxyutil

import (
	"net/http"
	"testing"
)

func TestIsHopByHop(t *testing.T) {
	hopHeaders := []string{
		"Connection",
		"Keep-Alive",
		"Proxy-Authenticate",
		"Proxy-Authorization",
		"Te",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Host",
		"Origin",
		"Referer",
	}
	for _, h := range hopHeaders {
		if !IsHopByHop(h) {
			t.Errorf("IsHopByHop(%q) = false, want true", h)
		}
	}

	nonHop := []string{
		"Content-Type",
		"Accept",
		"Authorization",
		"X-Custom-Header",
		"Cache-Control",
		"",
	}
	for _, h := range nonHop {
		if IsHopByHop(h) {
			t.Errorf("IsHopByHop(%q) = true, want false", h)
		}
	}
}

func TestIsHopByHop_CaseSensitive(t *testing.T) {
	// The map uses canonical header names; non-canonical should return false.
	if IsHopByHop("connection") {
		t.Error("IsHopByHop(\"connection\") should be false (not canonical)")
	}
	if IsHopByHop("KEEP-ALIVE") {
		t.Error("IsHopByHop(\"KEEP-ALIVE\") should be false (not canonical)")
	}
}

func TestCopyHeaders_Basic(t *testing.T) {
	src := http.Header{
		"Content-Type":   {"application/json"},
		"X-Request-Id":   {"abc123"},
		"Accept-Charset": {"utf-8"},
	}
	dst := make(http.Header)
	CopyHeaders(dst, src)

	for key, vals := range src {
		got := dst.Values(key)
		if len(got) != len(vals) {
			t.Fatalf("key %q: got %d values, want %d", key, len(got), len(vals))
		}
		for i, v := range vals {
			if got[i] != v {
				t.Errorf("key %q[%d]: got %q, want %q", key, i, got[i], v)
			}
		}
	}
}

func TestCopyHeaders_StripsHopByHop(t *testing.T) {
	src := http.Header{
		"Content-Type":      {"application/json"},
		"Connection":        {"keep-alive"},
		"Keep-Alive":        {"timeout=5"},
		"Transfer-Encoding": {"chunked"},
		"Upgrade":           {"websocket"},
		"Host":              {"example.com"},
		"Origin":            {"https://example.com"},
		"Referer":           {"https://example.com/page"},
	}
	dst := make(http.Header)
	CopyHeaders(dst, src)

	if dst.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be copied")
	}
	for _, h := range []string{"Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade", "Host", "Origin", "Referer"} {
		if dst.Get(h) != "" {
			t.Errorf("hop-by-hop header %q should not be copied", h)
		}
	}
}

func TestCopyHeaders_StripsConnectionListed(t *testing.T) {
	src := http.Header{
		"Connection":   {"X-Custom-Hop, X-Another"},
		"X-Custom-Hop": {"val1"},
		"X-Another":    {"val2"},
		"X-Keep-This":  {"val3"},
		"Content-Type": {"text/plain"},
	}
	dst := make(http.Header)
	CopyHeaders(dst, src)

	if dst.Get("X-Custom-Hop") != "" {
		t.Error("X-Custom-Hop listed in Connection should not be copied")
	}
	if dst.Get("X-Another") != "" {
		t.Error("X-Another listed in Connection should not be copied")
	}
	if dst.Get("X-Keep-This") != "val3" {
		t.Error("X-Keep-This should be copied")
	}
	if dst.Get("Content-Type") != "text/plain" {
		t.Error("Content-Type should be copied")
	}
}

func TestCopyHeaders_MultipleConnectionValues(t *testing.T) {
	src := http.Header{
		"Connection": {"X-Foo", "X-Bar, X-Baz"},
		"X-Foo":      {"f"},
		"X-Bar":      {"b"},
		"X-Baz":      {"z"},
		"X-Normal":   {"n"},
	}
	dst := make(http.Header)
	CopyHeaders(dst, src)

	for _, h := range []string{"X-Foo", "X-Bar", "X-Baz"} {
		if dst.Get(h) != "" {
			t.Errorf("%q listed across Connection values should not be copied", h)
		}
	}
	if dst.Get("X-Normal") != "n" {
		t.Error("X-Normal should be copied")
	}
}

func TestCopyHeaders_EmptyHeaders(t *testing.T) {
	dst := make(http.Header)
	CopyHeaders(dst, http.Header{})
	if len(dst) != 0 {
		t.Error("copying empty headers should produce empty dst")
	}
}

func TestCopyHeaders_MultipleValues(t *testing.T) {
	src := http.Header{
		"Accept": {"text/html", "application/json"},
	}
	dst := make(http.Header)
	CopyHeaders(dst, src)

	got := dst.Values("Accept")
	if len(got) != 2 {
		t.Fatalf("expected 2 Accept values, got %d", len(got))
	}
	if got[0] != "text/html" || got[1] != "application/json" {
		t.Errorf("Accept values = %v, want [text/html application/json]", got)
	}
}

func TestStripHopByHopHeaders_Basic(t *testing.T) {
	h := http.Header{
		"Content-Type":        {"application/json"},
		"Connection":          {"keep-alive"},
		"Keep-Alive":          {"timeout=5"},
		"Proxy-Authenticate":  {"Basic"},
		"Proxy-Authorization": {"Bearer tok"},
		"Te":                  {"trailers"},
		"Trailer":             {"X-Checksum"},
		"Transfer-Encoding":   {"chunked"},
		"Upgrade":             {"websocket"},
		"Host":                {"example.com"},
		"Origin":              {"https://example.com"},
		"Referer":             {"https://example.com/page"},
	}
	StripHopByHopHeaders(h)

	if h.Get("Content-Type") != "application/json" {
		t.Error("Content-Type should be preserved")
	}
	for _, name := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization",
		"Te", "Trailer", "Transfer-Encoding", "Upgrade", "Host", "Origin", "Referer",
	} {
		if h.Get(name) != "" {
			t.Errorf("hop-by-hop header %q should be stripped", name)
		}
	}
}

func TestStripHopByHopHeaders_ConnectionListed(t *testing.T) {
	h := http.Header{
		"Connection": {"X-Custom, X-Other"},
		"X-Custom":   {"val1"},
		"X-Other":    {"val2"},
		"X-Keep":     {"val3"},
	}
	StripHopByHopHeaders(h)

	if h.Get("X-Custom") != "" {
		t.Error("X-Custom listed in Connection should be stripped")
	}
	if h.Get("X-Other") != "" {
		t.Error("X-Other listed in Connection should be stripped")
	}
	if h.Get("X-Keep") != "val3" {
		t.Error("X-Keep should be preserved")
	}
}

func TestStripHopByHopHeaders_MultipleConnectionValues(t *testing.T) {
	h := http.Header{
		"Connection": {"X-A", "X-B, X-C"},
		"X-A":        {"a"},
		"X-B":        {"b"},
		"X-C":        {"c"},
		"X-D":        {"d"},
	}
	StripHopByHopHeaders(h)

	for _, name := range []string{"X-A", "X-B", "X-C", "Connection"} {
		if h.Get(name) != "" {
			t.Errorf("%q should be stripped", name)
		}
	}
	if h.Get("X-D") != "d" {
		t.Error("X-D should be preserved")
	}
}

func TestStripHopByHopHeaders_EmptyHeaders(t *testing.T) {
	h := make(http.Header)
	StripHopByHopHeaders(h) // should not panic
	if len(h) != 0 {
		t.Error("stripping empty headers should leave them empty")
	}
}

func TestStripHopByHopHeaders_NoConnectionHeader(t *testing.T) {
	h := http.Header{
		"Content-Type":      {"text/plain"},
		"Keep-Alive":        {"timeout=5"},
		"Transfer-Encoding": {"chunked"},
	}
	StripHopByHopHeaders(h)

	if h.Get("Content-Type") != "text/plain" {
		t.Error("Content-Type should be preserved")
	}
	if h.Get("Keep-Alive") != "" {
		t.Error("Keep-Alive should be stripped")
	}
	if h.Get("Transfer-Encoding") != "" {
		t.Error("Transfer-Encoding should be stripped")
	}
}
