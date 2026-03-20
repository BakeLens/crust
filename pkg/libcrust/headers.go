package libcrust

import (
	"net/http"
	"strings"
)

// hopByHopHeaders maps HTTP headers that must not be forwarded through a proxy
// per RFC 7230 §6.1. Immutable after init.
var hopByHopHeaders = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
	"Host":                true,
	"Origin":              true,
	"Referer":             true,
}

// IsHopByHop reports whether a header name is a hop-by-hop header
// that should not be forwarded through a proxy.
func IsHopByHop(name string) bool {
	return hopByHopHeaders[name]
}

// CopyHeaders copies response headers from src to dst, stripping hop-by-hop
// headers and any additional headers listed in the Connection header value
// per RFC 7230 §6.1.
func CopyHeaders(dst, src http.Header) {
	connHop := make(map[string]bool)
	for _, v := range src["Connection"] {
		for name := range strings.SplitSeq(v, ",") {
			connHop[http.CanonicalHeaderKey(strings.TrimSpace(name))] = true
		}
	}

	for key, values := range src {
		if hopByHopHeaders[key] || connHop[key] {
			continue
		}
		for _, value := range values {
			dst.Add(key, value)
		}
	}
}

// StripHopByHopHeaders removes hop-by-hop headers from outbound requests,
// including any additional headers listed in the Connection header value
// per RFC 7230 §6.1.
func StripHopByHopHeaders(h http.Header) {
	for _, v := range h["Connection"] {
		for name := range strings.SplitSeq(v, ",") {
			h.Del(strings.TrimSpace(name))
		}
	}
	for k := range hopByHopHeaders {
		h.Del(k)
	}
}
