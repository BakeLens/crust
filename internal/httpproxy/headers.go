package httpproxy

import (
	"net/http"

	"github.com/BakeLens/crust/internal/proxyutil"
)

// WarningBlockIndex is a high index value used for injected warning blocks
// to avoid conflicts with actual content block indices.
const WarningBlockIndex = 999

// IsHopByHop reports whether a header name is a hop-by-hop header.
func IsHopByHop(name string) bool {
	return proxyutil.IsHopByHop(name)
}

// copyHeaders delegates to the shared RFC 7230 compliant implementation.
func copyHeaders(dst, src http.Header) {
	proxyutil.CopyHeaders(dst, src)
}

// stripHopByHopHeaders delegates to the shared RFC 7230 compliant implementation.
func stripHopByHopHeaders(h http.Header) {
	proxyutil.StripHopByHopHeaders(h)
}
