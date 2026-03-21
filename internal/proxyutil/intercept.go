package proxyutil

import (
	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/types"
)

// InterceptResponse decompresses (if gzip), intercepts tool calls via the
// security interceptor, recompresses (if needed), and returns the modified body.
// Returns the original body unchanged if no interception is needed.
//
// Used by both daemon httpproxy and libcrust proxy for their non-streaming paths.
func InterceptResponse(body []byte, contentEncoding string, interceptor *security.Interceptor, ctx security.InterceptionContext) (modifiedBody []byte, blockedCount int) {
	if interceptor == nil {
		return body, 0
	}

	// Decompress for inspection if gzip-encoded.
	inspectBody := body
	isGzip := contentEncoding == "gzip" && len(body) > 2
	if isGzip {
		if decompressed, err := DecompressGzip(body); err == nil {
			inspectBody = decompressed
		} else {
			// Can't decompress — return original body.
			return body, 0
		}
	}

	// Intercept tool calls.
	result, err := interceptor.InterceptToolCalls(inspectBody, ctx)
	if err != nil || len(result.BlockedToolCalls) == 0 {
		return body, 0
	}

	// Use the modified response body.
	modified := result.ModifiedResponse

	// Re-compress if the original was gzip.
	if isGzip {
		if compressed, err := CompressGzip(modified); err == nil {
			modified = compressed
		}
	}

	return modified, len(result.BlockedToolCalls)
}

// DefaultInterceptionContext creates an InterceptionContext with common defaults.
func DefaultInterceptionContext(apiType types.APIType, blockMode types.BlockMode) security.InterceptionContext {
	return security.InterceptionContext{
		APIType:   apiType,
		BlockMode: blockMode,
	}
}
