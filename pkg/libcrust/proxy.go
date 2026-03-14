//go:build libcrust

package libcrust

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/BakeLens/crust/internal/security"
	"github.com/BakeLens/crust/internal/types"
)

// proxyState holds the running proxy server state.
var proxy struct {
	mu       sync.Mutex
	server   *http.Server
	listener net.Listener
	upstream *url.URL
	apiKey   string
	apiType  types.APIType
}

// maxResponseBody is the maximum response body size we'll buffer for
// interception (16 MB). Responses larger than this are passed through
// unmodified to avoid excessive memory use on mobile devices.
const maxResponseBody = 16 << 20

// StartProxy starts a local reverse proxy on the given port.
//
// The proxy forwards requests to upstreamURL (e.g. "https://api.anthropic.com")
// and intercepts responses through the Crust rule engine.
//
// apiKey: optional API key injected into upstream requests.
// apiType: "anthropic", "openai", or "openai_responses".
//
// The AI SDK in the app should set its base URL to http://127.0.0.1:<port>.
//
// The rule engine must be initialized via Init() before calling StartProxy.
func StartProxy(port int, upstreamURL string, apiKey string, apiType string) error {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()

	if proxy.server != nil {
		return fmt.Errorf("proxy already running on %s", proxy.listener.Addr())
	}

	u, err := url.Parse(upstreamURL)
	if err != nil {
		return fmt.Errorf("invalid upstream URL: %w", err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("upstream URL must use http or https scheme, got %q", u.Scheme)
	}

	proxy.upstream = u
	proxy.apiKey = apiKey
	proxy.apiType = parseAPIType(apiType)

	addr := fmt.Sprintf("127.0.0.1:%d", port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	proxy.listener = ln

	mux := http.NewServeMux()
	mux.HandleFunc("/", proxyHandler)

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 30 * time.Second,
	}
	proxy.server = srv

	go func() {
		_ = srv.Serve(ln)
	}()

	return nil
}

// StopProxy shuts down the local proxy. Safe to call if not running.
func StopProxy() {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()

	if proxy.server == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = proxy.server.Shutdown(ctx)

	proxy.server = nil
	proxy.listener = nil
}

// ProxyAddress returns the listening address (e.g. "127.0.0.1:8080"),
// or empty string if the proxy is not running.
func ProxyAddress() string {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()

	if proxy.listener == nil {
		return ""
	}
	return proxy.listener.Addr().String()
}

// proxyHandler forwards requests to upstream and intercepts responses.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Build upstream URL: base URL + request path + query.
	target := *proxy.upstream
	target.Path = singleJoinSlash(target.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	// Read request body.
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxResponseBody))
	_ = r.Body.Close()
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadRequest)
		return
	}

	// Detect if streaming is requested.
	var reqBody struct {
		Stream bool `json:"stream"`
	}
	_ = json.Unmarshal(bodyBytes, &reqBody)

	// Detect API type from path if not configured.
	at := proxy.apiType
	if at == 0 {
		at = detectAPITypeFromPath(r.URL.Path)
	}

	// Build upstream request.
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// Copy headers, strip hop-by-hop.
	copyHeaders(upReq.Header, r.Header)
	stripHopByHop(upReq.Header)
	upReq.ContentLength = int64(len(bodyBytes))
	upReq.Host = target.Host

	// Inject auth.
	injectProxyAuth(upReq.Header, proxy.apiKey, at)

	// Send to upstream.
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			ResponseHeaderTimeout: 120 * time.Second,
		},
	}
	resp, err := client.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	if reqBody.Stream {
		// Force non-streaming: rewrite stream=false, re-send to upstream,
		// and intercept the complete response. This ensures all tool calls
		// and text content go through security evaluation.
		_ = resp.Body.Close()

		nonStreamBody := forceNonStreaming(bodyBytes)
		upReq2, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(nonStreamBody))
		if err != nil {
			http.Error(w, "failed to create non-streaming request", http.StatusInternalServerError)
			return
		}
		copyHeaders(upReq2.Header, r.Header)
		stripHopByHop(upReq2.Header)
		upReq2.ContentLength = int64(len(nonStreamBody))
		upReq2.Host = target.Host
		injectProxyAuth(upReq2.Header, proxy.apiKey, at)

		resp, err = client.Do(upReq2)
		if err != nil {
			http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()
	}

	// Read response, intercept, return.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// Decompress if needed for inspection.
	inspectBody := respBody
	encoding := resp.Header.Get("Content-Encoding")
	if encoding == "gzip" && len(respBody) > 2 {
		if decompressed, err := decompressGzip(respBody); err == nil {
			inspectBody = decompressed
		}
	}

	// Intercept tool calls in successful responses.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		mu.RLock()
		i := interceptor
		mu.RUnlock()

		if i != nil {
			result, err := i.InterceptToolCalls(inspectBody, security.InterceptionContext{
				APIType:   at,
				BlockMode: types.BlockModeRemove,
			})
			if err == nil && len(result.BlockedToolCalls) > 0 {
				// Use the modified response body.
				modified := result.ModifiedResponse

				// If the original was gzip'd, re-compress.
				if encoding == "gzip" {
					if compressed, err := compressGzip(modified); err == nil {
						modified = compressed
					}
				}

				respBody = modified
			}
		}
	}

	// Write response back to client.
	copyHeaders(w.Header(), resp.Header)
	// Update Content-Length since body may have changed.
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- reverse proxy forwarding JSON API responses, not rendering HTML
	_, _ = w.Write(respBody)
}

// detectAPITypeFromPath guesses API type from the request path.
func detectAPITypeFromPath(path string) types.APIType {
	if strings.Contains(path, "/v1/messages") {
		return types.APITypeAnthropic
	}
	if strings.Contains(path, "/v1/responses") || strings.HasSuffix(path, "/responses") {
		return types.APITypeOpenAIResponses
	}
	return types.APITypeOpenAICompletion
}

// injectProxyAuth sets authentication headers.
func injectProxyAuth(h http.Header, apiKey string, at types.APIType) {
	if apiKey == "" {
		return
	}
	// Don't override if client already sent auth.
	if h.Get("Authorization") != "" || h.Get("X-Api-Key") != "" {
		return
	}
	if at == types.APITypeAnthropic {
		h.Set("X-Api-Key", apiKey)
	} else {
		h.Set("Authorization", "Bearer "+apiKey)
	}
}

// copyHeaders copies headers from src to dst (without replacing existing).
func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// stripHopByHop removes hop-by-hop headers per RFC 7230.
func stripHopByHop(h http.Header) {
	for _, k := range []string{
		"Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailers",
		"Transfer-Encoding", "Upgrade",
	} {
		h.Del(k)
	}
}

// singleJoinSlash joins base and extra paths without doubling slashes.
func singleJoinSlash(base, extra string) string {
	baseSlash := strings.HasSuffix(base, "/")
	extraSlash := strings.HasPrefix(extra, "/")
	switch {
	case baseSlash && extraSlash:
		return base + extra[1:]
	case !baseSlash && !extraSlash:
		return base + "/" + extra
	}
	return base + extra
}

// forceNonStreaming returns a copy of the JSON body with "stream" set to false.
// Preserves all other fields byte-for-byte via json.RawMessage.
func forceNonStreaming(body []byte) []byte {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil || raw == nil {
		return body // best-effort: return unchanged on parse failure
	}
	raw["stream"] = json.RawMessage("false")
	// Also remove stream_options to avoid upstream errors.
	delete(raw, "stream_options")
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(raw); err != nil {
		return body
	}
	return bytes.TrimRight(buf.Bytes(), "\n")
}

// decompressGzip decompresses a gzip'd byte slice.
func decompressGzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer func() { _ = r.Close() }()
	return io.ReadAll(io.LimitReader(r, maxResponseBody))
}

// compressGzip compresses a byte slice with gzip.
func compressGzip(data []byte) ([]byte, error) {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(data); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// EvaluateStream intercepts a complete (non-streaming) LLM API response
// and returns a JSON result with blocked/allowed tool calls.
// This is a convenience wrapper around InterceptResponse for apps that
// handle their own HTTP but want Crust filtering.
//
// Deprecated: use InterceptResponse directly.
func EvaluateStream(responseBody string, apiType string) string {
	return InterceptResponse(responseBody, apiType, "remove")
}

// StreamInterceptionSupported returns true — streaming requests are
// transparently converted to non-streaming for full security evaluation.
func StreamInterceptionSupported() bool {
	return true
}
