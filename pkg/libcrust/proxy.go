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

	"github.com/BakeLens/crust/internal/proxyutil"

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

// proxyClient is a shared HTTP client for upstream requests.
// Reusing the client enables TCP/TLS connection pooling.
var proxyClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 120 * time.Second,
		MaxIdleConns:          10,
		IdleConnTimeout:       90 * time.Second,
	},
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

	if upstreamURL != "" {
		u, err := url.Parse(upstreamURL)
		if err != nil {
			return fmt.Errorf("invalid upstream URL: %w", err)
		}
		if u.Scheme != "https" && u.Scheme != "http" {
			return fmt.Errorf("upstream URL must use http or https scheme, got %q", u.Scheme)
		}
		proxy.upstream = u
	} else {
		proxy.upstream = nil // auto mode
	}

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

// proxyConfig holds a snapshot of proxy configuration, taken under lock.
type proxyConfig struct {
	upstream *url.URL
	apiKey   string
	apiType  types.APIType
}

// snapshotProxyConfig reads proxy configuration under the lock.
// Returns nil if the proxy is not running at all.
func snapshotProxyConfig() *proxyConfig {
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if proxy.server == nil {
		return nil // proxy not running at all
	}
	if proxy.upstream != nil {
		// Copy the URL value so the caller doesn't share state.
		u := *proxy.upstream
		return &proxyConfig{upstream: &u, apiKey: proxy.apiKey, apiType: proxy.apiType}
	}
	return &proxyConfig{upstream: nil, apiKey: proxy.apiKey, apiType: proxy.apiType}
}

// proxyHandler forwards requests to upstream and intercepts responses.
func proxyHandler(w http.ResponseWriter, r *http.Request) {
	// Snapshot config under lock to avoid data races with StopProxy.
	cfg := snapshotProxyConfig()
	if cfg == nil {
		http.Error(w, "proxy not running", http.StatusServiceUnavailable)
		return
	}

	// Build upstream URL: fixed upstream or auto-resolve from request path.
	var target url.URL
	if cfg.upstream != nil {
		// Fixed upstream mode.
		target = *cfg.upstream
		target.Path = singleJoinSlash(target.Path, r.URL.Path)
		target.RawQuery = r.URL.RawQuery
	} else {
		// Auto mode: resolve upstream from request path.
		resolved := resolveUpstreamFromPath(r.URL.Path)
		if resolved == nil {
			http.Error(w, "cannot resolve upstream for path: "+r.URL.Path, http.StatusBadGateway)
			return
		}
		target = *resolved
		target.Path = singleJoinSlash(target.Path, r.URL.Path)
		target.RawQuery = r.URL.RawQuery
	}

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
	at := cfg.apiType
	if at == 0 {
		at = detectAPITypeFromPath(r.URL.Path)
	}

	// If streaming, force non-streaming upfront — no need to send the
	// streaming request first just to discard it.
	if reqBody.Stream {
		bodyBytes = proxyutil.ForceNonStreaming(bodyBytes)
	}

	// Build upstream request.
	upReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(bodyBytes))
	if err != nil {
		http.Error(w, "failed to create upstream request", http.StatusInternalServerError)
		return
	}

	// Copy headers, strip hop-by-hop.
	proxyutil.CopyHeaders(upReq.Header, r.Header)
	proxyutil.StripHopByHopHeaders(upReq.Header)
	upReq.ContentLength = int64(len(bodyBytes))
	upReq.Host = target.Host

	// Inject auth.
	injectProxyAuth(upReq.Header, cfg.apiKey, at)

	// Send to upstream (shared client for connection reuse).
	resp, err := proxyClient.Do(upReq)
	if err != nil {
		http.Error(w, fmt.Sprintf("upstream error: %v", err), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	// Read response, intercept, return.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		http.Error(w, "failed to read upstream response", http.StatusBadGateway)
		return
	}

	// If response exceeds maxResponseBody, pass through without interception
	// to avoid excessive memory use on mobile devices.
	oversized := len(respBody) > maxResponseBody

	// Decompress if needed for inspection.
	inspectBody := respBody
	encoding := resp.Header.Get("Content-Encoding")
	if !oversized && encoding == "gzip" && len(respBody) > 2 {
		if decompressed, err := decompressGzip(respBody); err == nil {
			inspectBody = decompressed
		}
	}

	// Intercept tool calls in successful, non-oversized responses.
	if !oversized && resp.StatusCode >= 200 && resp.StatusCode < 300 {
		i := getInterceptor()
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
	proxyutil.CopyHeaders(w.Header(), resp.Header)
	proxyutil.StripHopByHopHeaders(w.Header()) // strip hop-by-hop from response too
	// Update Content-Length since body may have changed.
	w.Header().Set("Content-Length", strconv.Itoa(len(respBody)))
	w.WriteHeader(resp.StatusCode)
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter -- reverse proxy forwarding JSON API responses, not rendering HTML
	_, _ = w.Write(respBody)
}

// detectAPITypeFromPath guesses API type from the request path.
// NOTE: Keep in sync with CrustURLProtocol.detectAPIType(from:) in CrustKit.swift.
func detectAPITypeFromPath(path string) types.APIType {
	if strings.Contains(path, "/v1/messages") {
		return types.APITypeAnthropic
	}
	if strings.Contains(path, "/v1/responses") || strings.HasSuffix(path, "/responses") {
		return types.APITypeOpenAIResponses
	}
	return types.APITypeOpenAICompletion
}

// resolveUpstreamFromPath determines the upstream API URL from the request path.
// It maps common AI API paths to their providers:
//
//	/v1/messages → Anthropic (api.anthropic.com)
//	/v1/chat/completions → OpenAI (api.openai.com)
//	/v1/responses → OpenAI (api.openai.com)
func resolveUpstreamFromPath(path string) *url.URL {
	var upstream string
	if strings.Contains(path, "/v1/messages") {
		upstream = "https://api.anthropic.com"
	} else if strings.Contains(path, "/v1/chat/completions") ||
		strings.Contains(path, "/v1/responses") ||
		strings.Contains(path, "/v1/embeddings") {
		upstream = "https://api.openai.com"
	} else {
		// Default to OpenAI for unknown paths.
		upstream = "https://api.openai.com"
	}
	u, err := url.Parse(upstream)
	if err != nil {
		return nil
	}
	return u
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
