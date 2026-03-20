package mcpgateway

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const schemeHTTPS = "https"

// handleWebSocket proxies a WebSocket upgrade request to the upstream server.
// Origin validation is already performed by checkOrigin in ServeHTTP before
// this handler is called.
//
// The proxy operates at the TCP level: after completing the HTTP upgrade
// handshake with the upstream, it copies bytes bidirectionally. This avoids
// needing a WebSocket library and works with any WebSocket subprotocol.
func (g *HTTPGateway) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "WebSocket proxy requires hijack support", http.StatusInternalServerError)
		return
	}

	// Build upstream URL with ws(s) scheme.
	upURL := *g.upstream
	switch upURL.Scheme {
	case schemeHTTPS:
		upURL.Scheme = "wss"
	default:
		upURL.Scheme = "ws"
	}
	upURL.Path = singleJoiningSlash(upURL.Path, r.URL.Path)
	upURL.RawQuery = r.URL.RawQuery

	// Dial upstream (TLS for https/wss, plain TCP otherwise).
	upConn, err := dialUpstream(r.Context(), &upURL)
	if err != nil {
		log.Warn("WebSocket upstream dial failed: %v", err)
		http.Error(w, "Failed to connect to upstream", http.StatusBadGateway)
		return
	}

	// Forward the original HTTP upgrade request to upstream.
	upgradeReq := buildUpgradeRequest(&upURL, r)
	if err := upgradeReq.Write(upConn); err != nil {
		upConn.Close()
		log.Warn("WebSocket upstream write failed: %v", err)
		http.Error(w, "Failed to send upgrade to upstream", http.StatusBadGateway)
		return
	}

	// Read and validate the upstream response before hijacking the client.
	upBuf := bufio.NewReader(upConn)
	upResp, err := http.ReadResponse(upBuf, upgradeReq)
	if err != nil {
		upConn.Close()
		log.Warn("WebSocket upstream response read failed: %v", err)
		http.Error(w, "Failed to read upstream response", http.StatusBadGateway)
		return
	}
	defer upResp.Body.Close()

	if upResp.StatusCode != http.StatusSwitchingProtocols {
		upConn.Close()
		log.Warn("WebSocket upstream rejected upgrade: %d", upResp.StatusCode)
		http.Error(w, fmt.Sprintf("Upstream rejected WebSocket upgrade: %d", upResp.StatusCode), http.StatusBadGateway)
		return
	}

	// Hijack the client connection.
	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		upConn.Close()
		log.Warn("WebSocket hijack failed: %v", err)
		return
	}

	// Write the validated 101 response to the client.
	//nolint:errcheck // best-effort write to hijacked connection
	upResp.Write(clientConn)

	log.Info("WebSocket proxied to %s (origin validated)", upURL.Host)

	// Bidirectional copy — when either side closes, the other follows.
	// Each direction's io.Copy unblocks when the source connection is closed
	// by the other direction, preventing deadlocks.
	done := make(chan struct{})
	go func() {
		defer close(done)
		// upstream → client: flush any buffered data from response reader first.
		if upBuf.Buffered() > 0 {
			//nolint:errcheck // best-effort flush
			io.CopyN(clientConn, upBuf, int64(upBuf.Buffered()))
		}
		_, _ = io.Copy(clientConn, upConn)
		// Half-close client to unblock the other direction's io.Copy.
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite() //nolint:errcheck // best-effort half-close
		} else {
			clientConn.Close()
		}
	}()

	// client → upstream: flush any buffered data from the hijacked reader.
	if clientBuf.Reader.Buffered() > 0 {
		buffered := make([]byte, clientBuf.Reader.Buffered())
		//nolint:errcheck // best-effort flush of buffered data
		clientBuf.Read(buffered)
		//nolint:errcheck // best-effort write
		upConn.Write(buffered)
	}
	_, _ = io.Copy(upConn, clientConn)
	// Half-close upstream to unblock the goroutine's io.Copy.
	if tc, ok := upConn.(*net.TCPConn); ok {
		tc.CloseWrite() //nolint:errcheck // best-effort half-close
	} else {
		upConn.Close()
	}
	<-done

	// Ensure both connections are fully closed.
	clientConn.Close()
	upConn.Close()
}

// isWebSocketUpgrade checks if the request is a WebSocket upgrade.
func isWebSocketUpgrade(r *http.Request) bool {
	return strings.EqualFold(r.Header.Get("Upgrade"), "websocket") &&
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// buildUpgradeRequest creates an HTTP/1.1 upgrade request to send to the upstream.
// It copies relevant headers from the original client request.
func buildUpgradeRequest(upURL *url.URL, orig *http.Request) *http.Request {
	req := &http.Request{
		Method:     http.MethodGet,
		URL:        upURL,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Host:       upURL.Host,
	}

	// Copy WebSocket headers.
	for _, key := range []string{
		"Upgrade",
		"Connection",
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Version",
		"Sec-WebSocket-Protocol",
		"Sec-WebSocket-Extensions",
	} {
		if v := orig.Header.Get(key); v != "" {
			req.Header.Set(key, v)
		}
	}

	// Copy MCP session header if present.
	if sid := orig.Header.Get(sessionHeader); sid != "" {
		req.Header.Set(sessionHeader, sid)
	}

	return req
}

// dialUpstream connects to the upstream server, using TLS for wss/https.
func dialUpstream(ctx context.Context, u *url.URL) (net.Conn, error) {
	addr := hostPort(u)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	switch u.Scheme {
	case "wss", schemeHTTPS:
		return (&tls.Dialer{
			NetDialer: dialer,
			Config: &tls.Config{
				ServerName: u.Hostname(),
				MinVersion: tls.VersionTLS12,
			},
		}).DialContext(ctx, "tcp", addr)
	default:
		return dialer.DialContext(ctx, "tcp", addr)
	}
}

// hostPort extracts host:port from a URL, defaulting to :80 or :443.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	switch u.Scheme {
	case "wss", schemeHTTPS:
		return u.Hostname() + ":443"
	default:
		return u.Hostname() + ":80"
	}
}

// singleJoiningSlash joins base and suffix paths with exactly one slash.
func singleJoiningSlash(base, suffix string) string {
	baseSlash := strings.HasSuffix(base, "/")
	suffixSlash := strings.HasPrefix(suffix, "/")
	switch {
	case baseSlash && suffixSlash:
		return base + suffix[1:]
	case !baseSlash && !suffixSlash:
		return base + "/" + suffix
	}
	return base + suffix
}
