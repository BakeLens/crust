package mcpgateway

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

// localhostPattern matches legitimate localhost addresses.
// Covers: localhost, 127.0.0.0/8, [::1], 0.0.0.0.
var localhostPattern = regexp.MustCompile(
	`^(?i:localhost|` +
		`127(?:\.\d{1,3}){3}|` + // 127.0.0.0/8
		`\[?::1\]?|` + // IPv6 loopback
		`0\.0\.0\.0)$`) // all-interfaces

// rebindingPattern matches DNS rebinding domains that resolve to loopback.
// Built from rules.RebindingSuffixes and rules.RebindingExact (single source of truth).
var rebindingPattern = buildRebindingPattern()

func buildRebindingPattern() *regexp.Regexp {
	// Wildcard DNS suffixes: \.(?:nip|sslip|xip)\.io
	var suffixCores []string
	for _, s := range rules.RebindingSuffixes {
		core := strings.TrimPrefix(s, ".")
		core = strings.TrimSuffix(core, ".io")
		suffixCores = append(suffixCores, regexp.QuoteMeta(core))
	}
	wildcard := `\.(?:` + strings.Join(suffixCores, "|") + `)\.io`

	// Exact domains: (?:localtest|lvh|vcap)\.me|lacolhost\.com
	var exactParts []string
	for domain := range rules.RebindingExact {
		exactParts = append(exactParts, regexp.QuoteMeta(domain))
	}

	return regexp.MustCompile(`(?i)(?:` + wildcard + `|` + strings.Join(exactParts, "|") + `)$`)
}

// checkOrigin rejects cross-origin browser requests (CSRF protection).
//
// Policy:
//   - No Origin header (and no Referer) → ALLOW (non-browser: MCP SDK, curl, CLI)
//   - Sec-Fetch-Site == "cross-site"    → BLOCK (unforgeable browser signal)
//   - Origin is localhost               → ALLOW
//   - Malformed Referer fallback        → BLOCK (fail-closed)
//   - Origin is "null"                  → BLOCK (privacy redirect, no legitimate MCP use)
//   - Origin is non-localhost           → BLOCK (browser CSRF)
//
// This implements the MCP spec requirement: "Servers MUST validate the Origin
// header on all incoming connections to prevent DNS rebinding attacks."
func checkOrigin(r *http.Request) error {
	// Sec-Fetch-Site is set by the browser and cannot be spoofed by JS.
	// If present and cross-site, block immediately.
	if sfs := r.Header.Get("Sec-Fetch-Site"); strings.EqualFold(sfs, "cross-site") {
		return errors.New(
			"[Crust] Blocked: a website tried to access your MCP server from a different origin. " +
				"This is a cross-site request, which could be an attack (see CVE-2025-49596). " +
				"Only requests from your own machine are allowed")
	}

	origin := r.Header.Get("Origin")

	// Fall back to Referer if Origin is absent.
	if origin == "" {
		referer := r.Header.Get("Referer")
		if referer == "" {
			// No origin signals at all — non-browser client (SDK, curl).
			return nil
		}
		// Extract origin from Referer URL.
		if u, err := url.Parse(referer); err == nil {
			origin = u.Scheme + "://" + u.Host
		} else {
			return errors.New(
				"[Crust] Blocked: request has a malformed Referer header. " +
					"Only requests from your own machine are allowed")
		}
	}

	// "null" origin is sent by sandboxed iframes and privacy redirects.
	if origin == "null" {
		return errors.New(
			"[Crust] Blocked: a sandboxed webpage tried to access your MCP server. " +
				"This could be an attack. Only requests from your own machine are allowed")
	}

	u, err := url.Parse(origin)
	if err != nil {
		return errors.New(
			"[Crust] Blocked: request has a malformed Origin header. " +
				"Only requests from your own machine are allowed")
	}

	host := u.Hostname()

	if localhostPattern.MatchString(host) {
		return nil
	}

	if rebindingPattern.MatchString(host) {
		return fmt.Errorf(
			"[Crust] Blocked: a website at %q tried to access your MCP server using a DNS rebinding trick. "+
				"This is a known attack technique. Only requests from your own machine are allowed", host)
	}

	return fmt.Errorf(
		"[Crust] Blocked: a website at %q tried to access your MCP server. "+
			"This could be an attack (see CVE-2025-49596). "+
			"Only requests from your own machine are allowed", origin)
}
