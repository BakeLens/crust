package rules

import (
	"context"
	"net"
	"net/netip"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// networkFileUploadFlags maps network commands to flags that read a local file
// for upload/exfiltration. When these flags are present with a file path,
// the operation should be OpRead so file-protection rules can trigger.
var networkFileUploadFlags = map[string][]string{
	"wget": {"--post-file", "--body-file"},
	"curl": {"-T", "--upload-file"},
}

// hasFileUploadFlag checks if a network command's arguments include a flag
// that reads a file for upload. Handles both "--flag value" and "--flag=value".
func hasFileUploadFlag(cmdName string, args []string) bool {
	flags, ok := networkFileUploadFlags[cmdName]
	if !ok {
		return false
	}
	for _, arg := range args {
		for _, flag := range flags {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				return true
			}
		}
	}
	return false
}

// networkOutputFlags maps network commands to flags that write downloaded
// content to a local file. When these flags are present, the operation should
// be OpWrite so file-protection rules can trigger.
var networkOutputFlags = map[string][]string{
	"wget":   {"-O", "--output-document"},
	"curl":   {"-o", "--output"},
	"aria2c": {"-o", "--out", "-d", "--dir"},
}

// hasOutputFlag checks if a network command's arguments include a flag
// that writes output to a local file.
func hasOutputFlag(cmdName string, args []string) bool {
	flags, ok := networkOutputFlags[cmdName]
	if !ok {
		return false
	}
	for _, arg := range args {
		for _, flag := range flags {
			if arg == flag || strings.HasPrefix(arg, flag+"=") {
				return true
			}
		}
	}
	return false
}

// extractHosts extracts hostnames/IPs from tokens (for network commands).
// All tokens are parsed through net/url for robust handling of schemes,
// ports, IPv6, userinfo, and other edge cases.
func extractHosts(tokens []string) []string {
	var hosts []string

	for _, token := range tokens {
		// Skip flags
		if strings.HasPrefix(token, "-") {
			continue
		}

		// Route everything through net/url by ensuring a scheme prefix.
		// This handles: "https://evil.com/path", "evil.com:8080/path",
		// "evil.com", "host:port", and bare hostnames uniformly.
		host := extractHostFromURL(token)
		// extractHostFromURL strips trailing dots (FQDN form: "A." → "a"), which
		// can cause looksLikeHost to reject a single-label FQDN. Fall back to
		// checking the raw token so "A." is accepted when the token itself looks
		// like a host.
		if host != "" && (looksLikeHost(host) || looksLikeHost(token)) {
			hosts = append(hosts, host)
		}
	}

	return hosts
}

// extractScpHost parses the user@host:path format used by scp/rsync.
// Returns the normalized host if found, or "" if the arg doesn't match the format.
func extractScpHost(arg string) string {
	if strings.HasPrefix(arg, "-") || arg == "" {
		return ""
	}
	colonIdx := strings.Index(arg, ":")
	if colonIdx <= 0 {
		return ""
	}
	hostPart := arg[:colonIdx]
	if atIdx := strings.LastIndex(hostPart, "@"); atIdx >= 0 {
		hostPart = hostPart[atIdx+1:]
	}
	hostLower := strings.ToLower(hostPart)
	if hostLower != "" && looksLikeHost(hostLower) {
		return normalizeIPHost(hostLower)
	}
	return ""
}

// extractSocatHost extracts a hostname/IP from a socat address token.
// Socat addresses look like "PROTOCOL:host:port" (e.g. "TCP:evil.com:4444",
// "UDP:1.2.3.4:53"). Non-network addresses like "EXEC:/bin/bash" or "STDIN"
// contain no extractable network host.
func extractSocatHost(arg string) string {
	if strings.HasPrefix(arg, "-") || arg == "" {
		return ""
	}
	// Split on ":" — socat address is TYPE:host:port (three parts minimum).
	parts := strings.SplitN(arg, ":", 3)
	if len(parts) < 2 {
		return ""
	}
	proto := strings.ToUpper(parts[0])
	// Only network-type socat addresses have a host in the second field.
	networkProtos := map[string]bool{
		"TCP": true, "TCP4": true, "TCP6": true,
		"UDP": true, "UDP4": true, "UDP6": true,
		"SSL": true, "OPENSSL": true,
	}
	if !networkProtos[proto] {
		return ""
	}
	host := strings.ToLower(parts[1])
	if looksLikeHost(host) {
		return normalizeIPHost(host)
	}
	return ""
}

// extractHostFromURL extracts the host from a URL, normalizes it, and lowercases it.
// Uses net/url for robust parsing of edge cases (IPv6, userinfo, etc.).
// Normalizes hex (0x7f000001) and decimal (2130706433) IP representations to
// canonical dotted-quad form so rules match regardless of encoding.
// Hosts are lowercased because RFC 3986 §3.2.2 says host is case-insensitive.
func extractHostFromURL(rawURL string) string {
	// Ensure scheme so net/url can parse correctly
	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}

	host := strings.ToLower(u.Hostname()) // strips port, handles [IPv6]
	host = strings.TrimRight(host, ".")   // strip trailing dot (FQDN form)
	return normalizeIPHost(host)
}

// normalizeIPHost converts non-standard IP representations to canonical form.
// Handles hex (0x7f000001) and decimal dword (2130706433) IP encodings used
// in SSRF bypasses. Only converts values that are clearly IP-like:
//   - Hex integers (0x prefix) — always intentional IP encoding
//   - Decimal integers > 16777215 (0xFFFFFF) — too large for a port/count,
//     must be a dword IP (covers all IPs ≥ 1.0.0.0)
//
// Returns the input unchanged for hostnames, small numbers, or standard IPs.
func normalizeIPHost(host string) string {
	// Already a standard IP (dotted-quad IPv4, IPv6)?
	// Unmap converts IPv6-mapped IPv4 (::ffff:127.0.0.1) to plain IPv4 (127.0.0.1)
	// so user rules matching "127.0.0.1" work regardless of IPv6 wrapping.
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}
	// Hex prefix (0x/0X) — always treat as IP encoding
	if strings.HasPrefix(host, "0x") || strings.HasPrefix(host, "0X") {
		if n, err := strconv.ParseUint(host, 0, 32); err == nil {
			return netip.AddrFrom4([4]byte{
				byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
			}).String()
		}
	}
	// Large decimal — dword IP (skip small numbers like port 8080)
	if n, err := strconv.ParseUint(host, 10, 32); err == nil && n > 0xFFFFFF {
		return netip.AddrFrom4([4]byte{
			byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n), //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
		}).String()
	}
	// Octal dotted-quad — e.g. 0177.0.0.1 = 127.0.0.1
	// Go's netip.ParseAddr rejects leading zeros, so we parse manually.
	// Only triggers when at least one octet has a leading zero (not "1.2.3.4").
	if parts := strings.Split(host, "."); len(parts) == 4 {
		hasLeadingZero := false
		var octets [4]byte
		valid := true
		for i, p := range parts {
			if p == "" {
				valid = false
				break
			}
			if len(p) > 1 && p[0] == '0' {
				hasLeadingZero = true
			}
			n, err := strconv.ParseUint(p, 0, 16) // base 0: auto-detect octal from "0" prefix
			if err != nil || n > 255 {
				valid = false
				break
			}
			octets[i] = byte(n)
		}
		if valid && hasLeadingZero {
			return netip.AddrFrom4(octets).String()
		}
	}
	// inet_aton short forms — e.g. 127.1 = 127.0.0.1, 127.0.1 = 127.0.0.1
	// 2-part: A.B where A is 8-bit, B is 24-bit
	// 3-part: A.B.C where A,B are 8-bit, C is 16-bit
	// curl/wget honor these on Linux; attackers use them to bypass loopback checks.
	if parts := strings.Split(host, "."); len(parts) >= 2 && len(parts) <= 3 {
		var octets [4]byte
		valid := true
		for i, p := range parts {
			if p == "" {
				valid = false
				break
			}
			var maxVal uint64
			if i < len(parts)-1 {
				maxVal = 255 // leading parts: 8-bit
			} else if len(parts) == 2 {
				maxVal = 0xFFFFFF // 2-part last: 24-bit
			} else {
				maxVal = 0xFFFF // 3-part last: 16-bit
			}
			n, err := strconv.ParseUint(p, 0, 32) // base 0: auto-detect hex/octal
			if err != nil || n > maxVal {
				valid = false
				break
			}
			if i < len(parts)-1 {
				octets[i] = byte(n) //nolint:gosec // n is validated ≤255 above; intentional uint64→byte for IP octet
			}
		}
		if valid {
			lastN, _ := strconv.ParseUint(parts[len(parts)-1], 0, 32) //nolint:errcheck // already validated in loop above
			if len(parts) == 2 {
				octets[1] = byte(lastN >> 16) //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
				octets[2] = byte(lastN >> 8)  //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
				octets[3] = byte(lastN)       //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
			} else { // 3 parts
				octets[2] = byte(lastN >> 8) //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
				octets[3] = byte(lastN)      //nolint:gosec // intentional uint64→byte truncation for IP octet extraction
			}
			return netip.AddrFrom4(octets).String()
		}
	}
	return host
}

// extractHostFromURLField extracts a host from a URL field value, handling both
// scheme-prefixed URLs ("https://evil.com/path") and scheme-less ("evil.com/path").
func extractHostFromURLField(s string) string {
	host := extractHostFromURL(s)
	if looksLikeHost(host) {
		return host
	}
	return ""
}

// RebindingSuffixes lists DNS rebinding services that resolve embedded IPs.
// e.g., 127.0.0.1.nip.io resolves to 127.0.0.1, A-B-C-D.sslip.io resolves to A.B.C.D.
//
// This is the single source of truth — selfprotect and mcpgateway build
// their regex patterns from this list. To add a new rebinding service,
// update only this slice; all consumers pick it up automatically.
var RebindingSuffixes = []string{".nip.io", ".sslip.io", ".xip.io"}

// RebindingExact lists domains that always resolve to 127.0.0.1.
//
// This list is intentionally incomplete — anyone can register a new domain
// pointing to 127.0.0.1. It covers the most commonly abused rebinding
// domains as defense-in-depth. The primary defense is that crust's
// management API listens on a Unix socket (not TCP), making DNS rebinding
// attacks moot. For additional coverage, users can add host-based blocking
// rules in their YAML configuration.
//
// To extend dynamically in the future: load extra entries from the crust
// config (e.g., server.extra_rebinding_domains) and append to this map
// at engine startup, before selfprotect/mcpgateway compile their regexes.
var RebindingExact = map[string]string{
	"localtest.me":  "127.0.0.1",
	"lvh.me":        "127.0.0.1",
	"vcap.me":       "127.0.0.1",
	"lacolhost.com": "127.0.0.1",
}

// expandRebindingHosts checks each host for DNS rebinding patterns and adds
// the embedded/resolved IP alongside the original hostname. This allows
// IP-based host rules to catch rebinding bypasses like 127.0.0.1.nip.io.
func expandRebindingHosts(hosts []string) []string {
	var expanded []string
	for _, h := range hosts {
		expanded = append(expanded, h)
		// Check exact rebinding domains (and subdomains)
		for domain, ip := range RebindingExact {
			if h == domain || strings.HasSuffix(h, "."+domain) {
				expanded = append(expanded, ip)
				break
			}
		}
		// Check wildcard DNS rebinding services: extract embedded IP
		// Formats: A.B.C.D.nip.io or A-B-C-D.sslip.io
		for _, suffix := range RebindingSuffixes {
			if !strings.HasSuffix(h, suffix) {
				continue
			}
			prefix := h[:len(h)-len(suffix)]
			// Try dotted-quad format: 127.0.0.1.nip.io
			if ip := normalizeIPHost(prefix); ip != prefix || isStandardIP(prefix) {
				expanded = append(expanded, ip)
				break
			}
			// Try dash format: 127-0-0-1.sslip.io
			dashed := strings.ReplaceAll(prefix, "-", ".")
			if ip := normalizeIPHost(dashed); ip != dashed || isStandardIP(dashed) {
				expanded = append(expanded, ip)
				break
			}
		}
	}
	return expanded
}

// isStandardIP returns true if s is a valid dotted-quad IPv4 or IPv6 address.
func isStandardIP(s string) bool {
	_, err := netip.ParseAddr(s)
	return err == nil
}

// looksLikeHost checks if a string looks like a hostname or IP address
// using net/netip for IP validation and RFC-compliant hostname checking.
func looksLikeHost(s string) bool {
	if s == "" {
		return false
	}

	// Use net/netip for IP address detection (handles IPv4, IPv6, and
	// zone IDs correctly — unlike manual digit checking)
	if _, err := netip.ParseAddr(s); err == nil {
		return true
	}

	// Hostname: must contain a dot, only [a-zA-Z0-9.-], at least one letter
	if !strings.Contains(s, ".") {
		return false
	}
	hasLetter := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		} else if c != '.' && c != '-' && (c < '0' || c > '9') {
			return false
		}
	}
	return hasLetter
}

// ---------------------------------------------------------------------------
// DNS-based loopback detection
// ---------------------------------------------------------------------------
//
// Resolves extracted hostnames and checks if they point to loopback IPs.
// This catches attacks where a custom domain (e.g., evil.com → 127.0.0.1)
// bypasses regex-based loopback detection.
//
// Results are cached with a bounded LRU to avoid repeated DNS lookups
// and limit memory usage.

// dnsCache is a bounded cache of hostname → resolved IPs with TTL expiry.
var dnsCache = &dnsLRU{
	entries: make(map[string]dnsCacheEntry),
	maxSize: 256,
	now:     time.Now,
}

type dnsCacheEntry struct {
	ips     []netip.Addr
	expires time.Time
}

type dnsLRU struct {
	mu      sync.Mutex
	entries map[string]dnsCacheEntry
	maxSize int
	now     func() time.Time // clock for TTL checks; defaults to time.Now
}

const dnsCacheTTL = 60 * time.Second

func (c *dnsLRU) get(host string) ([]netip.Addr, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[host]
	if !ok || c.now().After(e.expires) {
		return nil, false
	}
	return e.ips, true
}

func (c *dnsLRU) put(host string, ips []netip.Addr) {
	c.mu.Lock()
	defer c.mu.Unlock()
	// Evict oldest entries when at capacity (simple: clear half the cache).
	if len(c.entries) >= c.maxSize {
		i := 0
		half := c.maxSize / 2
		for k := range c.entries {
			delete(c.entries, k)
			i++
			if i >= half {
				break
			}
		}
	}
	c.entries[host] = dnsCacheEntry{
		ips:     ips,
		expires: c.now().Add(dnsCacheTTL),
	}
}

// dnsLookupTimeout is the maximum time for a single DNS lookup.
const dnsLookupTimeout = 2 * time.Second

// dnsEnabled controls whether DNS resolution is active.
// Automatically set to false during fuzz runs (-test.fuzz flag) to avoid
// 2s-per-lookup timeouts on random hostnames that accumulate and cause CI failures.
var dnsEnabled atomic.Bool

var dnsInitOnce sync.Once

func init() {
	dnsEnabled.Store(true)
}

func initDNSEnabled() {
	dnsInitOnce.Do(func() {
		for _, arg := range os.Args {
			if strings.HasPrefix(arg, "-test.fuzz=") || strings.HasPrefix(arg, "--test.fuzz=") {
				dnsEnabled.Store(false)
				return
			}
		}
	})
}

// resolveHost resolves a hostname to IP addresses using DNS, with caching.
// Returns nil for IP literals (already handled by normalizeIPHost) or on error.
// Returns nil immediately if dnsEnabled is false (fuzz/test mode).
func resolveHost(host string) []netip.Addr {
	initDNSEnabled()
	if host == "" {
		return nil
	}
	// Skip IP literals — already normalized by normalizeIPHost
	if addr, err := netip.ParseAddr(host); err == nil {
		// But return the addr if it's loopback so ResolvesToLoopback works on IPs too
		if addr.Unmap() == netip.MustParseAddr("::1") || loopbackPrefix.Contains(addr.Unmap()) {
			return []netip.Addr{addr.Unmap()}
		}
		return nil
	}
	// Skip DNS resolution when disabled (fuzz/test mode)
	if !dnsEnabled.Load() {
		return nil
	}
	// Skip non-hostname strings — but don't require a dot (covers "localhost"
	// and other single-label hostnames that resolve via /etc/hosts or DNS search domains)
	if !isResolvableHostname(host) {
		return nil
	}

	// Check cache
	if cached, ok := dnsCache.get(host); ok {
		return cached
	}

	// Resolve with timeout
	ctx, cancel := context.WithTimeout(context.Background(), dnsLookupTimeout)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		// Cache negative result to avoid repeated failing lookups
		dnsCache.put(host, nil)
		return nil
	}

	// Unmap IPv6-mapped IPv4 for consistent comparison
	for i, a := range addrs {
		addrs[i] = a.Unmap()
	}

	dnsCache.put(host, addrs)
	return addrs
}

// loopbackPrefixes defines the IP ranges considered loopback.
var loopbackPrefix = netip.MustParsePrefix("127.0.0.0/8")

// isResolvableHostname returns true if s looks like a hostname that could
// be resolved via DNS. Unlike looksLikeHost, it does NOT require a dot,
// allowing single-label hostnames like "localhost" that resolve via
// /etc/hosts or DNS search domains.
func isResolvableHostname(s string) bool {
	if s == "" {
		return false
	}
	hasLetter := false
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') {
			hasLetter = true
		} else if c != '.' && c != '-' && (c < '0' || c > '9') {
			return false
		}
	}
	return hasLetter
}

// ResolvesToLoopback returns true if any of the hostname's DNS records
// point to a loopback address (127.0.0.0/8 or ::1).
func ResolvesToLoopback(host string) bool {
	addrs := resolveHost(host)
	for _, a := range addrs {
		if a == netip.MustParseAddr("::1") || loopbackPrefix.Contains(a) {
			return true
		}
	}
	return false
}

// ResolveAndExpandHosts resolves non-IP hostnames via DNS and adds any
// loopback IPs to the host list. This enables IP-based rules to catch
// domains that resolve to loopback (e.g., evil.com → 127.0.0.1).
func ResolveAndExpandHosts(hosts []string) []string {
	expanded := hosts
	for _, h := range hosts {
		addrs := resolveHost(h)
		for _, a := range addrs {
			if a == netip.MustParseAddr("::1") || loopbackPrefix.Contains(a) {
				expanded = append(expanded, a.String())
			}
		}
	}
	return expanded
}

// hostResolvesToLoopbackWithCrust returns true if any host in the list
// DNS-resolves to a loopback address AND the raw JSON contains "crust"
// (case-insensitive). Used as a post-extraction self-protection check.
func hostResolvesToLoopbackWithCrust(hosts []string, rawJSON string) bool {
	if !strings.Contains(strings.ToLower(rawJSON), "crust") {
		return false
	}
	return slices.ContainsFunc(hosts, ResolvesToLoopback)
}
