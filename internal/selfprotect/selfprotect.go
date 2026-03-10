// Package selfprotect blocks agents from accessing Crust's own management
// API and Unix socket / Windows named pipe.  It runs as a pre-filter
// *before* the rule engine — protecting Crust itself is a separate concern
// from protecting the user's data.
package selfprotect

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/BakeLens/crust/internal/rules"
)

//go:generate go run selfprotect_verify.go

// loopbackHosts matches numeric loopback address representations.
// Shared between the forward pattern (loopback + crust path) and the
// reverse pattern (crust scheme + loopback host).
const loopbackHosts = `localhost|` +
	`127\.\d{1,3}\.\d{1,3}\.\d{1,3}|` + // entire 127.0.0.0/8 loopback range (4-part)
	`127\.\d+\.\d+|` + // inet_aton 3-part: 127.0.1
	`127\.\d+|` + // inet_aton 2-part: 127.1
	`\[?::(?:ffff:)?127\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?|` + // IPv6-mapped 127.x.x.x
	`\[?::1\]?|` + // IPv6 loopback
	`0\.0\.0\.0|` + // all-interfaces bind
	`0x7f[0-9a-f]{6}|` + // hex representation of 127.0.0.0/8
	`0x0[0:]|` + // hex zero host: 0x0:port or 0x0/path → 0.0.0.0
	`0177\.\d{1,3}\.\d{1,3}\.\d{1,3}|` + // octal representation of 127.0.0.0/8
	`2130706433` // decimal representation of 127.0.0.1

// rebindingRegex builds a regex fragment from rules.RebindingSuffixes and
// rules.RebindingExact — single source of truth for DNS rebinding domains.
func rebindingRegex() string {
	// Wildcard DNS suffixes: [a-z0-9.-]*\.(?:nip|sslip|xip)\.io
	var suffixCores []string
	for _, s := range rules.RebindingSuffixes {
		// ".nip.io" → "nip" (strip leading dot and TLD)
		core := strings.TrimPrefix(s, ".")
		core = strings.TrimSuffix(core, ".io")
		suffixCores = append(suffixCores, regexp.QuoteMeta(core))
	}
	wildcard := `[a-z0-9.-]*\.(?:` + strings.Join(suffixCores, "|") + `)\.io`

	// Exact rebinding domains grouped by TLD: (?:localtest|lvh|vcap)\.me|lacolhost\.com
	byTLD := map[string][]string{}
	for domain := range rules.RebindingExact {
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) == 2 {
			byTLD[parts[1]] = append(byTLD[parts[1]], regexp.QuoteMeta(parts[0]))
		}
	}
	var exactParts []string
	for tld, names := range byTLD {
		exactParts = append(exactParts, `(?:`+strings.Join(names, "|")+`)\.`+regexp.QuoteMeta(tld))
	}

	return wildcard + "|" + strings.Join(exactParts, "|")
}

// selfProtectAPIRegex is a hardcoded, tamper-proof check for management API access.
// Compiled once at init — cannot be altered by YAML rule changes or hot-reload.
// Covers: localhost, entire 127.0.0.0/8 range, IPv6 loopback (::1),
// IPv6-mapped IPv4 (::ffff:127.x.x.x), 0.0.0.0, hex (0x7fXXXXXX), decimal (2130706433),
// inet_aton short forms (127.1, 127.0.1), DNS rebinding services (nip.io, sslip.io, etc.).
var selfProtectAPIRegex = regexp.MustCompile(
	`(?i)(` +
		loopbackHosts + `|` +
		rebindingRegex() +
		`)[:/.].*crust` + // [:/.]  also catches dot-suffix hostnames (e.g. 127.0.0.1.evil → DNS rebinding)
		`|://0[:/.].*crust` + // bare 0 as URL host (= 0.0.0.0)
		`|crust\w*://(?:` + // reverse: "crust*" as URL scheme, loopback as host
		loopbackHosts + `|` +
		`0\b` + // bare 0 host
		`)`)

// selfProtectSocketRegex blocks agents from accessing the management API
// via Unix domain sockets or Windows named pipes. Compiled once at init.
var selfProtectSocketRegex = regexp.MustCompile(
	`(?i)(` +
		`--unix-socket|` + // curl --unix-socket
		`--unixsock|` + // ncat --unixsock
		`\bnc\s.*\s-U\s|` + // nc -U /path/to/socket (netcat)
		`\bncat\s.*\s-U\s|` + // ncat -U /path/to/socket
		`UNIX-CONNECT:|` + // socat UNIX-CONNECT:
		`UNIX:|` + // socat UNIX: (short alias)
		`AF_UNIX|` + // Python/C socket code
		`crust-api[-.]\S*\.sock|` + // socket filenames (crust-api-9090.sock etc.)
		`\\\\.\\pipe\\crust|` + // Windows named pipe \\.\pipe\crust*
		`NamedPipeClientStream` + // .NET named pipe access
		`)`)

// Check tests whether rawJSON targets the Crust management API or socket.
// Called by entry-point proxies BEFORE the rule engine.
// Returns a *MatchResult if blocked, nil if clean.
func Check(rawJSON string) *rules.MatchResult {
	if rawJSON == "" {
		return nil
	}

	// Normalize Unicode to catch homoglyph evasion (defense-in-depth).
	input := rules.NormalizeUnicode(rawJSON)

	// URL-decode to catch %63%72%75%73%74 ("crust") bypass.
	if decoded, err := url.QueryUnescape(input); err == nil && decoded != input {
		input = input + " " + decoded
	}

	if selfProtectAPIRegex.MatchString(input) {
		m := rules.NewMatch("builtin:protect-crust-api", rules.SeverityCritical, rules.ActionBlock, "Cannot access Crust management API")
		return &m
	}

	if selfProtectSocketRegex.MatchString(input) {
		m := rules.NewMatch("builtin:protect-crust-socket", rules.SeverityCritical, rules.ActionBlock, "Cannot access Crust management socket")
		return &m
	}

	return nil
}
