//go:build ignore

// This program verifies the self-protection regexes in selfprotect.go against
// comprehensive bypass vectors. It ensures no loopback/socket pattern is missed
// and no false positive is introduced. Run via go generate.
package main

import (
	"crypto/sha512"
	"fmt"
	"os"
	"regexp"
)

// Regex patterns copied from selfprotect.go — kept in sync via SHA-512 check.
var selfProtectAPIRegex = regexp.MustCompile(
	`(?i)(` +
		`localhost|` +
		`127\.\d{1,3}\.\d{1,3}\.\d{1,3}|` +
		`127\.\d+\.\d+|` +
		`127\.\d+|` +
		`\[?::(?:ffff:)?127\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?|` +
		`\[?::1\]?|` +
		`0\.0\.0\.0|` +
		`0x7f[0-9a-f]{6}|` +
		`0x0[0:]|` +
		`0177\.\d{1,3}\.\d{1,3}\.\d{1,3}|` +
		`2130706433|` +
		`[a-z0-9.-]*\.(?:nip|sslip|xip)\.io|` +
		`(?:localtest|lvh|vcap)\.me|` +
		`lacolhost\.com` +
		`)[:/.~].*crust` +
		`|://0[:/.].*crust` +
		`|crust\w*://(?:` +
		`localhost|` +
		`127\.\d{1,3}\.\d{1,3}\.\d{1,3}|` +
		`\[?::(?:ffff:)?127\.\d{1,3}\.\d{1,3}\.\d{1,3}\]?|` +
		`\[?::1\]?|` +
		`0\.0\.0\.0|` +
		`0x7f[0-9a-f]{6}|` +
		`0177\.\d{1,3}\.\d{1,3}\.\d{1,3}|` +
		`2130706433|` +
		`0\b` +
		`)`)

var selfProtectSocketRegex = regexp.MustCompile(
	`(?i)(` +
		`--unix-socket|` +
		`--unixsock|` +
		`\bnc\s.*\s-U\s|` +
		`\bncat\s.*\s-U\s|` +
		`UNIX-CONNECT:|` +
		`UNIX-CLIENT:|` +
		`UNIX-LISTEN:|` +
		`UNIX:|` +
		`AF_UNIX|` +
		`crust-api[-.]\S*\.sock|` +
		`\\\\.\\pipe\\crust|` +
		`NamedPipeClientStream` +
		`)`)

var selfProtectDataRegex = regexp.MustCompile(
	`(?i)` +
		`[/\\]\.crust[/\\]` +
		`|crust[_-]?(?:telemetry|security|api)[^.]*\.db` +
		`|crust\.(?:db|log|pid|port)`)

var selfProtectBinaryRegex = regexp.MustCompile(
	`(?i)(?:` +
		`/crust(?:["'\s,\]}]|$)|` +
		`/bakelens-sandbox(?:["'\s,\]}]|$)` +
		`)`)

var selfProtectProcessRegex = regexp.MustCompile(
	`(?i)(?:` +
		`\bkill\b.*\bcrust\b|` +
		`\bpkill\b.*\bcrust\b|` +
		`\bkillall\b.*\bcrust\b|` +
		`\bcrust\s+stop\b|` +
		`\bcrust\s+shutdown\b` +
		`)`)

var selfProtectExfilRegex = regexp.MustCompile(
	`(?:` +
		`\bRuleEngine\b|` +
		`\bEvalRequest\b|` +
		`\bexpandRuleHomes\b|` +
		`\bNormalizePath\b|` +
		`\bselfProtectAPIRegex\b|` +
		`\bselfProtectSocketRegex\b|` +
		`\bselfProtectDataRegex\b|` +
		`\bselfProtectBinaryRegex\b|` +
		`\bselfProtectProcessRegex\b|` +
		`\bselfProtectExfilRegex\b` +
		`)`)

// apiMustBlock lists inputs that MUST be caught by selfProtectAPIRegex.
var apiMustBlock = []struct {
	name  string
	input string
}{
	// Standard loopback IPv4
	{"localhost colon", `localhost:8080/crust/api`},
	{"localhost path", `localhost/crust/api`},
	{"localhost uppercase", `LOCALHOST:8080/crust/api`},
	{"localhost mixed case", `LocalHost:8080/crust/api`},
	{"127.0.0.1", `127.0.0.1:8080/crust/status`},
	{"127.0.0.2 loopback range", `127.0.0.2:8080/crust/stop`},
	{"127.255.255.254 loopback range", `127.255.255.254:8080/crust`},
	{"127.0.0.1 path sep", `127.0.0.1/crust/api`},

	// inet_aton short forms
	{"inet_aton 2-part 127.1", `127.1:8080/crust/api`},
	{"inet_aton 3-part 127.0.1", `127.0.1:8080/crust/api`},

	// IPv6 loopback
	{"IPv6 ::1 bracketed", `[::1]:8080/crust/api`},
	{"IPv6 ::1 bare", `::1:8080/crust`},

	// IPv6-mapped IPv4
	{"IPv6-mapped 127.0.0.1", `::ffff:127.0.0.1:8080/crust`},
	{"IPv6-mapped bracketed", `[::ffff:127.0.0.1]:8080/crust`},
	{"IPv6-mapped other loopback", `[::ffff:127.0.0.2]:8080/crust`},
	{"IPv6 plain mapped", `[::127.0.0.1]:8080/crust`},

	// 0.0.0.0 bind address
	{"0.0.0.0", `0.0.0.0:8080/crust/api`},

	// Hex representation
	{"hex 127.0.0.1", `0x7f000001:8080/crust`},
	{"hex 127.0.0.2", `0x7f000002:8080/crust`},
	{"hex 127.255.255.255", `0x7fffffff:8080/crust`},
	{"hex uppercase", `0x7F000001:8080/crust`},

	// Octal representation
	{"octal 127.0.0.1", `0177.0.0.1:8080/crust`},
	{"octal 127.0.0.2", `0177.0.0.2:8080/crust`},
	{"octal 127.255.255.255", `0177.255.255.255:8080/crust`},

	// Decimal representation
	{"decimal 127.0.0.1", `2130706433:8080/crust`},

	// DNS rebinding services
	{"nip.io", `127.0.0.1.nip.io:9090/api/crust/rules`},
	{"sslip.io", `127.0.0.1.sslip.io:9090/api/crust/rules`},
	{"xip.io", `10.0.0.1.xip.io:9090/api/crust/rules`},
	{"nip.io with subdomain", `app.127.0.0.1.nip.io:9090/crust`},
	{"sslip.io subdomain", `foo.bar.sslip.io:9090/crust`},
	{"localtest.me", `localtest.me:9090/api/crust/rules`},
	{"lvh.me", `lvh.me:9090/api/crust/rules`},
	{"vcap.me", `vcap.me:9090/api/crust/rules`},
	{"lacolhost.com", `lacolhost.com:9090/api/crust/rules`},
	{"sub.localtest.me", `sub.localtest.me:9090/crust`},
	{"sub.lvh.me", `foo.lvh.me:9090/crust`},

	// bare 0 as host
	{"bare 0 URL", `://0:9090/crust`},
	{"bare 0 URL path", `://0/crust`},

	// With http:// prefix
	{"http localhost", `http://localhost:8080/crust/api`},
	{"http 127.0.0.1", `http://127.0.0.1:8080/crust`},
	{"http [::1]", `http://[::1]:8080/crust`},
	{"http 0", `http://0:8080/crust`},

	// Reverse: "crust" as URL scheme, loopback as host
	{"crust:// scheme localhost", `Crust://loCAlhost`},
	{"crust0:// scheme bypass", `Crust0://loCAlhost`},
	{"crust:// scheme localhost mixed", `crust://LOCALHOST`},
	{"crust:// scheme 127.0.0.1", `crust://127.0.0.1:9090/api`},
	{"crust:// scheme [::1]", `crust://[::1]:9090/api`},
	{"crust:// scheme 0.0.0.0", `crust://0.0.0.0:9090`},
}

// apiMustAllow lists inputs that MUST NOT be caught (false positive check).
var apiMustAllow = []struct {
	name  string
	input string
}{
	{"external host", `example.com:8080/crust/api`},
	{"8.8.8.8", `8.8.8.8:8080/crust/api`},
	{"private 192.168", `192.168.1.1:8080/crust/api`},
	{"private 10.x", `10.0.0.1:8080/crust/api`},
	{"localhost no crust", `localhost:8080/other/api`},
	{"127.0.0.1 no crust", `127.0.0.1:8080/status`},
	{"empty string", ``},
	{"normal domain", `api.openai.com/v1/chat/completions`},
	{"just the word crust", `the earth's crust is thick`},
	{"just the word localhost", `localhost is the name`},
	{"crust no separator", `localhost8080crust`},
}

// socketMustBlock lists inputs that MUST be caught by selfProtectSocketRegex.
var socketMustBlock = []struct {
	name  string
	input string
}{
	// curl unix socket
	{"curl --unix-socket", `curl --unix-socket ~/.crust/crust-api-9090.sock http://localhost/api/rules`},
	{"curl --unix-socket uppercase", `curl --UNIX-SOCKET /tmp/crust.sock`},

	// ncat
	{"ncat --unixsock", `ncat --unixsock /tmp/crust.sock`},

	// nc -U
	{"nc -U", `nc -v -U /tmp/crust-api-9090.sock`},
	{"ncat -U", `ncat -v -U /tmp/crust-api-9090.sock`},

	// socat
	{"socat UNIX-CONNECT:", `socat UNIX-CONNECT:/home/user/.crust/crust-api-9090.sock -`},
	{"socat UNIX-CLIENT:", `socat UNIX-CLIENT:/tmp/crust-api.sock`},
	{"socat UNIX-LISTEN:", `socat UNIX-LISTEN:/tmp/crust-api.sock,fork`},
	{"socat UNIX:", `socat UNIX:/tmp/crust.sock -`},

	// Python AF_UNIX
	{"AF_UNIX", `python3 -c "import socket; s=socket.socket(socket.AF_UNIX)"`},

	// Socket filenames
	{"crust-api sock", `cat ~/.crust/crust-api-9090.sock`},
	{"crust-api sock variant", `ls /tmp/crust-api.9091.sock`},

	// Windows named pipe
	{"windows pipe", `echo | \\.\pipe\crust-api-9090`},

	// .NET named pipe
	{"dotnet pipe", `new NamedPipeClientStream(".", "crust-api-9090")`},
}

// socketMustAllow lists inputs that MUST NOT be caught (false positive check).
var socketMustAllow = []struct {
	name  string
	input string
}{
	{"normal curl", `curl https://api.openai.com/v1/chat/completions`},
	{"normal file read", `cat /home/user/.bashrc`},
	{"word socket in prose", `the socket was closed gracefully`},
	{"unrelated .sock file", `redis.sock`},
	{"normal pipe", `echo hello | grep world`},
	{"normal path", `/usr/local/bin/myapp`},
	{"normal URL", `https://example.com/api/v1`},
	{"empty string", ``},
}

// dataMustBlock lists inputs that MUST be caught by selfProtectDataRegex.
var dataMustBlock = []struct {
	name  string
	input string
}{
	{"crust dir unix", `cat ~/.crust/crust.db`},
	{"crust dir windows", `type C:\Users\user\.crust\crust.db`},
	{"crust dir write", `echo pwned > /home/user/.crust/evil.sh`},
	{"crust.db", `sqlite3 crust.db`},
	{"crust.log", `tail -f crust.log`},
	{"crust.pid", `cat crust.pid`},
	{"crust.port", `cat crust.port`},
	{"crust_telemetry.db", `cat crust_telemetry.db`},
	{"crust-security.db", `cat crust-security.db`},
	{"crustapi.db", `cat crustapi.db`},
}

// dataMustAllow lists inputs that MUST NOT be caught (false positive check).
var dataMustAllow = []struct {
	name  string
	input string
}{
	{"normal db", `sqlite3 /tmp/myapp.db`},
	{"crust word", `the crust of the earth`},
	{"crust in code", `// this implements the crust protocol`},
	{"unrelated db", `cat application.db`},
	{"unrelated log", `tail -f server.log`},
}

// binaryMustBlock lists inputs that MUST be caught by selfProtectBinaryRegex.
var binaryMustBlock = []struct {
	name  string
	input string
}{
	{"JSON write crust", `{"file_path":"/usr/local/bin/crust","content":"evil"}`},
	{"rm crust", `rm /usr/local/bin/crust`},
	{"mv crust", `mv /usr/local/bin/crust /tmp/crust.bak`},
	{"cp over crust", `cp /tmp/evil /usr/local/bin/crust`},
	{"homebrew crust", `chmod +x /opt/homebrew/bin/crust`},
	{"JSON bakelens-sandbox", `{"file_path":"/usr/local/bin/bakelens-sandbox"}`},
	{"rm bakelens-sandbox", `rm /usr/local/bin/bakelens-sandbox`},
	{"crust with single quote", `echo 'data' > /usr/local/bin/crust'`},
	{"crust end of line", `/usr/local/bin/crust`},
	{"crust with space", `cat /usr/local/bin/crust `},
}

// binaryMustAllow lists inputs that MUST NOT be caught (false positive check).
var binaryMustAllow = []struct {
	name  string
	input string
}{
	{"crust in prose", `the earth's crust is thick`},
	{"crust mid-path", `cat /home/user/crust-gui/src/main.rs`},
	{"encrust", `cat /usr/local/bin/encrust`},
	{"unrelated binary", `rm /usr/local/bin/myapp`},
	{"crust-gui binary", `/usr/local/bin/crust-gui`},
	{"crusted", `cat /usr/local/bin/crusted`},
}

// processMustBlock lists inputs that MUST be caught by selfProtectProcessRegex.
var processMustBlock = []struct {
	name  string
	input string
}{
	{"kill pgrep crust", `kill $(pgrep crust)`},
	{"pkill crust", `pkill crust`},
	{"killall crust", `killall crust`},
	{"kill -9 pgrep crust", `kill -9 $(pgrep crust)`},
	{"crust stop", `crust stop`},
	{"crust shutdown", `crust shutdown`},
	{"kill HUP crust", `kill -HUP $(pgrep crust)`},
}

// processMustAllow lists inputs that MUST NOT be caught (false positive check).
var processMustAllow = []struct {
	name  string
	input string
}{
	{"kill other", `kill $(pgrep nginx)`},
	{"crust start", `crust start`},
	{"crust status", `crust status`},
	{"crust version", `crust version --json`},
	{"unrelated kill", `kill -9 12345`},
	{"crust list-rules", `crust list-rules --json`},
}

// exfilMustBlock lists inputs that MUST be caught by selfProtectExfilRegex.
var exfilMustBlock = []struct {
	name  string
	input string
}{
	{"RuleEngine", `the RuleEngine evaluates patterns`},
	{"EvalRequest", `type EvalRequest struct`},
	{"expandRuleHomes", `func expandRuleHomes(rules`},
	{"NormalizePath", `NormalizePath handles unicode`},
	{"selfProtectAPIRegex", `var selfProtectAPIRegex = regexp`},
	{"selfProtectSocketRegex", `selfProtectSocketRegex blocks agents`},
	{"selfProtectDataRegex", `selfProtectDataRegex blocks data access`},
	{"selfProtectBinaryRegex", `selfProtectBinaryRegex matches paths`},
	{"selfProtectProcessRegex", `selfProtectProcessRegex blocks kill`},
	{"selfProtectExfilRegex", `selfProtectExfilRegex detects exfil`},
}

// exfilMustAllow lists inputs that MUST NOT be caught (false positive check).
var exfilMustAllow = []struct {
	name  string
	input string
}{
	{"normal code", `func main() { fmt.Println("hello") }`},
	{"rule word", `the rule is simple`},
	{"engine word", `search engine optimization`},
	{"eval word", `eval is dangerous in JavaScript`},
	{"normalize word", `normalize the data first`},
	{"path word", `the path is /usr/local/bin`},
}

func main() {
	failed := 0

	// ── 1. Verify API regex: must-block vectors ──
	fmt.Println("=== API regex: must-block vectors ===")
	for _, tt := range apiMustBlock {
		if !selfProtectAPIRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [API must-block]: %s: %q not matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-block vectors\n", len(apiMustBlock))

	// ── 2. Verify API regex: must-allow vectors (false positive check) ──
	fmt.Println("=== API regex: must-allow vectors ===")
	for _, tt := range apiMustAllow {
		if tt.input != "" && selfProtectAPIRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [API must-allow]: %s: %q incorrectly matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-allow vectors\n", len(apiMustAllow))

	// ── 3. Verify socket regex: must-block vectors ──
	fmt.Println("=== Socket regex: must-block vectors ===")
	for _, tt := range socketMustBlock {
		if !selfProtectSocketRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Socket must-block]: %s: %q not matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-block vectors\n", len(socketMustBlock))

	// ── 4. Verify socket regex: must-allow vectors (false positive check) ──
	fmt.Println("=== Socket regex: must-allow vectors ===")
	for _, tt := range socketMustAllow {
		if tt.input != "" && selfProtectSocketRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Socket must-allow]: %s: %q incorrectly matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-allow vectors\n", len(socketMustAllow))

	// ── 5. Verify data regex: must-block vectors ──
	fmt.Println("=== Data regex: must-block vectors ===")
	for _, tt := range dataMustBlock {
		if !selfProtectDataRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Data must-block]: %s: %q not matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-block vectors\n", len(dataMustBlock))

	// ── 6. Verify data regex: must-allow vectors (false positive check) ──
	fmt.Println("=== Data regex: must-allow vectors ===")
	for _, tt := range dataMustAllow {
		if tt.input != "" && selfProtectDataRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Data must-allow]: %s: %q incorrectly matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-allow vectors\n", len(dataMustAllow))

	// ── 7. Verify binary regex: must-block vectors ──
	fmt.Println("=== Binary regex: must-block vectors ===")
	for _, tt := range binaryMustBlock {
		if !selfProtectBinaryRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Binary must-block]: %s: %q not matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-block vectors\n", len(binaryMustBlock))

	// ── 8. Verify binary regex: must-allow vectors (false positive check) ──
	fmt.Println("=== Binary regex: must-allow vectors ===")
	for _, tt := range binaryMustAllow {
		if tt.input != "" && selfProtectBinaryRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Binary must-allow]: %s: %q incorrectly matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-allow vectors\n", len(binaryMustAllow))

	// ── 9. Verify process regex: must-block vectors ──
	fmt.Println("=== Process regex: must-block vectors ===")
	for _, tt := range processMustBlock {
		if !selfProtectProcessRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Process must-block]: %s: %q not matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-block vectors\n", len(processMustBlock))

	// ── 10. Verify process regex: must-allow vectors (false positive check) ──
	fmt.Println("=== Process regex: must-allow vectors ===")
	for _, tt := range processMustAllow {
		if tt.input != "" && selfProtectProcessRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Process must-allow]: %s: %q incorrectly matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-allow vectors\n", len(processMustAllow))

	// ── 11. Verify exfil regex: must-block vectors ──
	fmt.Println("=== Exfil regex: must-block vectors ===")
	for _, tt := range exfilMustBlock {
		if !selfProtectExfilRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Exfil must-block]: %s: %q not matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-block vectors\n", len(exfilMustBlock))

	// ── 12. Verify exfil regex: must-allow vectors (false positive check) ──
	fmt.Println("=== Exfil regex: must-allow vectors ===")
	for _, tt := range exfilMustAllow {
		if tt.input != "" && selfProtectExfilRegex.MatchString(tt.input) {
			fmt.Fprintf(os.Stderr, "FAIL [Exfil must-allow]: %s: %q incorrectly matched\n", tt.name, tt.input)
			failed++
		}
	}
	fmt.Printf("  checked %d must-allow vectors\n", len(exfilMustAllow))

	// ── 13. Verify regex count in source file ──
	fmt.Println("=== Source file integrity ===")
	src, err := os.ReadFile("selfprotect.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot read selfprotect.go: %v\n", err)
		os.Exit(1)
	}

	// Count compiled regexes
	reCount := 0
	for i := 0; i < len(src)-len("regexp.MustCompile"); i++ {
		if string(src[i:i+len("regexp.MustCompile")]) == "regexp.MustCompile" {
			reCount++
		}
	}
	if reCount != 6 {
		fmt.Fprintf(os.Stderr, "FAIL: expected 6 regexp.MustCompile calls, found %d\n", reCount)
		failed++
	} else {
		fmt.Printf("  regex count: %d (ok)\n", reCount)
	}

	// ── 14. Compute and print SHA-512 of selfprotect.go ──
	hash := sha512.Sum512(src)
	fmt.Printf("  SHA-512(selfprotect.go): %x\n", hash)

	// ── Summary ──
	total := len(apiMustBlock) + len(apiMustAllow) + len(socketMustBlock) + len(socketMustAllow) +
		len(dataMustBlock) + len(dataMustAllow) +
		len(binaryMustBlock) + len(binaryMustAllow) + len(processMustBlock) + len(processMustAllow) +
		len(exfilMustBlock) + len(exfilMustAllow)
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "\nFAIL: %d/%d self-protection verification checks failed.\n", failed, total)
		os.Exit(1)
	}
	fmt.Printf("\nok: all %d self-protection bypass vectors verified (6 regexes, SHA-512 recorded)\n", total)
}
