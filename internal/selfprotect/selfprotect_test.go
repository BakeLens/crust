package selfprotect

import (
	"regexp"
	"strings"
	"testing"

	"github.com/BakeLens/crust/internal/rules"
)

// SECURITY: Check must block all loopback representations targeting Crust API.
func TestCheck_APIBlocks(t *testing.T) {
	blocked := []struct {
		name  string
		input string
	}{
		{"localhost", `localhost:8080/crust/api`},
		{"localhost uppercase", `LOCALHOST:8080/crust/api`},
		{"127.0.0.1", `127.0.0.1:8080/crust/status`},
		{"127.0.0.2 loopback range", `127.0.0.2:8080/crust/stop`},
		{"127.255.255.254 loopback range", `127.255.255.254:8080/crust`},
		{"IPv6 ::1 bracketed", `[::1]:8080/crust/api`},
		{"IPv6 ::1 bare", `::1:8080/crust`},
		{"0.0.0.0", `0.0.0.0:8080/crust/api`},
		{"hex 127.0.0.1", `0x7f000001:8080/crust`},
		{"hex 127.0.0.2", `0x7f000002:8080/crust`},
		{"decimal 127.0.0.1", `2130706433:8080/crust`},
		{"IPv6-mapped 127.0.0.1", `::ffff:127.0.0.1:8080/crust`},
		{"IPv6-mapped bracketed", `[::ffff:127.0.0.1]:8080/crust`},
		{"IPv6-mapped other loopback", `[::ffff:127.0.0.2]:8080/crust`},
		{"path separator", `127.0.0.1/crust/api`},
		{"inet_aton 2-part", `127.1:8080/crust/api`},
		{"inet_aton 3-part", `127.0.1:8080/crust/api`},
		// DNS rebinding services
		{"nip.io rebinding", `127.0.0.1.nip.io:9090/api/crust/rules`},
		{"sslip.io rebinding", `127.0.0.1.sslip.io:9090/api/crust/rules`},
		{"xip.io rebinding", `10.0.0.1.xip.io:9090/api/crust/rules`},
		{"nip.io with subdomain", `app.127.0.0.1.nip.io:9090/crust`},
		{"localtest.me rebinding", `localtest.me:9090/api/crust/rules`},
		{"lvh.me rebinding", `lvh.me:9090/api/crust/rules`},
		{"vcap.me rebinding", `vcap.me:9090/api/crust/rules`},
		{"lacolhost.com rebinding", `lacolhost.com:9090/api/crust/rules`},
		// URL-encoded "crust" (%63%72%75%73%74)
		{"url-encoded crust", `localhost:8080/%63%72%75%73%74/api`},
	}

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			m := Check(tt.input)
			if m == nil {
				t.Errorf("SECURITY: Check must block %q but returned nil", tt.input)
			} else if m.RuleName != "builtin:protect-crust-api" {
				t.Errorf("expected rule builtin:protect-crust-api, got %s", m.RuleName)
			}
		})
	}
}

func TestCheck_APIAllows(t *testing.T) {
	allowed := []struct {
		name  string
		input string
	}{
		{"external host", `example.com:8080/crust/api`},
		{"private IP", `192.168.1.1:8080/crust/api`},
		{"10.x network", `10.0.0.1:8080/crust/api`},
		{"localhost no crust", `localhost:8080/other/api`},
		{"127.0.0.1 no crust", `127.0.0.1:8080/status`},
		{"empty string", ``},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			if m := Check(tt.input); m != nil {
				t.Errorf("Check should allow %q but blocked with rule %s", tt.input, m.RuleName)
			}
		})
	}
}

// SECURITY: Check must block agent access via Unix sockets and named pipes.
func TestCheck_SocketBlocks(t *testing.T) {
	blocked := []struct {
		name  string
		input string
	}{
		{"curl unix-socket", `curl --unix-socket ~/.crust/crust-api-9090.sock http://localhost/api/rules`},
		{"socat", `socat UNIX-CONNECT:/home/user/.crust/crust-api-9090.sock -`},
		{"python AF_UNIX", `python3 -c "import socket; s=socket.socket(socket.AF_UNIX)"`},
		{"socket filename", `cat ~/.crust/crust-api-9090.sock`},
		{"socket filename variant", `ls ~/.crust/crust-api-9091.sock`},
		{"windows pipe", `echo | \\.\pipe\crust-api-9090.sock`},
		{"dotnet pipe", `new NamedPipeClientStream(".", "crust-api-9090.sock")`},
	}

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			m := Check(tt.input)
			if m == nil {
				t.Errorf("SECURITY: Check must block %q but returned nil", tt.input)
			} else if m.RuleName != "builtin:protect-crust-socket" {
				t.Errorf("expected rule builtin:protect-crust-socket, got %s", m.RuleName)
			}
		})
	}
}

func TestCheck_SocketAllows(t *testing.T) {
	allowed := []struct {
		name  string
		input string
	}{
		{"normal curl", `curl https://api.openai.com/v1/chat/completions`},
		{"normal file read", `cat /home/user/.bashrc`},
		{"normal socket word", `the socket was closed`},
		{"unrelated .sock", `redis.sock`},
		{"normal pipe", `echo hello | grep world`},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			if m := Check(tt.input); m != nil {
				t.Errorf("Check should allow %q but blocked with rule %s", tt.input, m.RuleName)
			}
		})
	}
}

// SECURITY: Check must block direct access to Crust data directory and files.
func TestCheck_DataBlocks(t *testing.T) {
	blocked := []struct {
		name  string
		input string
	}{
		{"read db", `cat ~/.crust/crust.db`},
		{"sqlite3 db", `sqlite3 ~/.crust/crust.db "SELECT * FROM spans"`},
		{"read log", `tail -f ~/.crust/crust.log`},
		{"read pid", `cat ~/.crust/crust.pid`},
		{"read port", `cat ~/.crust/crust.port`},
		{"write to crust dir", `echo pwned > /home/user/.crust/evil.sh`},
		{"copy db", `cp /Users/user/.crust/crust.db /tmp/`},
		{"telemetry db", `cat crust_telemetry.db`},
		{"security db", `cat crust-security.db`},
		{"windows path", `type C:\Users\user\.crust\crust.db`},
		{"url-encoded", `cat ~/.crust/%63rust.db`},
	}

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			m := Check(tt.input)
			if m == nil {
				t.Errorf("SECURITY: Check must block %q but returned nil", tt.input)
			} else if m.RuleName != "builtin:protect-crust-data" {
				// May match socket or API regex first — that's also acceptable
				if m.RuleName != "builtin:protect-crust-socket" && m.RuleName != "builtin:protect-crust-api" {
					t.Errorf("expected builtin:protect-crust-data (or socket/api), got %s", m.RuleName)
				}
			}
		})
	}
}

func TestCheck_DataAllows(t *testing.T) {
	allowed := []struct {
		name  string
		input string
	}{
		{"normal db file", `sqlite3 /tmp/myapp.db`},
		{"crust word in text", `the crust of the earth`},
		{"crust in code comment", `// this implements the crust protocol`},
		{"unrelated .db", `cat application.db`},
		{"unrelated log", `tail -f server.log`},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			if m := Check(tt.input); m != nil {
				t.Errorf("Check should allow %q but blocked with rule %s", tt.input, m.RuleName)
			}
		})
	}
}

// SECURITY: Check must block agents from modifying crust binaries.
func TestCheck_BinaryBlocks(t *testing.T) {
	blocked := []struct {
		name  string
		input string
	}{
		{"write to /usr/local/bin/crust", `{"file_path":"/usr/local/bin/crust","content":"evil"}`},
		{"delete crust binary", `rm /usr/local/bin/crust`},
		{"move crust binary", `mv /usr/local/bin/crust /tmp/crust.bak`},
		{"overwrite crust", `cp /tmp/evil /usr/local/bin/crust`},
		{"homebrew crust path", `chmod +x /opt/homebrew/bin/crust`},
		{"bakelens-sandbox", `{"file_path":"/usr/local/bin/bakelens-sandbox"}`},
		{"delete bakelens-sandbox", `rm /usr/local/bin/bakelens-sandbox`},
	}

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			m := Check(tt.input)
			if m == nil {
				t.Errorf("SECURITY: Check must block %q but returned nil", tt.input)
			} else if m.RuleName != "builtin:protect-crust-binary" {
				t.Errorf("expected rule builtin:protect-crust-binary, got %s", m.RuleName)
			}
		})
	}
}

func TestCheck_BinaryAllows(t *testing.T) {
	allowed := []struct {
		name  string
		input string
	}{
		{"word crust in prose", `the earth's crust is thick`},
		{"word crust mid-path", `cat /home/user/crust-gui/src/main.rs`},
		{"word encrust", `cat /usr/local/bin/encrust`},
		{"unrelated binary", `rm /usr/local/bin/myapp`},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			if m := Check(tt.input); m != nil && m.RuleName == "builtin:protect-crust-binary" {
				t.Errorf("Check should allow %q but blocked with rule %s", tt.input, m.RuleName)
			}
		})
	}
}

// SECURITY: Check must block agents from killing or stopping the crust daemon.
func TestCheck_ProcessBlocks(t *testing.T) {
	blocked := []struct {
		name  string
		input string
	}{
		{"kill crust", `kill $(pgrep crust)`},
		{"pkill crust", `pkill crust`},
		{"killall crust", `killall crust`},
		{"kill -9 crust", `kill -9 $(pgrep crust)`},
		{"crust stop", `crust stop`},
		{"crust shutdown", `crust shutdown`},
	}

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			m := Check(tt.input)
			if m == nil {
				t.Errorf("SECURITY: Check must block %q but returned nil", tt.input)
			} else if m.RuleName != "builtin:protect-crust-process" {
				t.Errorf("expected rule builtin:protect-crust-process, got %s", m.RuleName)
			}
		})
	}
}

func TestCheck_ProcessAllows(t *testing.T) {
	allowed := []struct {
		name  string
		input string
	}{
		{"kill other process", `kill $(pgrep nginx)`},
		{"crust start", `crust start`},
		{"crust status", `crust status`},
		{"crust version", `crust version --json`},
		{"unrelated kill", `kill -9 12345`},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			if m := Check(tt.input); m != nil && m.RuleName == "builtin:protect-crust-process" {
				t.Errorf("Check should allow %q but blocked with rule %s", tt.input, m.RuleName)
			}
		})
	}
}

// SECURITY: Check must block exfiltration of crust internal source patterns.
func TestCheck_ExfilBlocks(t *testing.T) {
	blocked := []struct {
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

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			m := Check(tt.input)
			if m == nil {
				t.Errorf("SECURITY: Check must block %q but returned nil", tt.input)
			} else if m.RuleName != "builtin:protect-crust-exfil" {
				t.Errorf("expected rule builtin:protect-crust-exfil, got %s", m.RuleName)
			}
		})
	}
}

func TestCheck_ExfilAllows(t *testing.T) {
	allowed := []struct {
		name  string
		input string
	}{
		{"normal code", `func main() { fmt.Println("hello") }`},
		{"rule word", `the rule is simple`},
		{"engine word", `search engine optimization`},
		{"eval word", `eval is dangerous in JavaScript`},
		{"normalize word", `normalize the data first`},
	}

	for _, tt := range allowed {
		t.Run(tt.name, func(t *testing.T) {
			if m := Check(tt.input); m != nil && m.RuleName == "builtin:protect-crust-exfil" {
				t.Errorf("Check should allow %q but blocked with rule %s", tt.input, m.RuleName)
			}
		})
	}
}

// SECURITY: Check must block double and triple URL-encoded bypass attempts.
func TestCheck_DoubleURLEncodingBypass(t *testing.T) {
	blocked := []struct {
		name  string
		input string
	}{
		// Double URL-encoding: %25XX → %XX → char
		// "crust" = %63%72%75%73%74, double-encoded = %2563%2572%2575%2573%2574
		{"double-encoded crust in API path", "localhost:8080/%2563%2572%2575%2573%2574/api"},
		{"double-encoded crust in data path", "cat ~/.crust/%2563rust.db"},
		// Double-encoded slash + crust
		{"double-encoded path with crust", "127.0.0.1:8080%2F%2563%2572%2575%2573%2574"},
		// Triple URL-encoding: %25 → %, then decode twice more
		{"triple-encoded crust", "localhost:8080/%252563%252572%252575%252573%252574/api"},
	}

	for _, tt := range blocked {
		t.Run(tt.name, func(t *testing.T) {
			m := Check(tt.input)
			if m == nil {
				t.Errorf("SECURITY: Check must block double/triple URL-encoded %q but returned nil", tt.input)
			}
		})
	}
}

// TestVerifyRegexMatchesProduction ensures the verify script's hardcoded regex
// fragments stay in sync with the production selfprotect.go patterns.
// This catches drift between the two files (Bug #6 scenario).
func TestVerifyRegexMatchesProduction(t *testing.T) {
	prodAPI := selfProtectAPIRegex.String()

	// 1. The API regex must use the separator class [:/.~] (no \w — causes false positives like localhost8080crust)
	if !strings.Contains(prodAPI, `[:/.~]`) {
		t.Errorf("selfProtectAPIRegex missing separator class [:/.~], got: %s", prodAPI)
	}

	// 2. The bare-0 branch must use [:/.]  not [:/]
	if !strings.Contains(prodAPI, `://0[:/.]`) {
		t.Errorf("selfProtectAPIRegex bare-0 branch missing dot in char class, got: %s", prodAPI)
	}

	// 3. Verify that every RebindingSuffix appears in the compiled regex.
	for _, suffix := range rules.RebindingSuffixes {
		core := strings.TrimPrefix(suffix, ".")
		core = strings.TrimSuffix(core, ".io")
		if !strings.Contains(prodAPI, core) {
			t.Errorf("selfProtectAPIRegex missing rebinding suffix core %q from rules.RebindingSuffixes", core)
		}
	}

	// 4. Verify that every RebindingExact domain name appears in the compiled regex.
	for domain := range rules.RebindingExact {
		parts := strings.SplitN(domain, ".", 2)
		if len(parts) == 0 {
			continue
		}
		name := parts[0]
		if !strings.Contains(prodAPI, name) {
			t.Errorf("selfProtectAPIRegex missing rebinding exact domain %q from rules.RebindingExact", domain)
		}
	}

	// 5. Verify socket, data, binary, process, exfil regexes compile (smoke test).
	for name, re := range map[string]*regexp.Regexp{
		"socket":  selfProtectSocketRegex,
		"data":    selfProtectDataRegex,
		"binary":  selfProtectBinaryRegex,
		"process": selfProtectProcessRegex,
		"exfil":   selfProtectExfilRegex,
	} {
		if re.String() == "" {
			t.Errorf("selfProtect%sRegex compiled to empty string", name)
		}
	}
}

// FuzzSelfProtectBypass attempts to find inputs that bypass self-protection.
// Tests API regex, socket regex, and loopback+crust bypass detection.
func FuzzSelfProtectBypass(f *testing.F) {
	// API regex seeds
	f.Add("localhost:9090/api/crust/rules")
	f.Add("127.0.0.1:9090/api/crust/rules")
	f.Add("[::1]:9090/crust")
	f.Add("0x7f000001:9090/crust")
	f.Add("2130706433:9090/crust")
	f.Add("127.0.0.1.nip.io:9090/crust")
	f.Add("http://0:9090/api/crust/rules")
	// Socket regex seeds
	f.Add("curl --unix-socket /tmp/crust.sock http://localhost/api")
	f.Add("socat UNIX-CONNECT:/tmp/crust.sock -")
	f.Add(`\\.\pipe\crust-api`)
	f.Add("nc -U /tmp/crust-api-9090.sock")
	// Bypass seeds
	f.Add("http://127.0.0.1:9090/api/crust/rules")
	f.Add("http://localhost:9090/api/crust/stop")
	f.Add("http://[::1]:9090/crust")
	f.Add("http://0x7f000001:9090/crust")

	// Oracle patterns: loopback URL with "crust" in the same URL structure.
	// Pattern 1: loopback host with "crust" in the path — e.g. http://localhost:9090/crust
	// Only URL-legal chars (: / . - _ ~ digits letters) between host and "crust".
	// Excludes % to avoid false triggers on non-decoded percent sequences like "host%Crust".
	// The character class between host and "crust" deliberately excludes hyphen:
	// "localhost-foo" is a different hostname, not a loopback path.
	oracleLoopbackCrust := regexp.MustCompile(`(?i)[a-z][a-z0-9+\-.]*://(?:localhost|127\.0\.0\.1)\b[:/\w.~]*crust`)
	// Pattern 2: "crust" scheme with loopback host — e.g. crust://localhost
	oracleCrustScheme := regexp.MustCompile(`(?i)\bcrust\w*://(?:localhost|127\.0\.0\.1)`)

	f.Fuzz(func(t *testing.T, input string) {
		result := Check(input)

		if result == nil && (oracleLoopbackCrust.MatchString(input) || oracleCrustScheme.MatchString(input)) {
			t.Errorf("BYPASS: %q contains loopback+crust URL but was not blocked", input)
		}
	})
}
