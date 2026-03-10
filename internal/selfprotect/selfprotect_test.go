package selfprotect

import (
	"regexp"
	"testing"
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
