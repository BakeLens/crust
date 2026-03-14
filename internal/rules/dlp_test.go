package rules

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

// TestDLPFalsePositives verifies DLP patterns do NOT fire on normal code
// that happens to contain similar-looking strings.
func TestDLPFalsePositives(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		// AWS: short strings starting with AKIA but too short
		{"AWS-like but too short", "Write",
			`{"file_path":"/tmp/test.py","content":"AKIA_PLACEHOLDER = 'not a key'"}`},
		// GitHub: ghp_ but too short (under 36 chars)
		{"GitHub-like but too short", "Write",
			`{"file_path":"/tmp/test.py","content":"ghp_short"}`},
		// Stripe: sk_test_ (test keys, not live)
		{"Stripe test key (not live)", "Write",
			`{"file_path":"/tmp/test.py","content":"STRIPE_KEY = 'sk_test_ABCDEFGHIJKLMNOPQRSTUVWXYZab'"}`},
		// Google: AIza-like but wrong length
		{"Google-like but wrong length", "Write",
			`{"file_path":"/tmp/test.py","content":"key = 'AIzaShort'"}`},
		// Normal code with "token" and "key" words
		{"normal code with key/token words", "Write",
			`{"file_path":"/tmp/test.py","content":"api_key = get_token()\nfor key in tokens:\n    print(key)"}`},
		// Hex strings that look like tokens but aren't prefixed
		{"plain hex string (no prefix)", "Write",
			`{"file_path":"/tmp/test.py","content":"hash = 'aabbccddeeff00112233445566778899'"}`},
		// UUIDs (look like Heroku but missing prefix)
		{"UUID without heroku_ prefix", "Write",
			`{"file_path":"/tmp/test.py","content":"id = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'"}`},
		// Base64 content (not a token)
		{"base64 data (not a token)", "Write",
			`{"file_path":"/tmp/test.py","content":"data = 'SGVsbG8gV29ybGQhIFRoaXMgaXMgYSB0ZXN0Lg=='"}`},
		// Documentation/comments mentioning token formats
		{"documentation about token format", "Write",
			`{"file_path":"/tmp/README.md","content":"Tokens start with ghp_ followed by 36 alphanumeric characters."}`},
		// npm-like but wrong length
		{"npm-like but wrong length", "Write",
			`{"file_path":"/tmp/test.js","content":"const npm_version = '1.0.0'"}`},
		// Normal curl command without secrets
		{"curl without secrets", "Bash",
			`{"command":"curl -H 'Content-Type: application/json' https://api.example.com/data"}`},
		// Short dapi-like string (not 32 hex chars)
		{"dapi-like but too short", "Write",
			`{"file_path":"/tmp/test.py","content":"dapibus = 'lorem ipsum'"}`},
		// PEM: certificates and public keys are NOT private keys
		{"PEM certificate (not private key)", "Write",
			`{"file_path":"/tmp/test.pem","content":"-----BEGIN CERTIFICATE-----\nMIIBkTCB...\n-----END CERTIFICATE-----"}`},
		{"PEM public key (not private key)", "Write",
			`{"file_path":"/tmp/test.pem","content":"-----BEGIN PUBLIC KEY-----\nMIIBIjAN...\n-----END PUBLIC KEY-----"}`},
		// Short HuggingFace-like token
		{"hf_ too short", "Write",
			`{"file_path":"/tmp/test.py","content":"hf_short"}`},
		// Short Groq-like key
		{"gsk_ too short", "Write",
			`{"file_path":"/tmp/test.py","content":"gsk_short"}`},
		// Short Twilio-like key (SK but not 32 hex)
		{"SK too short for Twilio", "Write",
			`{"file_path":"/tmp/test.py","content":"SKU = 'product-123'"}`},
		// Short r8_ token
		{"r8_ too short", "Write",
			`{"file_path":"/tmp/test.py","content":"r8_short"}`},
		// vercel_ in normal code (version string, not a token)
		{"vercel_ in version context", "Write",
			`{"file_path":"/tmp/test.js","content":"const vercel_sdk = '1.0'"}`},
		// "BEGIN CERTIFICATE" is not a private key
		{"PEM certificate request", "Write",
			`{"file_path":"/tmp/test.pem","content":"-----BEGIN CERTIFICATE REQUEST-----\nMIIBkTCB...\n-----END CERTIFICATE REQUEST-----"}`},
		// hvs. but too short
		{"hvs. too short", "Write",
			`{"file_path":"/tmp/test.env","content":"hvs.short"}`},
		// dp.st. but too short
		{"dp.st. too short", "Write",
			`{"file_path":"/tmp/test.env","content":"dp.st.short"}`},
		// lin_api_ but too short
		{"lin_api_ too short", "Write",
			`{"file_path":"/tmp/test.env","content":"lin_api_short"}`},
		// PMAK- but too short
		{"PMAK- too short", "Write",
			`{"file_path":"/tmp/test.env","content":"PMAK-short"}`},
		// sbp_ but too short
		{"sbp_ too short", "Write",
			`{"file_path":"/tmp/test.env","content":"sbp_short"}`},
		// Normal Go code with SK in variable name
		{"SK in Go variable name", "Write",
			`{"file_path":"/tmp/test.go","content":"func SKip() {}"}`},
		// Firebase-like but too short
		{"AAAA prefix but too short", "Write",
			`{"file_path":"/tmp/test.py","content":"AAAA_PADDING = True"}`},
		// Normal code mentioning private key in comments
		{"private key in comment text", "Write",
			`{"file_path":"/tmp/test.py","content":"# Generate a private key using openssl"}`},
		// dop_v1_ but too short
		{"dop_v1_ too short", "Write",
			`{"file_path":"/tmp/test.env","content":"dop_v1_short"}`},
		// Normal Python f-string with hf_ substring
		{"hf_ in variable name", "Write",
			`{"file_path":"/tmp/test.py","content":"half_width = 100"}`},
		// gsk_ as Go package prefix
		{"gsk_ in package name", "Write",
			`{"file_path":"/tmp/test.go","content":"import gsk_utils"}`},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if result.Matched && strings.HasPrefix(result.RuleName, "builtin:dlp-") {
				t.Errorf("False positive: DLP rule '%s' fired on benign content", result.RuleName)
			} else {
				t.Logf("PASS: not blocked by DLP")
			}
		})
	}
}

// TestDLPBypass_Caught tests bypass attempts the normalizer defeats.
func TestDLPBypass_Caught(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"unicode escape in JSON decodes to literal AWS key",
			"Write",
			// \u0041 = A, \u004B = K → AKIA after json.Unmarshal
			`{"file_path":"/home/user/project/config.py","content":"KEY = '\u0041\u004BI\u0041` + "IOSFODNN7REALKEY1" + `'"}`,
		},
		{
			"zero-width joiner stripped from GitHub token",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"token = ` + "ghp_" + "\u200D" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED — bypass succeeded")
			} else {
				t.Logf("Bypass defeated: blocked by '%s'", result.RuleName)
			}
		})
	}
}

// TestDLPBypass_NotCaught documents known gaps where DLP cannot detect secrets.
func TestDLPBypass_NotCaught(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"bash indirection: echo $SECRET > file (variable reference, no literal key)",
			"Bash",
			`{"command":"echo $AWS_SECRET_KEY > /home/user/project/config.py"}`,
		},
		{
			"base64-encoded key in write content",
			"Write",
			`{"file_path":"/home/user/project/deploy.sh","content":"echo QUtJQUlPU0ZPRE5ON1JFQUxLRVkx | base64 -d > /tmp/key"}`,
		},
		{
			"string concat in generated code",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"key = \"AK\" + \"IA\" + \"IOSFODNN7REALKEY1\""}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if result.Matched {
				t.Logf("Gap closed! Now blocked by '%s' (update test)", result.RuleName)
			} else {
				t.Logf("Known gap: not caught (as expected)")
			}
		})
	}
}

// TestDLPSecretDetection tests that the DLP engine blocks writes containing secrets.
func TestDLPSecretDetection(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"DLP: writing AWS access key",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"AWS_KEY = '` + "AKIA" + "IOSFODNN7REALKEY1" + `'"}`,
		},
		{
			"DLP: writing GitHub PAT",
			"Write",
			`{"file_path":"/home/user/project/.gitconfig","content":"token = ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`,
		},
		{
			"DLP: writing GitHub fine-grained token",
			"Write",
			`{"file_path":"/home/user/project/config.json","content":"` + "github_pat_" + "01ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOP" + `"}`,
		},
		{
			"DLP: writing Slack bot token",
			"Write",
			`{"file_path":"/home/user/project/slack.py","content":"SLACK_TOKEN = '` + "xoxb-" + "1234567890123-1234567890123-ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `'"}`,
		},
		{
			"DLP: writing Slack webhook URL",
			"Write",
			`{"file_path":"/home/user/project/webhook.yml","content":"url: ` + "https://hooks.slack" + ".com/services/" + "T0ABCDEFG/B0ABCDEFG/abcdefghijklmnopqrstuvwx" + `"}`,
		},
		{
			"DLP: writing Stripe live key",
			"Write",
			`{"file_path":"/home/user/project/stripe.py","content":"STRIPE_KEY = '` + "sk" + "_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `'"}`,
		},
		{
			"DLP: writing Google API key",
			"Write",
			`{"file_path":"/home/user/project/google.py","content":"API_KEY = '` + "AIza" + "SyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456" + `'"}`,
		},
		{
			"DLP: writing SendGrid API key",
			"Write",
			`{"file_path":"/home/user/project/email.py","content":"SENDGRID_KEY = '` + "SG." + "abcdefghijklmnopqrstuv" + "." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr" + `'"}`,
		},
		{
			"DLP: writing Heroku API key",
			"Write",
			`{"file_path":"/home/user/project/heroku.py","content":"HEROKU_KEY = '` + "heroku_" + "a1b2c3d4-e5f6-7890-abcd-ef1234567890" + `'"}`,
		},
		{
			"DLP: MCP tool writing AWS key via shape detection",
			"save_file",
			`{"file_path":"/home/user/project/creds.py","content":"KEY = '` + "AKIA" + "IOSFODNN7EXAMPLE2" + `'"}`,
		},
		{
			"DLP: editing in Stripe live key",
			"Edit",
			`{"file_path":"/home/user/project/config.py","old_string":"KEY = ''","new_string":"KEY = '` + "sk" + "_live_" + "51234567890abcdefghijklmnopq" + `'"}`,
		},
		// --- New patterns ---
		{
			"DLP: writing GitLab PAT",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"GITLAB_TOKEN = '` + "glpat-" + "ABCDEFghijklmnopqrstuv" + `'"}`,
		},
		{
			"DLP: writing PyPI token",
			"Write",
			`{"file_path":"/home/user/project/.pypirc","content":"password = ` + "pypi-" + "AgEIcHlwaS5vcmcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + `"}`,
		},
		{
			"DLP: writing npm token",
			"Write",
			`{"file_path":"/home/user/project/.npmrc","content":"//registry.npmjs.org/:_authToken=` + "npm_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij" + `"}`,
		},
		{
			"DLP: writing Shopify shared secret",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"SECRET = '` + "shpss_" + "aabbccddeeff00112233445566778899" + `'"}`,
		},
		{
			"DLP: writing Shopify access token",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"TOKEN = '` + "shpat_" + "aabbccddeeff00112233445566778899" + `'"}`,
		},
		{
			"DLP: writing Databricks token",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"TOKEN = '` + "dapi" + "aabbccddeeff00112233445566778899" + `'"}`,
		},
		{
			"DLP: writing Anthropic API key",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"ANTHROPIC_KEY = '` + "sk-ant-api03-" + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst", 2) + `'"}`,
		},
		{
			"DLP: writing OpenAI project key",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"OPENAI_KEY = '` + "sk-proj-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + `'"}`,
		},
		{
			"DLP: writing Stripe webhook secret",
			"Write",
			`{"file_path":"/home/user/project/config.py","content":"WEBHOOK_SECRET = '` + "whsec_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `'"}`,
		},
		{
			"DLP: writing age secret key",
			"Write",
			`{"file_path":"/home/user/project/key.txt","content":"` + "AGE-SECRET-KEY-" + "1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ" + `"}`,
		},
		// --- Expanded patterns ---
		{
			"DLP: RSA private key in any operation",
			"Bash",
			`{"command":"cat /tmp/key.pem"}` + "\n-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBA...\n-----END RSA PRIVATE KEY-----",
		},
		{
			"DLP: OpenSSH private key",
			"Write",
			`{"file_path":"/home/user/project/deploy_key","content":"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAA...\n-----END OPENSSH PRIVATE KEY-----"}`,
		},
		{
			"DLP: writing HuggingFace token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"HF_TOKEN=` + "hf_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" + `"}`,
		},
		{
			"DLP: writing Groq API key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"GROQ_KEY=` + "gsk_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwx" + `"}`,
		},
		{
			"DLP: writing Vercel token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"VERCEL_TOKEN=` + "vercel_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `"}`,
		},
		{
			"DLP: writing Supabase key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"SUPABASE_KEY=` + "sbp_" + "aabbccddeeff00112233445566778899aabbccddeeff" + `"}`,
		},
		{
			"DLP: writing DigitalOcean PAT",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"DO_TOKEN=` + "dop_v1_" + "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb" + `"}`,
		},
		{
			"DLP: writing DigitalOcean OAuth token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"DO_OAUTH=` + "doo_v1_" + "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899aabb" + `"}`,
		},
		{
			"DLP: writing HashiCorp Vault token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"VAULT_TOKEN=` + "hvs." + "ABCDEFghijklmnopqrstuvwx0123" + `"}`,
		},
		{
			"DLP: writing Linear API key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"LINEAR_KEY=` + "lin_api_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop" + `"}`,
		},
		{
			"DLP: writing Postman API key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"POSTMAN_KEY=` + "PMAK-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `"}`,
		},
		{
			"DLP: writing Replicate API token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"REPLICATE_TOKEN=` + "r8_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop" + `"}`,
		},
		{
			"DLP: writing Twilio API key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"TWILIO_KEY=` + "SK" + "aabbccddeeff00112233445566778899" + `"}`,
		},
		{
			"DLP: writing Doppler token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"DOPPLER_TOKEN=` + "dp.st." + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + `"}`,
		},
		{
			"DLP: writing OpenAI admin key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"OPENAI_ADMIN=` + "sk-admin-" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + `"}`,
		},
		{
			"DLP: writing Firebase key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"FIREBASE_KEY=` + "AAAA" + "ABCDEFG" + ":" + strings.Repeat("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop", 4) + `"}`,
		},
		// --- Newer service patterns ---
		{
			"DLP: writing PlanetScale token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"PLANETSCALE_TOKEN=` + "pscale_tkn_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef" + `"}`,
		},
		{
			"DLP: writing Resend API key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"RESEND_KEY=` + "re_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `"}`,
		},
		{
			"DLP: writing Fly.io token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"FLY_TOKEN=` + "fo1_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + `"}`,
		},
		{
			"DLP: writing Railway token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"RAILWAY_TOKEN=` + "railway_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `"}`,
		},
		{
			"DLP: writing Clerk secret key",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"CLERK_SECRET=` + "sk_live_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `"}`,
		},
		{
			"DLP: writing Upstash token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"UPSTASH_TOKEN=` + "AX" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + `"}`,
		},
		{
			"DLP: writing Neon token",
			"Write",
			`{"file_path":"/home/user/project/.env","content":"NEON_TOKEN=` + "neon_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh" + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{
				Name:      tc.tool,
				Arguments: []byte(tc.args),
			}
			result := engine.Evaluate(call)
			if !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED (tool=%s)", tc.tool)
			} else {
				t.Logf("PASS: Blocked by rule '%s'", result.RuleName)
			}
		})
	}
}

// TestDLP_ScansNonContentFields verifies that DLP scans the full RawJSON payload,
// not just the Content field. Secrets in non-content fields (e.g., file_path,
// old_string) must still be caught.
func TestDLP_ScansNonContentFields(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	awsKey := "AKIA" + "IOSFODNN7REALKEY1"

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"secret in old_string field (not content)",
			"Edit",
			`{"file_path":"/home/user/project/config.py","old_string":"KEY = '` + awsKey + `'","new_string":"KEY = 'redacted'"}`,
		},
		{
			"secret in file_path field",
			"Write",
			`{"file_path":"/home/user/project/` + awsKey + `.py","content":"clean content here"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if !result.Matched {
				t.Errorf("Expected DLP to catch secret in non-content field, but it was ALLOWED")
			} else if !strings.HasPrefix(result.RuleName, "builtin:dlp-") {
				t.Logf("Blocked by '%s' (not DLP, but still caught)", result.RuleName)
			} else {
				t.Logf("PASS: Blocked by DLP rule '%s'", result.RuleName)
			}
		})
	}
}

// TestToolNameSanitization verifies null bytes and control chars in tool names
// are stripped before extraction, so the tool is still correctly identified.
func TestToolNameSanitization(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// "Wr\x00ite" with null byte should be sanitized to "Write" and still
	// trigger DLP on a GitHub token write.
	call := ToolCall{
		Name:      "Wr\x00ite",
		Arguments: []byte(`{"file_path":"/home/user/project/config.py","content":"token = ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`),
	}
	result := engine.Evaluate(call)
	if !result.Matched {
		t.Errorf("Tool name with null byte: expected BLOCKED but was ALLOWED")
	} else {
		t.Logf("PASS: Null byte tool name sanitized, blocked by '%s'", result.RuleName)
	}
}

// TestNullByteWriteBlocked verifies that write content with null bytes is blocked.
func TestNullByteWriteBlocked(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	call := ToolCall{
		Name:      "Write",
		Arguments: []byte(`{"file_path":"/tmp/test.txt","content":"hello` + "\x00" + `world"}`),
	}
	result := engine.Evaluate(call)
	if !result.Matched {
		t.Errorf("Null byte in write content: expected BLOCKED but was ALLOWED")
	} else if result.RuleName != "builtin:block-null-byte-write" {
		t.Errorf("Expected rule 'builtin:block-null-byte-write', got '%s'", result.RuleName)
	} else {
		t.Logf("PASS: Null byte write blocked by '%s'", result.RuleName)
	}
}

// TestNullByteWriteAllowsCleanContent verifies normal writes are not affected.
func TestNullByteWriteAllowsCleanContent(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	call := ToolCall{
		Name:      "Write",
		Arguments: []byte(`{"file_path":"/tmp/test.txt","content":"hello world"}`),
	}
	result := engine.Evaluate(call)
	if result.Matched {
		t.Errorf("Clean write content: expected ALLOWED but was BLOCKED by '%s'", result.RuleName)
	} else {
		t.Logf("PASS: Clean write content allowed")
	}
}

// TestDLPScanAllOperations verifies DLP fires on execute/network operations, not just writes.
func TestScanDLP_CryptoDetection(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	// BIP39 12-word mnemonic — should be caught by ScanDLP's crypto tier.
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	result := engine.ScanDLP(mnemonic)
	if result == nil {
		t.Fatal("ScanDLP should block BIP39 mnemonic in server response")
		return
	}
	if result.RuleName != "builtin:dlp-crypto-bip39-mnemonic" {
		t.Errorf("RuleName = %s, want builtin:dlp-crypto-bip39-mnemonic", result.RuleName)
	}
}

func TestDLPScanAllOperations(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc string
		tool string
		args string
	}{
		{
			"DLP blocks secret in curl command (OpExecute/OpNetwork)",
			"Bash",
			`{"command":"curl -H 'Authorization: Bearer ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `' https://api.github.com/user"}`,
		},
		{
			"DLP blocks AWS key in echo command (OpExecute)",
			"Bash",
			`{"command":"echo '` + "AKIA" + "IOSFODNN7REALKEY1" + `'"}`,
		},
		{
			"DLP blocks secret in Read tool (OpRead)",
			"Read",
			`{"file_path":"/home/user/project/config.py","content":"token = ` + "ghp_" + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef0123" + `"}`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: tc.tool, Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED — DLP missed secret in %s tool", tc.tool)
			} else {
				t.Logf("PASS: Blocked by '%s'", result.RuleName)
			}
		})
	}
}

// TestCommandUnicodeNormalization verifies that commands with zero-width
// invisible characters are normalized before PreFilter and rule matching.
func TestCommandUnicodeNormalization(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	cases := []struct {
		desc    string
		args    string
		blocked bool
	}{
		{
			"zero-width joiner in command does not break matching",
			// A benign "ls" command with a zero-width joiner should not cause issues.
			`{"command":"l` + "\u200D" + `s /tmp"}`,
			false,
		},
		{
			"fullwidth chars in command flagged as evasive",
			// Fullwidth "cat" — IsSuspiciousInput flags this as evasive during extraction.
			`{"command":"` + "\uff43\uff41\uff54" + ` /etc/passwd"}`,
			true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.desc, func(t *testing.T) {
			call := ToolCall{Name: "Bash", Arguments: []byte(tc.args)}
			result := engine.Evaluate(call)
			if tc.blocked && !result.Matched {
				t.Errorf("Expected BLOCKED but was ALLOWED")
			} else if !tc.blocked && result.Matched {
				t.Errorf("Expected ALLOWED but was BLOCKED by '%s'", result.RuleName)
			} else {
				t.Logf("PASS: result matched=%v rule='%s'", result.Matched, result.RuleName)
			}
		})
	}
}

// TestDLPScanner_PanicRecovery verifies that a panic inside the gitleaks
// detector is caught by recover() and Scan returns nil instead of crashing.
func TestDLPScanner_PanicRecovery(t *testing.T) {
	scanner, err := NewDLPScanner()
	if err != nil {
		t.Fatalf("NewDLPScanner: %v", err)
	}

	// Swap the detector with nil to force a nil-pointer panic inside Scan.
	scanner.detector = nil

	findings := scanner.Scan("AKIAIOSFODNN7REALKEY1")
	if findings != nil {
		t.Errorf("expected nil findings after panic recovery, got %d", len(findings))
	}

	// Scanner should still be usable after recovery.
	scans, _ := scanner.Stats()
	if scans != 1 {
		t.Errorf("scanCount = %d, want 1 (scan should be counted before panic)", scans)
	}
}

// TestDLPBugFixes verifies fixes for specific DLP pattern bugs.
func TestDLPBugFixes(t *testing.T) {
	engine, err := NewEngine(context.Background(), EngineConfig{DisableBuiltin: false})
	if err != nil {
		t.Fatalf("Failed to create engine: %v", err)
	}

	t.Run("Bug3: JWT pattern catches standard Auth0/Firebase JWT (intentional)", func(t *testing.T) {
		// A standard Auth0 JWT — not Turso-specific. The pattern intentionally
		// catches all JWTs as a security measure, and the rule is now named
		// "builtin:dlp-jwt-token" to reflect that.
		jwt := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9." +
			"eyJpc3MiOiJodHRwczovL2F1dGgwLmNvbS8iLCJzdWIiOiIxMjM0NTY3ODkwIiwiYXVkIjoiaHR0cHM6Ly9hcGkuZXhhbXBsZS5jb20ifQ." +
			"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		call := ToolCall{
			Name:      "Write",
			Arguments: []byte(`{"file_path":"/tmp/test.py","content":"TOKEN = '` + jwt + `'"}`),
		}
		result := engine.Evaluate(call)
		if !result.Matched {
			t.Errorf("Expected JWT to be blocked but was ALLOWED")
		} else if result.RuleName != "builtin:dlp-jwt-token" && result.RuleName != "builtin:dlp-gitleaks-jwt" {
			t.Errorf("Expected JWT rule, got '%s'", result.RuleName)
		} else {
			t.Logf("PASS: Standard JWT blocked by '%s' (intentional catch-all)", result.RuleName)
		}
	})

	t.Run("Bug4: base64 data starting with AX embedded in word not caught", func(t *testing.T) {
		// A base64-encoded string that happens to start with AX but is embedded
		// in a longer alphanumeric context (e.g., a hash or encoded blob).
		// After fix: word boundary prevents matching inside a larger word.
		call := ToolCall{
			Name:      "Write",
			Arguments: []byte(`{"file_path":"/tmp/test.py","content":"hash = 'PREFIX_AXabcdefghijklmnopqrstuvwxyz0123456789ABCDEF_SUFFIX'"}`),
		}
		result := engine.Evaluate(call)
		if result.Matched && result.RuleName == "builtin:dlp-upstash-token" {
			t.Errorf("False positive: Upstash pattern matched base64 data embedded in larger word")
		} else {
			t.Logf("PASS: embedded AX-prefixed data not falsely caught as Upstash token")
		}
	})

	t.Run("Bug4: standalone Upstash token still caught", func(t *testing.T) {
		// Real standalone Upstash token should still be caught.
		call := ToolCall{
			Name:      "Write",
			Arguments: []byte(`{"file_path":"/tmp/test.env","content":"UPSTASH_TOKEN=AX` + "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrst" + `"}`),
		}
		result := engine.Evaluate(call)
		if !result.Matched {
			t.Errorf("Expected Upstash token to be blocked but was ALLOWED")
		} else {
			t.Logf("PASS: standalone Upstash token blocked by '%s'", result.RuleName)
		}
	})

	t.Run("Bug20: SKvariable_name + hex does not false positive", func(t *testing.T) {
		// A Go variable like "SKippedCount" followed by hex-like chars in the
		// surrounding code should not trigger the Twilio pattern.
		call := ToolCall{
			Name:      "Write",
			Arguments: []byte(`{"file_path":"/tmp/test.go","content":"var SKippedItemsaabbccddeeff00112233 = 0"}`),
		}
		result := engine.Evaluate(call)
		if result.Matched && result.RuleName == "builtin:dlp-twilio-api-key" {
			t.Errorf("False positive: Twilio pattern matched 'SKippedItems...' variable name")
		} else {
			t.Logf("PASS: SK in variable name not falsely caught as Twilio key")
		}
	})

	t.Run("Bug20: standalone Twilio key still caught", func(t *testing.T) {
		call := ToolCall{
			Name:      "Write",
			Arguments: []byte(`{"file_path":"/tmp/test.env","content":"TWILIO_KEY=SK` + "aabbccddeeff00112233445566778899" + `"}`),
		}
		result := engine.Evaluate(call)
		if !result.Matched {
			t.Errorf("Expected Twilio key to be blocked but was ALLOWED")
		} else {
			t.Logf("PASS: standalone Twilio key blocked by '%s'", result.RuleName)
		}
	})

	t.Run("Bug21: re_compile_result_handler does not false positive", func(t *testing.T) {
		// A Go/Python identifier like "re_compile_result_handler_for_test" should not
		// trigger the Resend API key pattern.
		call := ToolCall{
			Name:      "Write",
			Arguments: []byte(`{"file_path":"/tmp/test.py","content":"def re_compile_result_handler_for_tests(): pass"}`),
		}
		result := engine.Evaluate(call)
		if result.Matched && result.RuleName == "builtin:dlp-resend-api-key" {
			t.Errorf("False positive: Resend pattern matched 're_compile_result_handler...' identifier")
		} else {
			t.Logf("PASS: re_ in identifier not falsely caught as Resend key")
		}
	})

	t.Run("Bug21: standalone Resend key still caught", func(t *testing.T) {
		call := ToolCall{
			Name:      "Write",
			Arguments: []byte(`{"file_path":"/tmp/test.env","content":"RESEND_KEY=re_` + "ABCDEFGHIJKLMNOPQRSTUVWXYZab" + `"}`),
		}
		result := engine.Evaluate(call)
		if !result.Matched {
			t.Errorf("Expected Resend key to be blocked but was ALLOWED")
		} else {
			t.Logf("PASS: standalone Resend key blocked by '%s'", result.RuleName)
		}
	})

	t.Run("Bug22: FHIR pattern works on normal-sized input", func(t *testing.T) {
		// Use json.Marshal to properly embed the FHIR JSON as a string value
		fhirBundle := `{"resourceType": "Bundle", "id": "example", "type": "searchset", "entry": []}`
		args, _ := json.Marshal(map[string]string{"file_path": "/tmp/fhir.json", "content": fhirBundle})
		call := ToolCall{
			Name:      "Write",
			Arguments: args,
		}
		result := engine.Evaluate(call)
		if !result.Matched {
			t.Errorf("Expected FHIR bundle to be blocked but was ALLOWED")
		} else {
			t.Logf("PASS: FHIR bundle blocked by '%s'", result.RuleName)
		}
	})

	t.Run("Bug22: FHIR pattern does not catastrophic backtrack on large non-matching input", func(t *testing.T) {
		// Build a large JSON-like input that starts with resourceType:Bundle
		// but never has the matching "type" field — this would cause catastrophic
		// backtracking with unbounded [\s\S]*? but is fine with the {0,5000} limit.
		large := `{"resourceType": "Bundle", ` + strings.Repeat(`"data": "x", `, 1000) + `"end": true}`
		args, _ := json.Marshal(map[string]string{"file_path": "/tmp/large.json", "content": large})
		call := ToolCall{
			Name:      "Write",
			Arguments: args,
		}
		// This should complete quickly (not hang) and not match since "type" is absent.
		result := engine.Evaluate(call)
		if result.Matched && result.RuleName == "builtin:dlp-fhir-bundle" {
			t.Errorf("FHIR pattern should not match input without proper type field")
		} else {
			t.Logf("PASS: large non-matching input handled without issue")
		}
	})
}
