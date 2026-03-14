//go:build ignore

// This program verifies DLP regex pattern integrity: compilation, match/no-match
// test vectors, and pattern count. Run via go generate.
package main

import (
	"crypto/sha512"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// expectedPatternCount is the number of DLP patterns in dlp.go.
const expectedPatternCount = 46

// dlpVector defines a test vector for a single DLP pattern.
type dlpVector struct {
	name    string   // pattern name (builtin:dlp-*)
	regex   string   // raw regex string (must compile)
	mustHit []string // strings that MUST match
	mustMis []string // strings that MUST NOT match
}

// pad returns a string of n repeated '0' characters. Used to construct
// test vectors at runtime so no single string literal triggers GitHub
// push protection's secret scanning.
func pad(n int) string { return strings.Repeat("0", n) }

// vectors contains test vectors for all 46 DLP patterns.
// Vectors are built with pad() to avoid triggering secret scanners.
var vectors = []dlpVector{
	{
		name:  "builtin:dlp-aws-access-key",
		regex: `(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`,
		mustHit: []string{
			"AKIA" + strings.Repeat("A", 16),
			"ASIA" + strings.Repeat("B", 16),
			"A3T2" + strings.Repeat("C", 16),
		},
		mustMis: []string{
			"AKIA_SHORT",
			"akiaiosfodnn7example",
			"RANDOMSTRING1234567",
		},
	},
	{
		name:  "builtin:dlp-github-token",
		regex: `(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`,
		mustHit: []string{
			"ghp_" + pad(36),
			"gho_" + pad(36),
			"ghs_" + pad(36),
		},
		mustMis: []string{
			"ghp_short",
			"ghx_" + pad(36),
		},
	},
	{
		name:  "builtin:dlp-github-fine-grained-token",
		regex: `github_pat_[A-Za-z0-9_]{82,}`,
		mustHit: []string{
			"github_pat_01" + pad(82),
		},
		mustMis: []string{
			"github_pat_short",
			"github_pat_01" + pad(8),
		},
	},
	{
		name:  "builtin:dlp-slack-token",
		regex: `xox[bpas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,}`,
		mustHit: []string{
			"xoxb-" + pad(13) + "-" + pad(13) + "-" + strings.Repeat("A", 20),
			"xoxp-" + pad(10) + "-" + pad(10) + "-" + strings.Repeat("A", 20),
		},
		mustMis: []string{
			"xoxb-123-123-short",
			"xoxz-1234567890-1234567890-00000000000000000000",
		},
	},
	{
		name:  "builtin:dlp-slack-webhook",
		regex: `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}`,
		mustHit: []string{
			"https://hooks.slack.com/services/T" + pad(9) + "/B" + pad(9) + "/" + strings.Repeat("a", 26),
		},
		mustMis: []string{
			"https://hooks.slack.com/services/T01/B01/short",
			"https://example.com/services/T000000000/B000000000/aaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
	},
	{
		name:  "builtin:dlp-stripe-live-key",
		regex: `(?:sk|pk|rk)_live_[a-zA-Z0-9]{20,}`,
		mustHit: []string{
			"sk_live_" + pad(26),
			"pk_live_" + pad(26),
			"rk_live_" + pad(26),
		},
		mustMis: []string{
			"sk_test_" + pad(26),
			"sk_live_short",
		},
	},
	{
		name:  "builtin:dlp-google-api-key",
		regex: `AIza[A-Za-z0-9_\-]{35}`,
		mustHit: []string{
			"AIzaSy" + pad(35),
		},
		mustMis: []string{
			"AIzaShort",
			"BIzaSy" + pad(35),
		},
	},
	{
		name:  "builtin:dlp-sendgrid-api-key",
		regex: `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`,
		mustHit: []string{
			"SG." + pad(22) + "." + pad(43),
		},
		mustMis: []string{
			"SG.short.short",
			"XX." + pad(22) + "." + pad(43),
		},
	},
	{
		name:  "builtin:dlp-heroku-api-key",
		regex: `heroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,
		mustHit: []string{
			"heroku_" + pad(8) + "-" + pad(4) + "-" + pad(4) + "-" + pad(4) + "-" + pad(12),
		},
		mustMis: []string{
			"heroku_short",
			"a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
	},
	{
		name:  "builtin:dlp-gitlab-pat",
		regex: `glpat-[A-Za-z0-9_\-]{20,}`,
		mustHit: []string{
			"glpat-" + pad(25),
		},
		mustMis: []string{
			"glpat-short",
			"gltoken-" + pad(25),
		},
	},
	{
		name:  "builtin:dlp-pypi-token",
		regex: `pypi-[A-Za-z0-9_\-]{50,}`,
		mustHit: []string{
			"pypi-" + strings.Repeat("A", 55),
		},
		mustMis: []string{
			"pypi-short",
		},
	},
	{
		name:  "builtin:dlp-npm-token",
		regex: `npm_[A-Za-z0-9]{36}`,
		mustHit: []string{
			"npm_" + pad(36),
		},
		mustMis: []string{
			"npm_short",
			"npm_version",
		},
	},
	{
		name:  "builtin:dlp-shopify-shared-secret",
		regex: `shpss_[a-fA-F0-9]{32}`,
		mustHit: []string{
			"shpss_" + pad(32),
		},
		mustMis: []string{
			"shpss_short",
		},
	},
	{
		name:  "builtin:dlp-shopify-access-token",
		regex: `shpat_[a-fA-F0-9]{32}`,
		mustHit: []string{
			"shpat_" + pad(32),
		},
		mustMis: []string{
			"shpat_short",
		},
	},
	{
		name:  "builtin:dlp-databricks-token",
		regex: `dapi[a-f0-9]{32}`,
		mustHit: []string{
			"dapi" + pad(32),
		},
		mustMis: []string{
			"dapishort",
			"dapibus",
		},
	},
	{
		name:  "builtin:dlp-anthropic-api-key",
		regex: `sk-ant-api\d{2}-[A-Za-z0-9_\-]{90,}`,
		mustHit: []string{
			"sk-ant-api03-" + strings.Repeat("A", 90),
			"sk-ant-api04-" + strings.Repeat("B", 100),
		},
		mustMis: []string{
			"sk-ant-api03-short",
			"sk-ant-apiXX-" + strings.Repeat("A", 90),
		},
	},
	{
		name:  "builtin:dlp-openai-project-key",
		regex: `sk-proj-[A-Za-z0-9_\-]{40,}`,
		mustHit: []string{
			"sk-proj-" + pad(40),
		},
		mustMis: []string{
			"sk-proj-short",
		},
	},
	{
		name:  "builtin:dlp-stripe-webhook-secret",
		regex: `whsec_[A-Za-z0-9]{20,}`,
		mustHit: []string{
			"whsec_" + pad(26),
		},
		mustMis: []string{
			"whsec_short",
		},
	},
	{
		name:  "builtin:dlp-age-secret-key",
		regex: `AGE-SECRET-KEY-[A-Z0-9]{59}`,
		mustHit: []string{
			"AGE-SECRET-KEY-1" + strings.Repeat("Q", 58),
		},
		mustMis: []string{
			"AGE-SECRET-KEY-SHORT",
			"AGE-PUBLIC-KEY-1" + strings.Repeat("Q", 58),
		},
	},
	{
		name:  "builtin:dlp-private-key",
		regex: `-----BEGIN[A-Z ]* PRIVATE KEY-----`,
		mustHit: []string{
			"-----BEGIN RSA PRIVATE KEY-----",
			"-----BEGIN PRIVATE KEY-----",
			"-----BEGIN OPENSSH PRIVATE KEY-----",
			"-----BEGIN EC PRIVATE KEY-----",
		},
		mustMis: []string{
			"-----BEGIN CERTIFICATE-----",
			"-----BEGIN PUBLIC KEY-----",
			"-----BEGIN CERTIFICATE REQUEST-----",
		},
	},
	{
		name:  "builtin:dlp-huggingface-token",
		regex: `hf_[A-Za-z0-9]{34,}`,
		mustHit: []string{
			"hf_" + pad(34),
		},
		mustMis: []string{
			"hf_short",
			"half_width",
		},
	},
	{
		name:  "builtin:dlp-groq-api-key",
		regex: `gsk_[A-Za-z0-9]{48,}`,
		mustHit: []string{
			"gsk_" + pad(48),
		},
		mustMis: []string{
			"gsk_short",
		},
	},
	{
		name:  "builtin:dlp-vercel-token",
		regex: `vercel_[A-Za-z0-9]{20,}`,
		mustHit: []string{
			"vercel_" + pad(26),
		},
		mustMis: []string{
			"vercel_sdk",
			"vercel_short",
		},
	},
	{
		name:  "builtin:dlp-supabase-key",
		regex: `sbp_[a-f0-9]{40,}`,
		mustHit: []string{
			"sbp_" + pad(44),
		},
		mustMis: []string{
			"sbp_short",
		},
	},
	{
		name:  "builtin:dlp-digitalocean-pat",
		regex: `dop_v1_[a-f0-9]{64}`,
		mustHit: []string{
			"dop_v1_" + pad(64),
		},
		mustMis: []string{
			"dop_v1_short",
		},
	},
	{
		name:  "builtin:dlp-digitalocean-oauth",
		regex: `doo_v1_[a-f0-9]{64}`,
		mustHit: []string{
			"doo_v1_" + pad(64),
		},
		mustMis: []string{
			"doo_v1_short",
		},
	},
	{
		name:  "builtin:dlp-hashicorp-vault",
		regex: `hvs\.[A-Za-z0-9_\-]{24,}`,
		mustHit: []string{
			"hvs." + pad(30),
		},
		mustMis: []string{
			"hvs.short",
		},
	},
	{
		name:  "builtin:dlp-linear-api-key",
		regex: `lin_api_[A-Za-z0-9]{40,}`,
		mustHit: []string{
			"lin_api_" + pad(40),
		},
		mustMis: []string{
			"lin_api_short",
		},
	},
	{
		name:  "builtin:dlp-postman-api-key",
		regex: `PMAK-[A-Za-z0-9]{24,}`,
		mustHit: []string{
			"PMAK-" + pad(28),
		},
		mustMis: []string{
			"PMAK-short",
		},
	},
	{
		name:  "builtin:dlp-replicate-api-token",
		regex: `r8_[A-Za-z0-9]{36,}`,
		mustHit: []string{
			"r8_" + pad(40),
		},
		mustMis: []string{
			"r8_short",
		},
	},
	{
		name:  "builtin:dlp-twilio-api-key",
		regex: `SK[a-fA-F0-9]{32}`,
		mustHit: []string{
			"SK" + pad(32),
		},
		mustMis: []string{
			"SKshort",
			"SKU",
		},
	},
	{
		name:  "builtin:dlp-doppler-token",
		regex: `dp\.st\.[a-zA-Z0-9_\-]{40,}`,
		mustHit: []string{
			"dp.st." + pad(40) + "qrst",
		},
		mustMis: []string{
			"dp.st.short",
		},
	},
	{
		name:  "builtin:dlp-openai-admin-key",
		regex: `sk-admin-[A-Za-z0-9_\-]{40,}`,
		mustHit: []string{
			"sk-admin-" + pad(40) + "qrst",
		},
		mustMis: []string{
			"sk-admin-short",
		},
	},
	{
		name:  "builtin:dlp-firebase-key",
		regex: `AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}`,
		mustHit: []string{
			"AAAAABCDEFG:" + strings.Repeat("0000000000000000000000000000000000000000", 4),
		},
		mustMis: []string{
			"AAAA_PADDING",
			"AAAAABCDEFG:short",
		},
	},
	{
		name:  "builtin:dlp-planetscale-token",
		regex: `pscale_tkn_[A-Za-z0-9_\-]{30,}`,
		mustHit: []string{
			"pscale_tkn_" + pad(30),
		},
		mustMis: []string{
			"pscale_tkn_short",
		},
	},
	{
		name:  "builtin:dlp-resend-api-key",
		regex: `re_[A-Za-z0-9]{20,}`,
		mustHit: []string{
			"re_" + pad(26),
		},
		mustMis: []string{
			"re_short",
		},
	},
	{
		name:  "builtin:dlp-flyio-token",
		regex: `fo1_[A-Za-z0-9_\-]{40,}`,
		mustHit: []string{
			"fo1_" + pad(40) + "qrst",
		},
		mustMis: []string{
			"fo1_short",
		},
	},
	{
		name:  "builtin:dlp-railway-token",
		regex: `railway_[A-Za-z0-9_\-]{20,}`,
		mustHit: []string{
			"railway_" + pad(26),
		},
		mustMis: []string{
			"railway_short",
		},
	},
	{
		name:  "builtin:dlp-clerk-secret-key",
		regex: `sk_live_[A-Za-z0-9]{20,}`,
		mustHit: []string{
			"sk_live_" + pad(26),
		},
		mustMis: []string{
			"sk_live_short",
			"sk_test_" + pad(26),
		},
	},
	{
		name:  "builtin:dlp-upstash-token",
		regex: `AX[A-Za-z0-9]{40,}`,
		mustHit: []string{
			"AX" + pad(40) + "qrst",
		},
		mustMis: []string{
			"AXshort",
		},
	},
	{
		name:  "builtin:dlp-turso-token",
		regex: `eyJhbGciOi[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{20,}`,
		mustHit: []string{
			"eyJhbGciOi" + strings.Repeat("A", 50) + "." + strings.Repeat("B", 50) + "." + strings.Repeat("C", 20),
		},
		mustMis: []string{
			"eyJhbGciOishort.short.short",
		},
	},
	{
		name:  "builtin:dlp-neon-token",
		regex: `neon_[A-Za-z0-9_\-]{30,}`,
		mustHit: []string{
			"neon_" + pad(30) + "cdefgh",
		},
		mustMis: []string{
			"neon_short",
		},
	},
	// ── Mobile PII patterns ──
	{
		name:  "builtin:dlp-vcard",
		regex: `BEGIN:VCARD\r?\nVERSION:\d`,
		mustHit: []string{
			"BEGIN:VCARD\nVERSION:3",
			"BEGIN:VCARD\r\nVERSION:4",
			"BEGIN:VCARD\nVERSION:2",
		},
		mustMis: []string{
			"BEGIN:VCARD",           // missing VERSION line
			"BEGIN:VCALENDAR",       // wrong type
			"VCARD",                 // no BEGIN:
			"BEGIN:VCARD VERSION:3", // missing newline
		},
	},
	{
		name:  "builtin:dlp-icalendar",
		regex: `BEGIN:VCALENDAR\r?\nVERSION:\d`,
		mustHit: []string{
			"BEGIN:VCALENDAR\nVERSION:2",
			"BEGIN:VCALENDAR\r\nVERSION:2",
		},
		mustMis: []string{
			"BEGIN:VCALENDAR",           // missing VERSION
			"BEGIN:VCARD\nVERSION:3",    // wrong type
			"BEGIN:VCALENDAR VERSION:2", // missing newline
		},
	},
	{
		name:  "builtin:dlp-mobileconfig",
		regex: `<key>PayloadType</key>\s*<string>Configuration</string>`,
		mustHit: []string{
			"<key>PayloadType</key><string>Configuration</string>",
			"<key>PayloadType</key>\n\t\t<string>Configuration</string>",
			"<key>PayloadType</key> <string>Configuration</string>",
		},
		mustMis: []string{
			"<key>PayloadType</key><string>VPN</string>", // not Configuration
			"PayloadType Configuration",                  // not XML
			"<key>OtherKey</key><string>Configuration</string>",
		},
	},
	{
		name:  "builtin:dlp-fhir-bundle",
		regex: `"resourceType"\s*:\s*"Bundle"[\s\S]*?"type"\s*:\s*"(?:searchset|collection|document)"`,
		mustHit: []string{
			`"resourceType":"Bundle","type":"searchset"`,
			`"resourceType" : "Bundle", "id": "123", "type" : "collection"`,
			`"resourceType":"Bundle","meta":{},"type":"document"`,
		},
		mustMis: []string{
			`"resourceType":"Patient"`,                     // wrong resource
			`"resourceType":"Bundle","type":"transaction"`, // non-PII bundle type
			`"type":"searchset"`,                           // no resourceType
		},
	},
}

func main() {
	failed := 0

	// 1. Verify pattern count matches expected.
	if len(vectors) != expectedPatternCount {
		fmt.Fprintf(os.Stderr, "FAIL: vector count %d != expected %d\n", len(vectors), expectedPatternCount)
		failed++
	}

	// 2. Count patterns in dlp.go source by counting `name:` fields with "builtin:dlp-" prefix.
	data, err := os.ReadFile("dlp.go")
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAIL: cannot read dlp.go: %v\n", err)
		os.Exit(1)
	}

	sourceCount := 0
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, `name:`) && strings.Contains(trimmed, `"builtin:dlp-`) {
			sourceCount++
		}
	}
	if sourceCount != expectedPatternCount {
		fmt.Fprintf(os.Stderr, "FAIL: dlp.go has %d patterns, expected %d\n", sourceCount, expectedPatternCount)
		failed++
	}

	// 3. Verify SHA-512 of dlp.go source.
	hash := fmt.Sprintf("%x", sha512.Sum512(data))
	const expectedHash = "129d44e6902af86ed460dfd5af99ba1dd6905855cb1db318e0a71738d4ebb31566fbca793e34ea306c3ee2e51c7fe6589fa7e3ca09435d28c8b16b01b5db3399"
	if hash != expectedHash {
		fmt.Fprintf(os.Stderr, "FAIL: dlp.go SHA-512 mismatch\n  got:  %s\n  want: %s\n", hash, expectedHash)
		failed++
	}

	// 4. Compile each regex and test vectors.
	for i, v := range vectors {
		re, err := regexp.Compile(v.regex)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: [%d] %s: regex compile error: %v\n", i, v.name, err)
			failed++
			continue
		}

		for _, s := range v.mustHit {
			if !re.MatchString(s) {
				fmt.Fprintf(os.Stderr, "FAIL: [%d] %s: mustHit not matched: %q\n", i, v.name, s)
				failed++
			}
		}

		for _, s := range v.mustMis {
			if re.MatchString(s) {
				fmt.Fprintf(os.Stderr, "FAIL: [%d] %s: mustMis incorrectly matched: %q\n", i, v.name, s)
				failed++
			}
		}
	}

	// 5. Cross-check: verify each vector regex exists in dlp.go source.
	src := string(data)
	for i, v := range vectors {
		// Check the regex string appears in dlp.go (backtick-quoted).
		if !strings.Contains(src, v.regex) {
			fmt.Fprintf(os.Stderr, "FAIL: [%d] %s: regex not found in dlp.go source\n", i, v.name)
			failed++
		}
		// Check the pattern name appears in dlp.go.
		if !strings.Contains(src, v.name) {
			fmt.Fprintf(os.Stderr, "FAIL: [%d] %s: name not found in dlp.go source\n", i, v.name)
			failed++
		}
	}

	if failed > 0 {
		// Print SHA-512 to help update the expected hash.
		fmt.Fprintf(os.Stderr, "\ndlp.go SHA-512: %s\n", hash)
		fmt.Fprintf(os.Stderr, "\n%d DLP verification check(s) failed.\n", failed)
		os.Exit(1)
	}

	fmt.Printf("ok: all %d DLP patterns verified (compile + vectors + count + source cross-check)\n", len(vectors))
	fmt.Printf("dlp.go SHA-512: %s\n", hash)
}
