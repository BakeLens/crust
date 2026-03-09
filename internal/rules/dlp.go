package rules

//go:generate go run dlp_verify.go

import "regexp"

// Hardcoded DLP (Data Loss Prevention) token detection patterns.
// Compiled at init, checked on all operations (Tier 1).
// Core patterns sourced from gitleaks v8.24, extended for newer AI/cloud services.
// Curated for blocking (not warning) — each pattern must have a distinctive prefix
// to avoid false positives.

type dlpPattern struct {
	name    string
	re      *regexp.Regexp
	message string
}

var dlpPatterns = []dlpPattern{
	// AWS
	{
		name:    "builtin:dlp-aws-access-key",
		re:      regexp.MustCompile(`(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}`),
		message: "Cannot write AWS access key — potential credential leak",
	},

	// GitHub
	{
		name:    "builtin:dlp-github-token",
		re:      regexp.MustCompile(`(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255}`),
		message: "Cannot write GitHub token — potential credential leak",
	},
	{
		name:    "builtin:dlp-github-fine-grained-token",
		re:      regexp.MustCompile(`github_pat_[A-Za-z0-9_]{82,}`),
		message: "Cannot write GitHub fine-grained token — potential credential leak",
	},

	// Slack
	{
		name:    "builtin:dlp-slack-token",
		re:      regexp.MustCompile(`xox[bpas]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{20,}`),
		message: "Cannot write Slack token — potential credential leak",
	},
	{
		name:    "builtin:dlp-slack-webhook",
		re:      regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[a-zA-Z0-9]{20,}`),
		message: "Cannot write Slack webhook URL — potential credential leak",
	},

	// Stripe
	{
		name:    "builtin:dlp-stripe-live-key",
		re:      regexp.MustCompile(`(?:sk|pk|rk)_live_[a-zA-Z0-9]{20,}`),
		message: "Cannot write Stripe live key — potential credential leak",
	},

	// Google
	{
		name:    "builtin:dlp-google-api-key",
		re:      regexp.MustCompile(`AIza[A-Za-z0-9_\-]{35}`),
		message: "Cannot write Google API key — potential credential leak",
	},

	// SendGrid
	{
		name:    "builtin:dlp-sendgrid-api-key",
		re:      regexp.MustCompile(`SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`),
		message: "Cannot write SendGrid API key — potential credential leak",
	},

	// Heroku
	{
		name:    "builtin:dlp-heroku-api-key",
		re:      regexp.MustCompile(`heroku_[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`),
		message: "Cannot write Heroku API key — potential credential leak",
	},

	// GitLab
	{
		name:    "builtin:dlp-gitlab-pat",
		re:      regexp.MustCompile(`glpat-[A-Za-z0-9_\-]{20,}`),
		message: "Cannot write GitLab personal access token — potential credential leak",
	},

	// PyPI
	{
		name:    "builtin:dlp-pypi-token",
		re:      regexp.MustCompile(`pypi-[A-Za-z0-9_\-]{50,}`),
		message: "Cannot write PyPI token — potential credential leak",
	},

	// npm
	{
		name:    "builtin:dlp-npm-token",
		re:      regexp.MustCompile(`npm_[A-Za-z0-9]{36}`),
		message: "Cannot write npm token — potential credential leak",
	},

	// Shopify
	{
		name:    "builtin:dlp-shopify-shared-secret",
		re:      regexp.MustCompile(`shpss_[a-fA-F0-9]{32}`),
		message: "Cannot write Shopify shared secret — potential credential leak",
	},
	{
		name:    "builtin:dlp-shopify-access-token",
		re:      regexp.MustCompile(`shpat_[a-fA-F0-9]{32}`),
		message: "Cannot write Shopify access token — potential credential leak",
	},

	// Databricks
	{
		name:    "builtin:dlp-databricks-token",
		re:      regexp.MustCompile(`dapi[a-f0-9]{32}`),
		message: "Cannot write Databricks token — potential credential leak",
	},

	// Anthropic (api03, api04, … — version-flexible prefix)
	{
		name:    "builtin:dlp-anthropic-api-key",
		re:      regexp.MustCompile(`sk-ant-api\d{2}-[A-Za-z0-9_\-]{90,}`),
		message: "Cannot write Anthropic API key — potential credential leak",
	},

	// OpenAI
	{
		name:    "builtin:dlp-openai-project-key",
		re:      regexp.MustCompile(`sk-proj-[A-Za-z0-9_\-]{40,}`),
		message: "Cannot write OpenAI project key — potential credential leak",
	},

	// Stripe webhook signing secret
	{
		name:    "builtin:dlp-stripe-webhook-secret",
		re:      regexp.MustCompile(`whsec_[A-Za-z0-9]{20,}`),
		message: "Cannot write Stripe webhook secret — potential credential leak",
	},

	// age encryption
	{
		name:    "builtin:dlp-age-secret-key",
		re:      regexp.MustCompile(`AGE-SECRET-KEY-[A-Z0-9]{59}`),
		message: "Cannot write age secret key — potential credential leak",
	},

	// Private keys (PEM format) — fires on ALL operations, not just writes.
	// Catches RSA, EC, DSA, OpenSSH, Ed25519, and generic PRIVATE KEY headers.
	{
		name:    "builtin:dlp-private-key",
		re:      regexp.MustCompile(`-----BEGIN[A-Z ]* PRIVATE KEY-----`),
		message: "Cannot expose private key — potential credential leak",
	},

	// HuggingFace
	{
		name:    "builtin:dlp-huggingface-token",
		re:      regexp.MustCompile(`hf_[A-Za-z0-9]{34,}`),
		message: "Cannot write HuggingFace token — potential credential leak",
	},

	// Groq
	{
		name:    "builtin:dlp-groq-api-key",
		re:      regexp.MustCompile(`gsk_[A-Za-z0-9]{48,}`),
		message: "Cannot write Groq API key — potential credential leak",
	},

	// Vercel
	{
		name:    "builtin:dlp-vercel-token",
		re:      regexp.MustCompile(`vercel_[A-Za-z0-9]{20,}`),
		message: "Cannot write Vercel token — potential credential leak",
	},

	// Supabase
	{
		name:    "builtin:dlp-supabase-key",
		re:      regexp.MustCompile(`sbp_[a-f0-9]{40,}`),
		message: "Cannot write Supabase key — potential credential leak",
	},

	// DigitalOcean
	{
		name:    "builtin:dlp-digitalocean-pat",
		re:      regexp.MustCompile(`dop_v1_[a-f0-9]{64}`),
		message: "Cannot write DigitalOcean token — potential credential leak",
	},
	{
		name:    "builtin:dlp-digitalocean-oauth",
		re:      regexp.MustCompile(`doo_v1_[a-f0-9]{64}`),
		message: "Cannot write DigitalOcean OAuth token — potential credential leak",
	},

	// HashiCorp Vault
	{
		name:    "builtin:dlp-hashicorp-vault",
		re:      regexp.MustCompile(`hvs\.[A-Za-z0-9_\-]{24,}`),
		message: "Cannot write HashiCorp Vault token — potential credential leak",
	},

	// Linear
	{
		name:    "builtin:dlp-linear-api-key",
		re:      regexp.MustCompile(`lin_api_[A-Za-z0-9]{40,}`),
		message: "Cannot write Linear API key — potential credential leak",
	},

	// Postman
	{
		name:    "builtin:dlp-postman-api-key",
		re:      regexp.MustCompile(`PMAK-[A-Za-z0-9]{24,}`),
		message: "Cannot write Postman API key — potential credential leak",
	},

	// Replicate
	{
		name:    "builtin:dlp-replicate-api-token",
		re:      regexp.MustCompile(`r8_[A-Za-z0-9]{36,}`),
		message: "Cannot write Replicate API token — potential credential leak",
	},

	// Twilio
	{
		name:    "builtin:dlp-twilio-api-key",
		re:      regexp.MustCompile(`SK[a-fA-F0-9]{32}`),
		message: "Cannot write Twilio API key — potential credential leak",
	},

	// Doppler
	{
		name:    "builtin:dlp-doppler-token",
		re:      regexp.MustCompile(`dp\.st\.[a-zA-Z0-9_\-]{40,}`),
		message: "Cannot write Doppler token — potential credential leak",
	},

	// OpenAI admin key
	{
		name:    "builtin:dlp-openai-admin-key",
		re:      regexp.MustCompile(`sk-admin-[A-Za-z0-9_\-]{40,}`),
		message: "Cannot write OpenAI admin key — potential credential leak",
	},

	// Firebase Cloud Messaging
	{
		name:    "builtin:dlp-firebase-key",
		re:      regexp.MustCompile(`AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140,}`),
		message: "Cannot write Firebase key — potential credential leak",
	},

	// PlanetScale
	{
		name:    "builtin:dlp-planetscale-token",
		re:      regexp.MustCompile(`pscale_tkn_[A-Za-z0-9_\-]{30,}`),
		message: "Cannot write PlanetScale token — potential credential leak",
	},

	// Resend
	{
		name:    "builtin:dlp-resend-api-key",
		re:      regexp.MustCompile(`re_[A-Za-z0-9]{20,}`),
		message: "Cannot write Resend API key — potential credential leak",
	},

	// Fly.io
	{
		name:    "builtin:dlp-flyio-token",
		re:      regexp.MustCompile(`fo1_[A-Za-z0-9_\-]{40,}`),
		message: "Cannot write Fly.io token — potential credential leak",
	},

	// Railway
	{
		name:    "builtin:dlp-railway-token",
		re:      regexp.MustCompile(`railway_[A-Za-z0-9_\-]{20,}`),
		message: "Cannot write Railway token — potential credential leak",
	},

	// Clerk
	{
		name:    "builtin:dlp-clerk-secret-key",
		re:      regexp.MustCompile(`sk_live_[A-Za-z0-9]{20,}`),
		message: "Cannot write Clerk secret key — potential credential leak",
	},

	// Upstash
	{
		name:    "builtin:dlp-upstash-token",
		re:      regexp.MustCompile(`AX[A-Za-z0-9]{40,}`),
		message: "Cannot write Upstash token — potential credential leak",
	},

	// Turso/LibSQL
	{
		name:    "builtin:dlp-turso-token",
		re:      regexp.MustCompile(`eyJhbGciOi[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{50,}\.[A-Za-z0-9_\-]{20,}`),
		message: "Cannot write Turso/LibSQL auth token — potential credential leak",
	},

	// Neon
	{
		name:    "builtin:dlp-neon-token",
		re:      regexp.MustCompile(`neon_[A-Za-z0-9_\-]{30,}`),
		message: "Cannot write Neon database token — potential credential leak",
	},

	// Add new patterns above this line.
}
