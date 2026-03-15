# How It Works

## Architecture

```text
                    REQUEST SIDE                         RESPONSE SIDE
                         │                                    │
Agent Request ──▶ [Layer 0: History Scan] ──▶ LLM ──▶ [Layer 1: Rules] ──▶ Execute
                         │                                    │
                      ↓ BLOCK                              ↓ BLOCK
                   (14-30μs)                             (14-30μs)
               "Bad agent detected"                   "Action blocked"

                    MANAGEMENT API
                         │
                   SQLite DB ──▶ [Layer 2: Privacy] ──▶ API Response
                                       │
                                    ↓ STRIP
                             Sensitive attributes,
                             tool arguments, URL params

Rule Evaluation:
  1.  Self-protection pre-checker → regex on raw JSON (loopback + crust)
  2.  Sanitize tool name → strip null bytes, control chars
  3.  Extract paths, hosts, commands, content from tool arguments
  4.  DNS loopback detection → resolve hosts, block if loopback + crust
  5.  Normalize Unicode → NFKC, strip invisible chars and confusables
  6.  Block null bytes in write content
  7.  Block evasive commands (fork bombs, unparseable shell)
  8.  Detect encoding obfuscation (base64, hex)
  9.  DLP Secret Detection → API keys/tokens + crypto keys (BIP39, xprv, WIF)
  10. Prepare paths → filter shell globs, normalize, expand filesystem globs
  11. Resolve symlinks → match both original and resolved
  12. Hardcoded path guards → /proc, crypto wallets (after symlink resolution)
  13. Operation-based rules → path/command/host matching
  14. Fallback rules (content-only) → raw JSON matching for ANY tool
```

**Layer 0 (Request History):** Scans tool_calls in conversation history. Catches "bad agent" patterns where malicious actions already occurred in past turns.

**Layer 2 (Privacy Sanitization):** All management API responses pass through `telemetry/sanitize.go` before leaving the process. Strips LLM message bodies (`input.value`, `output.value`), tool call arguments (`tool.parameters`), and URL query parameters (which may contain API keys). Raw data remains in the local SQLite database for forensic inspection via `sqlite3`. This layer protects against shoulder-surfing the TUI, API responses accidentally included in bug reports, and local processes scraping the management API.

**Rule Engine:** Evaluates tool calls through the pipeline above. Self-protection (steps 1 & 4) is injected via dependency injection to avoid circular imports. Hardcoded path guards (step 12) use a registry pattern — add new guards without modifying the pipeline.

**[MCP Gateway](mcp.md) (`crust mcp gateway`):** Wraps [MCP](https://modelcontextprotocol.io) servers as a transparent stdio proxy. Inspects both directions — client→server requests (`tools/call`, `resources/read`) and server→client responses (DLP secret scanning). Works with any MCP server (filesystem, database, custom).

**[MCP HTTP Gateway](mcp.md) (`crust mcp http`):** Reverse proxy for [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports) MCP servers. Includes hardcoded CSRF protection — validates `Origin` and `Sec-Fetch-Site` headers on all requests including WebSocket upgrades, blocking cross-origin browser attacks (CVE-2025-49596, CVE-2026-25253). Non-browser MCP SDK clients are unaffected.

**[ACP Mode](acp.md) (`crust acp-wrap`):** Wraps [ACP](https://agentclientprotocol.com) agents as a transparent stdio proxy. Intercepts `fs/read_text_file`, `fs/write_text_file`, and `terminal/create` requests. Supports JetBrains IDEs and other ACP-compatible editors.

**Auto-detect (`crust wrap`):** Inspects both MCP and ACP methods in both directions. Response DLP scans all server responses for leaked secrets. Method names are disjoint — no conflict.

---

## Rule Schema (Progressive Disclosure)

```yaml
# Level 1: One-liner
- block: "**/.env"

# Level 2: With exceptions
- block: "**/.env"
  except: "**/.env.example"

# Level 3: With actions
- block: "/etc/**"
  actions: [delete]
  message: "Cannot delete system files"

# Level 4: Advanced match
- name: block-proc-access
  match:
    path: "re:/proc/\\d+/environ"
    tool: [Bash, Read]

# Level 5: Composite (AND/OR)
- name: block-symlink-bypass
  all:
    - command: "re:ln\\s+-s"
    - path: "/etc/**"

# Fallback Rules (Content-only) - matches ANY tool including MCP
- name: block-domain
  match:
    content: "malicious.com"  # Matches raw JSON args
  message: "Cannot access malicious.com"
```

### `$HOME` Variable

Path patterns support `$HOME` as a variable, expanded to the current user's home directory at engine startup. This protects only the running user's files and eliminates the need to enumerate OS-specific paths:

```yaml
- name: protect-ssh-keys
  block: "$HOME/.ssh/id_*"
  except: "$HOME/.ssh/id_*.pub"
  message: "Cannot access SSH private keys"
```

At init time, `$HOME` expands to the actual home directory:
- macOS: `/Users/yourname`
- Linux: `/home/yourname`
- Windows: `C:/Users/yourname`

Cross-OS app paths can all be listed under `$HOME` — wrong-OS patterns compile but never match at runtime:

```yaml
# Discord on all platforms — only the matching OS path fires
- "$HOME/Library/Application Support/discord/**"   # macOS
- "$HOME/.config/discord/**"                        # Linux
- "$HOME/AppData/Roaming/discord/**"                # Windows
```

`$HOME` is the only supported variable in path patterns. The linter rejects other variables (`$PATH`, `$USER`), braced syntax (`${HOME}`), and `$HOME` not at the start of a pattern.

---

## When Each Layer Blocks

| Attack | Layer 0 | Layer 1 | Layer 2 | MCP Gateway | ACP Mode |
|--------|---------|---------|---------|-------------|----------|
| Bad agent with secrets in history | ✅ Blocked | - | - | - | - |
| Poisoned conversation replay | ✅ Blocked | - | - | - | - |
| LLM generates `cat .env` | - | ✅ Blocked | - | - | - |
| LLM generates `rm -rf /etc` | - | ✅ Blocked | - | - | - |
| `$(cat .env)` obfuscation | - | ✅ Blocked | - | - | - |
| `eval "cat .env"` wrapping | - | ✅ Blocked (recursive parse) | - | - | - |
| Fork bomb `f(){ f|f& }; f` | - | ✅ Blocked (AST) | - | - | - |
| `echo payload \| base64 -d \| sh` | - | ✅ Blocked (pre-filter) | - | - | - |
| Hex-encoded command `$'\x63\x61\x74'` | - | ✅ Blocked (pre-filter) | - | - | - |
| Symlink bypass | - | ✅ Blocked (composite) | - | - | - |
| Leaking real API keys/tokens | - | ✅ Blocked (DLP) | - | ✅ Blocked (DLP) | ✅ Blocked (DLP) |
| MCP client reads `.env` | - | - | - | ✅ Blocked (inbound) | - |
| MCP client reads SSH keys | - | - | - | ✅ Blocked (inbound) | - |
| MCP `resources/read file:///etc/shadow` | - | - | - | ✅ Blocked (inbound) | - |
| MCP server returns API keys in results | - | - | - | ✅ Blocked (response DLP) | - |
| MCP server returns tokens in results | - | - | - | ✅ Blocked (response DLP) | - |
| ACP agent reads `.env` via IDE | - | - | - | - | ✅ Blocked |
| ACP agent reads SSH keys via IDE | - | - | - | - | ✅ Blocked |
| ACP agent runs `cat /etc/shadow` | - | - | - | - | ✅ Blocked |
| BIP39 mnemonic in content | - | ✅ Blocked (crypto DLP) | - | ✅ Blocked (DLP) | ✅ Blocked (DLP) |
| xprv/WIF private key in content | - | ✅ Blocked (crypto DLP) | - | ✅ Blocked (DLP) | ✅ Blocked (DLP) |
| Access `~/.bitcoin/wallet.dat` | - | ✅ Blocked (hardcoded) | - | - | - |
| Symlink to crypto wallet dir | - | ✅ Blocked (post-symlink) | - | - | - |
| vCard/iCalendar data in content | - | ✅ Blocked (DLP) | - | ✅ Blocked (DLP) | ✅ Blocked (DLP) |
| Apple mobileconfig payload | - | ✅ Blocked (DLP) | - | ✅ Blocked (DLP) | ✅ Blocked (DLP) |
| FHIR health data bundle | - | ✅ Blocked (DLP) | - | ✅ Blocked (DLP) | ✅ Blocked (DLP) |
| Mobile PII access (contacts, camera, etc.) | - | ✅ Blocked (rule) | - | - | - |
| Bluetooth/NFC hardware access | - | ✅ Blocked (rule) | - | - | - |
| Biometric auth bypass | - | ✅ Blocked (rule) | - | - | - |
| Unauthorized in-app purchase | - | ✅ Blocked (rule) | - | - | - |
| Secret leaked in AI text response | - | ✅ Redacted (text DLP) | - | - | - |
| Secret in OpenAI message.content | - | ✅ Redacted (text DLP) | - | - | - |
| Secret in Responses output_text | - | ✅ Redacted (text DLP) | - | - | - |
| User pastes API key into AI chat | - | ✅ Blocked (outbound DLP) | - | - | - |
| Phishing URL in AI text (tel:, sms:) | - | ✅ Blocked (URL validation) | - | - | - |
| Custom DNS → 127.0.0.1 targeting crust API | - | ✅ Blocked (DNS resolve) | - | - | - |
| LLM messages in API response | - | - | ✅ Stripped | - | - |
| Tool arguments in API response | - | - | ✅ Stripped | - | - |
| API keys in target URL params | - | - | ✅ Stripped | - | - |
| Absolute paths in rule metadata | - | - | ✅ Stripped | - | - |

---

## Shell Command Analysis

The rule engine uses a hybrid interpreter+AST approach to extract paths and operations from shell commands (Bash tool calls, `sh -c` wrappers, etc.).

**Interpreter mode:** A sandboxed shell interpreter expands variables, command substitutions, and tilde/glob patterns in dry-run mode. This produces fully expanded paths — `DIR=/tmp; ls $DIR` yields `/tmp`, not `$DIR`.

**AST fallback:** When a statement contains constructs unsafe for interpretation (process substitution `<()`, background `&`, heredocs, coprocs, fd redirects), the parser falls back to AST extraction which reads literal text from the syntax tree.

**Hybrid mode:** When a script mixes safe and unsafe statements, the engine runs the interpreter on safe statements (preserving variable expansion) and uses AST fallback only for unsafe ones. Inner commands of process substitutions and coprocs are recursively interpreted when possible.

```text
DIR=/tmp; diff <(ls $DIR) <(ls $DIR/sub)

Without hybrid:  diff, ls (literal — $DIR unexpanded)
With hybrid:     diff, ls /tmp, ls /tmp/sub (fully expanded)
```

### Evasion Detection

The shell parser detects several evasion techniques at the AST level:

| Technique | Detection |
|-----------|-----------|
| **Fork bombs** | AST walk detects self-recursive `FuncDecl` (e.g., `bomb(){ bomb\|bomb& }; bomb`) |
| **Eval wrapping** | `eval` args are joined and recursively parsed as shell code (like `sh -c`) |
| **Base64 encoding** | Pre-filter regex catches `base64 -d` / `base64 --decode` patterns |
| **Hex encoding** | Pre-filter catches 3+ consecutive `\xNN` escape sequences |

Evasion techniques (fork bombs, eval) are detected at the AST level (step 6) after parsing. The pre-filter runs next (step 7) and catches encoding-based obfuscation where the actual command is hidden in encoded form — invisible to the parser at parse time.

---

## DLP Secret Detection

Step 9 of the evaluation pipeline runs DLP (Data Loss Prevention) patterns against all operations. These patterns detect real API keys, tokens, and cryptocurrency secrets by their format, regardless of file path or tool name.

In stdio proxy modes (MCP Gateway, ACP Wrap, Auto-detect), DLP also scans **server/agent responses** before they reach the client. This catches secrets leaked by the subprocess — for example, an MCP server returning file content that contains an AWS access key. The response is replaced with a JSON-RPC error so the secret never reaches the client.

| Provider | Pattern |
|----------|---------|
| AWS | Access key IDs (`AKIA...`, `ASIA...`) |
| GitHub | Personal access tokens, fine-grained tokens (`ghp_...`, `github_pat_...`) |
| GitLab | Personal access tokens (`glpat-...`) |
| Slack | Bot/app tokens, webhook URLs |
| Stripe | Live keys, webhook signing secrets (`sk_live_...`, `whsec_...`) |
| Google | API keys (`AIza...`) |
| SendGrid | API keys (`SG....`) |
| Heroku | API keys (`heroku_...`) |
| OpenAI | Project keys, admin keys (`sk-proj-...`, `sk-admin-...`) |
| Anthropic | API keys (`sk-ant-api03-...`) |
| Shopify | Shared secrets, access tokens (`shpss_...`, `shpat_...`) |
| Databricks | Access tokens (`dapi...`) |
| PyPI | Upload tokens (`pypi-...`) |
| npm | Auth tokens (`npm_...`) |
| age | Secret keys (`AGE-SECRET-KEY-...`) |
| Private keys | PEM format (RSA, EC, DSA, OpenSSH, Ed25519) |
| HuggingFace | API tokens (`hf_...`) |
| Groq | API keys (`gsk_...`) |
| Vercel | Tokens (`vercel_...`) |
| Supabase | Service keys (`sbp_...`) |
| DigitalOcean | PATs, OAuth tokens (`dop_v1_...`, `doo_v1_...`) |
| HashiCorp Vault | Tokens (`hvs....`) |
| Linear | API keys (`lin_api_...`) |
| Postman | API keys (`PMAK-...`) |
| Replicate | API tokens (`r8_...`) |
| Twilio | API keys (`SK...`) |
| Doppler | Tokens (`dp.st....`) |
| Firebase | Cloud Messaging keys (`AAAA...:...`) |
| PlanetScale | Database tokens (`pscale_tkn_...`) |
| Resend | API keys (`re_...`) |
| Fly.io | Tokens (`fo1_...`) |
| Railway | Tokens (`railway_...`) |
| Clerk | Secret keys (`sk_live_...`) |
| Upstash | Redis/Kafka tokens (`AX...`) |
| Turso/LibSQL | Auth tokens (JWT format) |
| Neon | Database tokens (`neon_...`) |
| vCard | Contact data export (`BEGIN:VCARD`) |
| iCalendar | Calendar event export (`BEGIN:VCALENDAR`) |
| Apple mobileconfig | Configuration Profiles (`PayloadType: Configuration`) |
| HL7 FHIR | Health data bundles (`resourceType: Bundle`) |

Tier 1 patterns (46 hardcoded) are sourced from [gitleaks v8.24](https://github.com/gitleaks/gitleaks) and extended for newer services and mobile PII formats (vCard, iCalendar, FHIR health data, Apple Configuration Profiles). See `internal/rules/dlp.go` for the full list.

[gitleaks](https://github.com/gitleaks/gitleaks) is integrated as an in-process Go library, providing 200+ additional token formats beyond the hardcoded patterns. No external binary is required.

### Cryptocurrency Key Detection

Step 8 also runs crypto-specific DLP with **cryptographic validation** — not just regex matching. This eliminates false positives by verifying checksums.

| Type | Detection | Validation |
|------|-----------|------------|
| BIP39 mnemonic | Sliding window (12/15/18/21/24 words) | Embedded 10-language wordlist (20,480 words) |
| Extended private key | `[xyzt]prv` prefix match | base58check checksum via btcutil |
| WIF private key | `[5KL]` prefix match | base58check checksum + version byte (0x80/0xEF) |

BIP39 mnemonics are the universal seed phrase standard used by Bitcoin, Ethereum, Solana, Cardano, Cosmos, Polkadot, and most other chains. See `internal/rules/dlp_crypto.go` for the implementation.

### Crypto Wallet Path Protection

Step 12 blocks access to sensitive path prefixes including `/proc` and cryptocurrency wallet directories. Paths are computed at init using OS-specific data directories (e.g., `~/Library/Application Support/Bitcoin/` on macOS, `~/.bitcoin/` on Linux, `%LOCALAPPDATA%\Bitcoin` on Windows). This check runs **after symlink resolution** (step 11) so symlink bypasses are caught. New guards can be added to the `pathGuards` registry without modifying the pipeline.

Protected chains: Bitcoin, Litecoin, Dogecoin, Dash, Ethereum, Electrum, Monero, Zcash, Cardano, Cosmos, Polkadot, Avalanche, Tron, Solana, Sui, Aptos.

---

## Built-in Rule Principles

1. **Protect secrets first** - Credentials are the #1 target; block all access paths
2. **Prevent persistence** - Stop attackers from surviving reboots (cron, systemd, RC files)
3. **Block lateral movement** - Internal networks, cloud metadata, container escapes
4. **Allow legitimate dev work** - Never block normal coding tasks; use exceptions for `.example` files
5. **Fail safe** - When in doubt, block and explain why

---

## Protection Categories (Examples)

The rule engine can protect against various attack vectors:

| Category | Examples |
|----------|----------|
| Credentials | .env, SSH keys, cloud creds, tokens, DLP secret detection |
| System | `/etc/passwd`, `/etc/shadow`, binaries, kernel modules, boot |
| Crypto Wallets | BIP39 mnemonics, xprv/WIF keys, wallet.dat, keystore (16 chains) |
| Persistence | Shell RC, cron, systemd, git hooks, mobile background tasks |
| Privilege Escalation | Sudoers, PAM, LD_PRELOAD |
| Container Escape | Docker/containerd sockets |
| Network | Internal networks, cloud metadata |
| Mobile | PII (contacts, photos, calendar, location, health, camera, microphone, call log, SMS), keychain, clipboard, URL schemes, Bluetooth/NFC, biometric auth, in-app purchases |

See `internal/rules/builtin/security.yaml` for path rules, `internal/rules/dlp.go` for token patterns, and `internal/rules/dlp_crypto.go` for crypto key detection.

