<p align="center">
  <img src="docs/banner.png" alt="Crust Banner" width="100%" />
</p>

<h1 align="center">Crust</h1>

<p align="center">
  <strong>Your agents should never <del>(try to)</del> read your secrets.</strong>
</p>

<p align="center">
  <a href="https://getcrust.io">Website</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#agent-setup">Agent Setup</a> •
  <a href="#protection">Protection</a> •
  <a href="#plugins">Plugins</a> •
  <a href="#documentation">Docs</a> •
  <a href="https://github.com/BakeLens/crust/issues">Issues</a> •
  <a href="https://github.com/BakeLens/crust/discussions">Discussions</a>
</p>

<p align="center">
  <a href="https://github.com/BakeLens/crust/actions/workflows/ci.yml"><img src="https://github.com/BakeLens/crust/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
<a href="https://goreportcard.com/report/github.com/BakeLens/crust"><img src="https://goreportcard.com/badge/github.com/BakeLens/crust" alt="Go Report Card" /></a>
  <a href="https://github.com/BakeLens/crust/releases"><img src="https://img.shields.io/github/v/release/BakeLens/crust" alt="Release" /></a>
  <img src="https://img.shields.io/github/go-mod/go-version/BakeLens/crust" alt="Go Version" />
  <img src="https://img.shields.io/badge/License-Elastic%202.0-blue.svg" alt="License" />
  <img src="https://img.shields.io/badge/Platform-macOS%2012%2B%20%7C%20Linux%20%7C%20Windows%2010%2B%20%7C%20FreeBSD%2014%2B-lightgrey" alt="Platform" />
</p>

<p align="center">
  <a href="https://github.com/BakeLens/crust/blob/main/SECURITY.md"><img src="https://img.shields.io/badge/Security%20Policy-Responsible%20Disclosure-green" alt="Security Policy" /></a>
  <img src="https://img.shields.io/badge/SAST-gosec%20%7C%20semgrep-blueviolet" alt="SAST" />
  <img src="https://img.shields.io/badge/Fuzz%20Tested-43%20targets-orange" alt="Fuzz Tested" />
  <img src="https://img.shields.io/badge/Secrets-govulncheck%20%7C%20gitleaks-critical" alt="Secret Scanning" />
</p>

## What is Crust?

Crust is a transparent, local gateway between your AI agents and LLM providers. It intercepts every tool call — file reads, shell commands, network requests — and blocks dangerous actions before they execute. No code changes required.

**100% local. Your data never leaves your machine.**

<p align="center">
  <img src="docs/demo.gif" alt="Crust in action" width="800" />
</p>

## How It Works

<p align="center">
  <img src="docs/crust.png" alt="Crust architecture" width="90%" />
</p>

Crust has five entry points — use one or combine them:

| Entry Point | Command | What It Does |
|-------------|---------|--------------|
| **HTTP Proxy** | `crust start` | Sits between your agent and the LLM API. Scans tool calls in both the request (conversation history) and response (new actions) before they execute. |
| **MCP Stdio Gateway** | `crust mcp gateway` | Wraps any stdio [MCP](https://modelcontextprotocol.io) server, intercepting `tools/call` and `resources/read` in both directions — including DLP scanning of server responses for leaked secrets. |
| **MCP HTTP Gateway** | `crust mcp http` | Reverse proxy for [Streamable HTTP](https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http) MCP servers — same rule engine, no stdio required. |
| **ACP Stdio Proxy** | `crust acp-wrap` | Wraps any [ACP](https://agentclientprotocol.com) agent, intercepting file reads, writes, and terminal commands before the IDE executes them. |
| **Auto-detect** | `crust wrap` | Inspects both MCP and ACP methods simultaneously — use when you don't know which protocol a subprocess speaks. |

All entry points apply the same [evaluation pipeline](docs/how-it-works.md) — self-protection, input sanitization, Unicode normalization, obfuscation detection, DLP secret scanning, path normalization, symlink resolution, and rule matching — each step in microseconds.

All activity is logged locally to encrypted storage.

## Quick Start

**macOS / Linux / BSD:**
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/BakeLens/crust/main/install.sh)"
```

**Windows (PowerShell):**
```powershell
irm https://raw.githubusercontent.com/BakeLens/crust/main/install.ps1 | iex
```

**Docker:**
```bash
docker compose up -d        # uses the included docker-compose.yml
# or manually:
docker build -t crust https://github.com/BakeLens/crust.git
docker run -p 9090:9090 crust
```

Then start the gateway:

```bash
crust start --auto
```

Auto mode detects your LLM provider from the model name — no endpoint URL or API key configuration needed. Your agent's existing auth is passed through.

## Agent Setup

### HTTP Proxy

Point your agent to Crust:

| Agent | Configuration |
|-------|---------------|
| **[Claude Code](https://github.com/anthropics/claude-code)** | `ANTHROPIC_BASE_URL=http://localhost:9090` |
| **[Codex CLI](https://github.com/openai/codex)** | `OPENAI_BASE_URL=http://localhost:9090/v1` |
| **[Cursor](https://cursor.com)** | Settings → Models → Override OpenAI Base URL → `http://localhost:9090/v1` |
| **[Cline](https://github.com/cline/cline)** | Settings → API Configuration → Base URL → `http://localhost:9090/v1` |
| **[Windsurf](https://windsurf.com)** | Settings → AI → Provider Base URL → `http://localhost:9090/v1` |
| **[JetBrains AI](https://www.jetbrains.com/ai/)** | Settings → AI Assistant → Providers & API keys → Base URL → `http://localhost:9090/v1` |
| **[Continue](https://github.com/continuedev/continue)** | Set `apiBase` to `http://localhost:9090/v1` in config |
| **[Aider](https://github.com/Aider-AI/aider)** | `OPENAI_API_BASE=http://localhost:9090/v1` |

<details>
<summary><strong>More agents...</strong></summary>

| Agent | Configuration |
|-------|---------------|
| **[Zed](https://github.com/zed-industries/zed)** | Set `api_url` to `http://localhost:9090/v1` in settings |
| **[Tabby](https://github.com/TabbyML/tabby)** | Set `api_endpoint` to `http://localhost:9090/v1` in config |
| **[avante.nvim](https://github.com/yetone/avante.nvim)** | Set `endpoint` to `http://localhost:9090/v1` in config |
| **[codecompanion.nvim](https://github.com/olimorris/codecompanion.nvim)** | Set `url` to `http://localhost:9090/v1` in adapter config |
| **[CodeGPT](https://github.com/timkmecl/codegpt)** | Set custom provider URL to `http://localhost:9090/v1` |
| **[OpenClaw](https://github.com/openclaw/openclaw)** | Set `baseUrl` to `http://localhost:9090` in `~/.openclaw/openclaw.json` |
| **[OpenCode](https://github.com/opencode-ai/opencode)** | `OPENAI_BASE_URL=http://localhost:9090/v1` |
| **Any OpenAI-compatible agent** | Set your LLM base URL to `http://localhost:9090/v1` |

</details>

Crust auto-detects the provider from the model name and passes through your auth — no endpoint URL or API key configuration needed. Clients that send `/api/v1/...` paths (e.g. some JetBrains configurations) are also supported. For providers with non-standard base paths like [OpenRouter](https://openrouter.ai) (`https://openrouter.ai/api`), use `--endpoint`.

```bash
crust status     # Check if running
crust logs -f    # Follow logs
crust doctor     # Diagnose provider endpoints
crust stop       # Stop crust
```

### MCP Gateway

For [MCP](https://modelcontextprotocol.io) servers, Crust intercepts `tools/call` and `resources/read` requests before they reach the server.

```bash
crust mcp gateway -- npx -y @modelcontextprotocol/server-filesystem /path/to/dir
```

Works with any MCP server. See the [MCP setup guide](docs/mcp.md) for details and examples.

### ACP Integration

For IDEs that use the [Agent Client Protocol](https://agentclientprotocol.com) (ACP), Crust can wrap any ACP agent as a transparent stdio proxy — intercepting file reads, writes, and terminal commands before the IDE executes them. No changes to the agent or IDE required.

```bash
crust acp-wrap -- goose acp
```

Supports JetBrains IDEs and other ACP-compatible editors. See the [ACP setup guide](docs/acp.md) for step-by-step instructions.

## Protection

### Built-in Rules

Crust ships with **27 security rules** (24 locked, 3 user-disablable) and **42 DLP token-detection patterns** out of the box:

| Category | What's Protected |
|----------|-----------------|
| **Credentials** | `.env`, SSH keys, cloud creds (AWS, GCP, Azure), GPG keys |
| **System Auth** | `/etc/passwd`, `/etc/shadow`, sudoers |
| **Shell History** | `.bash_history`, `.zsh_history`, `.python_history`, and more |
| **Browser Data** | Chrome, Firefox, Safari passwords, cookies, local storage |
| **Package Tokens** | npm, pip, Cargo, Composer, NuGet, Gem auth tokens |
| **Git Credentials** | `.git-credentials`, `.config/git/credentials` |
| **Persistence** | Shell RC files, `authorized_keys`, cron/systemd/launchd, git hooks |
| **Agent Config** | `.claude/settings.json`, `.cursor/mcp.json`, `.mcp.json` — prevents privilege escalation |
| **DLP Token Detection** | Content-based scanning for real API keys and tokens (AWS, GitHub, Stripe, OpenAI, Anthropic, and [31 more](docs/how-it-works.md#dlp-secret-detection)) |
| **Key Exfiltration** | Content-based PEM private key detection |
| **Crypto Wallets** | BIP39 mnemonics, xprv/WIF keys (checksum-validated), wallet directories for 16 chains |
| **Self-Protection** | Agents cannot read, modify, or disable Crust itself |
| **Dangerous Commands** | `eval`/`exec` with dynamic code execution |

All rules are open source: [`internal/rules/builtin/security.yaml`](internal/rules/builtin/security.yaml) (path rules), [`internal/rules/dlp.go`](internal/rules/dlp.go) (DLP patterns), and [`internal/rules/dlp_crypto.go`](internal/rules/dlp_crypto.go) (crypto key detection)

These defenses are validated against [**26 real-world CVEs**](docs/cve-tracker.md) affecting Cursor, GitHub Copilot, Claude Code, and other AI agents — including prompt injection, config hijacking, and token exfiltration attacks.

### Custom Rules

Rules use a progressive disclosure schema — start simple, add complexity only when needed:

```yaml
rules:
  # One-liner: block all .env files
  - block: "**/.env"

  # With exceptions and specific actions
  - block: "**/.ssh/id_*"
    except: "**/*.pub"
    actions: [read, copy]
    message: "Cannot access SSH private keys"

  # Advanced: regex matching on commands
  - name: block-rm-rf
    match:
      command: "re:rm\\s+-rf\\s+/"
    message: "Blocked: recursive delete from root"
```

```bash
crust add-rule my-rules.yaml    # Rules active immediately (hot reload)
```

### Plugins

Plugins are **late-stage protection layers** that run after the built-in 13-step evaluation pipeline. When the engine allows a tool call, it passes through registered plugins before returning the final verdict. Plugins can implement sandboxing, rate limiting, audit logging, or custom policy enforcement.

Plugins communicate over a **JSON wire protocol** (newline-delimited JSON over stdin/stdout) — write them in **any language**: Python, Go, Rust, Node.js, etc.

```python
# sandbox_plugin.py — restrict file access to project directory
def handle_evaluate(req):
    for path in req.get("paths", []):
        if not path.startswith("/home/user/project"):
            return {"rule_name": "sandbox:fs-deny", "severity": "high",
                    "message": f"path {path} is outside sandbox"}
    return None  # allow
```

Key features:
- **OS-level crash isolation** — plugins run as separate processes; a crash cannot affect the engine
- **Circuit breaker** — plugins that fail 3 times are auto-disabled with exponential backoff
- **Rule snapshot access** — plugins receive a read-only view of all active engine rules
- **First-block wins** — plugins evaluate concurrently; the first block cancels the rest

See the [Plugin System](docs/plugins.md) documentation for the full wire protocol specification, data types, and examples.

### Crust Self-Security

A security tool must protect itself first. Crust is built to resist tampering — even by the AI agents it monitors:

| Principle | What it means |
|-----------|---------------|
| **Only you can access it** | Crust's control interface only listens on your machine — no one else on the network can reach it |
| **Agents can't disable it** | A hardcoded pre-filter prevents AI agents from turning off, reconfiguring, or bypassing Crust |
| **Your files stay private** | All config and log files are locked to your user account — other users and programs can't read them |
| **Secrets use OS keyring** | API keys and encryption keys are stored in your OS keyring (macOS Keychain / Linux Secret Service / Windows Credential Manager), never in environment variables |
| **Logs are encrypted** | Activity logs are stored in an encrypted database; the key never appears in command history |
| **Oversized requests are rejected** | Abnormally large inputs are dropped before processing to prevent abuse |
| **Connections are encrypted** | All traffic to LLM providers uses modern encryption (TLS 1.2+) |
| **Every code change is scanned** | 14 automated security checks run on every commit — vulnerability scanning, secret detection, race condition testing |

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Documentation

**Setup**

| Guide | Description |
|-------|-------------|
| [Configuration](docs/configuration.md) | Providers, auto mode, block modes |
| [MCP Gateway](docs/mcp.md) | Stdio proxy for [MCP](https://modelcontextprotocol.io) servers — Claude Desktop, custom servers |
| [ACP Integration](docs/acp.md) | Stdio proxy for [ACP](https://agentclientprotocol.com) agents — JetBrains, VS Code |
| [Docker](docs/docker.md) | Dockerfile, docker-compose, container setup |

**Reference**

| Guide | Description |
|-------|-------------|
| [CLI Reference](docs/cli.md) | Commands, flags, environment variables |
| [How It Works](docs/how-it-works.md) | Architecture, rule engine, evaluation pipeline |
| [Plugin System](docs/plugins.md) | Wire protocol, crash isolation, circuit breaker, examples |
| [Shell Parsing](docs/shell-parsing.md) | Bash command parsing for path/command extraction |
| [CVE Tracker](docs/cve-tracker.md) | AI agent vulnerability tracker |
| [Migration](docs/migration.md) | Upgrade guides for breaking changes |

<details>
<summary><strong>Build from Source</strong></summary>

Requires Go 1.26.1+ and a C compiler (CGO is needed for SQLite).

```bash
git clone https://github.com/BakeLens/crust.git
cd crust
go build .
./crust version   # Windows: .\crust.exe version
```

Go 1.26 enables the [Green Tea garbage collector](https://go.dev/blog/go1.26) by default, which reduces GC overhead by 10–40% — this meaningfully improves latency for the hot-path proxy pipeline. Run `go fix ./...` before submitting PRs to apply any pending modernizations automatically.

</details>

## Contributing

Crust is open-source and in active development. We welcome contributions — PRs for new security rules are especially appreciated.

- [Report a bug](https://github.com/BakeLens/crust/issues)
- [Security vulnerabilities](SECURITY.md) — please report privately
- [Discussions](https://github.com/BakeLens/crust/discussions)

Add this badge to your project's README:

```markdown
[![Protected by Crust](https://img.shields.io/badge/Protected%20by-Crust-blue)](https://github.com/BakeLens/crust)
```

<details>
<summary><strong>Citation</strong></summary>

If you use Crust in your research, please cite:

```bibtex
@software{crust2026,
  title = {Crust: A Transparent Gateway for AI Agent Security},
  author = {Chen, Zichen and Chen, Yuanyuan and Jiang, Bowen and Xu, Zhangchen},
  year = {2026},
  url = {https://github.com/BakeLens/crust}
}
```

</details>

## License

[Elastic License 2.0](LICENSE)
