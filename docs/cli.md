# CLI Reference

## Commands

```bash
# Gateway
crust start --auto                          # Auto mode (recommended)
crust start --endpoint URL --api-key KEY    # Manual mode
crust start --auto --block-mode replace     # Show block messages to agent
crust start --foreground --auto             # Foreground mode (for Docker)
crust stop                                  # Stop the gateway
crust status [--json] [--live]              # Check if running
crust status --live --api-addr HOST:PORT    # Remote dashboard (Docker)
crust status --agents [--json] [--api-addr ADDR]  # Detect running AI agents
crust logs [-f] [-n N]                      # View logs

# Rules
crust list-rules [--json] [--api-addr ADDR] # List active rules
crust add-rule FILE                         # Add custom rules (hot reload)
crust remove-rule FILE                      # Remove user rules
crust list-rules --reload                   # Force reload all rules

# MCP / ACP Proxies (see [MCP setup guide](mcp.md), [ACP setup guide](acp.md))
crust wrap [flags] -- <cmd...>              # Auto-detect MCP or ACP (stdio proxy)

# Diagnostics
crust doctor                                # Diagnostics + MCP config scan
crust doctor [--timeout 5s] [--retries N]   # Check providers + scan for unguarded agents
crust doctor --report                       # Generate sanitized report for GitHub issues

# Other
crust version [--json]                      # Show version
crust completion [--install]                # Install shell completion (bash/zsh/fish)
crust uninstall                             # Complete removal
```

## Start Flags

| Flag | Description |
|------|-------------|
| `--auto` | Resolve providers from model names |
| `--endpoint URL` | LLM API endpoint URL |
| `--api-key KEY` | API key (prefer `LLM_API_KEY` env var) |
| `--foreground` | Run in foreground (for Docker/containers) |
| `--listen-address ADDR` | Bind address (default `127.0.0.1`, use `0.0.0.0` for Docker) |
| `--block-mode MODE` | `remove` (delete tool calls) or `replace` (substitute with a text warning block) |
| `--no-color` | Disable colored output |
| `--proxy-port PORT` | Proxy server port (default from config) |
| `--log-level LEVEL` | `trace`, `debug`, `info`, `warn`, `error` |
| `--telemetry` | Enable telemetry |
| `--retention-days N` | Telemetry retention in days (0=forever) |
| `--db-key KEY` | Database encryption key (prefer `DB_KEY` env var) |
| `--config PATH` | Path to configuration file |
| `--disable-builtin` | Disable builtin security rules (locked rules remain active) |

## Status / List-Rules Flags

| Flag | Description |
|------|-------------|
| `--api-addr HOST:PORT` | Connect to a remote daemon (e.g. Docker) over TCP instead of the local Unix socket |

## Status --agents Flags

The `--agents` flag on `crust status` detects running AI agents and their protection status.

| Flag | Description |
|------|-------------|
| `--agents` | Show detected AI agents |
| `--json` | Output as JSON |
| `--api-addr HOST:PORT` | Query a remote daemon (e.g. Docker) over TCP instead of the local Unix socket |

Agent statuses:

| Status | Meaning |
|--------|---------|
| `protected` | Process detected and config patched to route through Crust |
| `running` | Process detected but not routed through Crust |
| `configured` | Config patched but process not currently running |

Works with or without the daemon running. When the daemon is running, `crust status --agents` queries it for accurate patch status (protected/configured). Without the daemon, it performs a local process scan only — detected agents show as `running` since patch status is unavailable.

## Doctor Flags

| Flag | Description |
|------|-------------|
| `--timeout DURATION` | Timeout per provider check (default `5s`) |
| `--retries N` | Retries for connection errors (default `1`, use `0` to disable) |
| `--report` | Generate a sanitized markdown report for GitHub issues |
| `--config PATH` | Path to configuration file |

## Wrap Flags

| Flag | Description |
|------|-------------|
| `--config PATH` | Path to configuration file |
| `--log-level LEVEL` | `trace`, `debug`, `info`, `warn` (default), `error` |
| `--rules-dir DIR` | Override user rules directory |
| `--disable-builtin` | Disable builtin security rules (31 locked rules remain active) |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `LLM_API_KEY` | API key for the LLM endpoint |
| `DB_KEY` | Database encryption key |
| `NO_COLOR` | Disable colored output (any value) |

## Examples

```bash
# Interactive setup
crust start

# Auto mode with env-based auth
crust start --auto

# Manual mode with explicit endpoint
LLM_API_KEY=sk-xxx crust start --endpoint https://openrouter.ai/api/v1

# Docker/container mode
crust start --foreground --auto --listen-address 0.0.0.0

# Follow logs
crust logs -f

# Add rules (validates automatically before adding)
crust add-rule my-rules.yaml

# Machine-readable output
crust status --json
crust list-rules --json

# Remote dashboard (daemon running in Docker)
crust status --live --api-addr localhost:9090
crust list-rules --api-addr localhost:9090

# Detect running AI agents
crust status --agents
crust status --agents --json
crust status --agents --api-addr localhost:9090   # query remote daemon

# Diagnostics — check providers + scan for unguarded agent servers
crust doctor
crust doctor --timeout 3s --retries 0
crust doctor --report              # sanitized report for GitHub issues

# Wrap agent for JetBrains/Zed (auto-detects MCP or ACP)
crust wrap -- goose acp
crust wrap --log-level debug -- goose acp
```
