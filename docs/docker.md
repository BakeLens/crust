# Docker

A [`Dockerfile`](../Dockerfile) is included in the repo. The builder stage uses `golang:1.26.1-bookworm`; the runtime stage uses `debian:bookworm-slim`.

## Quick Start

```bash
docker build -t crust .
docker run -d -t -p 9090:9090 crust
```

The default entrypoint runs `crust start --foreground --auto --listen-address 0.0.0.0`. Use `-t` for ANSI-styled `docker logs` output.

## docker-compose

With per-provider API keys injected via environment:

```yaml
# docker-compose.yml
services:
  crust:
    build: .
    ports:
      - "9090:9090"
    tty: true
    restart: always
    environment:
      - OPENAI_API_KEY=${OPENAI_API_KEY}
    volumes:
      - crust-data:/home/crust/.crust
      - ./config.yaml:/home/crust/.crust/config.yaml:ro
volumes:
  crust-data:
```

```yaml
# config.yaml — provider keys reference env vars
upstream:
  providers:
    openai:
      url: "https://api.openai.com"
      api_key: "$OPENAI_API_KEY"
```

Point your agents to `http://<docker-host>:9090` instead of `localhost`.

## Remote Dashboard from Host

When `--listen-address` is non-loopback (as in the default Docker entrypoint with `0.0.0.0`), the management API is mounted on the proxy port (9090). This lets you run the interactive dashboard on the host:

```bash
# Start daemon in Docker (detached)
docker run -d -p 9090:9090 crust

# Live dashboard from host
crust status --live --api-addr localhost:9090

# List rules from host
crust list-rules --api-addr localhost:9090

# Query API directly
curl http://localhost:9090/api/security/status
curl http://localhost:9090/api/security/stats
curl http://localhost:9090/api/telemetry/sessions

# Stats aggregation (for dashboards)
curl http://localhost:9090/api/telemetry/stats/trend?range=7d
curl http://localhost:9090/api/telemetry/stats/distribution?range=30d
curl http://localhost:9090/api/telemetry/stats/coverage?range=30d
```

The `--api-addr` flag tells CLI commands to connect over TCP instead of the local Unix socket. No extra ports needed — the API shares the existing proxy port. On localhost (the default `--listen-address`), the API is only accessible via Unix socket.

## What Works in Docker

All rule-based blocking, tool call inspection (Layers 0 & 1), content scanning, telemetry, and auto-mode provider resolution. These operate on API traffic passing through the proxy and work regardless of where Crust runs.

## TUI in Docker

Use `-t` for ANSI-styled output (colors, bold, icons) in `docker logs`. Without `-t`, output is plain text and terminal escape sequence queries are suppressed automatically. With `-t`, a real TTY is present so lipgloss auto-detects color support.

For interactive TUI setup, use `docker run -it --entrypoint crust crust start --foreground` (without `--auto`). Set `NO_COLOR=1` to force plain.

See [tui.md](tui.md) for the full technical breakdown of how foreground mode handles terminal detection in containers.

## Persistent Data

Telemetry and the SQLite database are stored at `/home/crust/.crust/crust.db`. Mount a volume to persist across restarts:

```bash
docker run -d -t -p 9090:9090 -v crust-data:/home/crust/.crust crust
```

If using database encryption (`DB_KEY`), the same key must be provided on every restart.
