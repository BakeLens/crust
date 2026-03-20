# Migration Guide

## Stats Aggregation API

### What Changed

Three new read-only endpoints provide pre-aggregated stats from `tool_call_logs` for dashboards and GUIs. These run SQL aggregation server-side instead of requiring clients to fetch raw logs and compute stats locally.

### New Endpoints

| Endpoint | Query Params | Description |
|----------|-------------|-------------|
| `GET /api/telemetry/stats/trend` | `range` (`7d`, `30d`, `90d`) | Daily total/blocked call counts, grouped by date |
| `GET /api/telemetry/stats/distribution` | `range` (`7d`, `30d`, `90d`) | Block counts grouped by rule name and by tool name |
| `GET /api/telemetry/stats/coverage` | `range` (`7d`, `30d`, `90d`) | Detected AI tools with total calls, blocked calls, API type, last seen |

All endpoints default to a sensible range if `range` is omitted (7d for trend, 30d for distribution/coverage). Maximum range is 90 days.

### Example Responses

**Trend:**
```json
[
  {"date": "2026-03-08", "total_calls": 142, "blocked_calls": 3},
  {"date": "2026-03-09", "total_calls": 87, "blocked_calls": 1}
]
```

**Distribution:**
```json
{
  "by_rule": [{"rule": "block-env-files", "count": 12}],
  "by_tool": [{"tool_name": "Bash", "count": 8}]
}
```

**Coverage:**
```json
[
  {"tool_name": "Bash", "api_type": "anthropic", "total_calls": 340, "blocked_calls": 5, "last_seen": "2026-03-10 14:30:00"}
]
```

### Architecture

The endpoints use a framework-agnostic `StatsService` (`internal/telemetry/stats.go`) with plain `net/http` handlers. These are mounted in an `http.ServeMux` via `mux.HandleFunc()`. The service can also be used directly from Go code (CLI, TUI, tests) without any external HTTP framework dependency.

### TUI

The live dashboard (`crust status --live`) has a new **Stats** tab (press `3`) showing a 7-day block trend chart, top blocked rules/tools, and tool coverage.

### Impact

- No breaking changes. Existing endpoints are unchanged.
- Available on both Unix socket and TCP (when `--listen-address` is non-loopback).

---

## Management API on Proxy Port (v2.0 → v2.2)

### What Changed

The management API (`/api/*` routes) is now also mounted on the proxy HTTP server (port 9090) when `--listen-address` is set to a non-loopback address (e.g. `0.0.0.0`). This enables remote management and dashboard usage for Docker deployments. On localhost, the API remains socket-only.

### Impact

- CLI commands (`status`, `list-rules`) accept `--api-addr HOST:PORT` to connect over TCP instead of the local Unix socket.
- `curl` can now reach the API directly: `curl http://localhost:9090/api/security/status`
- The Unix socket still works for local connections (backward compatible).
- Docker users can run the live dashboard from the host: `crust status --live --api-addr localhost:9090`

### Security Note

The API is only mounted on the proxy port when `--listen-address` is non-loopback (e.g. `0.0.0.0`). On localhost (the default), management API access remains socket-only. When exposed, write endpoints (add/remove rules) are accessible to anyone who can reach the port. Restrict network access as appropriate.

---

## Management API: TCP → Unix Domain Socket (v1.x → v2.0)

### What Changed

The management API now uses Unix domain sockets instead of TCP. This provides kernel-enforced access control (`chmod 0600`), eliminates port conflicts, and is invisible to port scanners.

- **Unix/macOS**: `~/.crust/crust-api-{port}.sock`
- **Windows**: Named pipe `\\.\pipe\crust-api-{port}.sock`

### Impact

- The `api.port` config key is removed. Use `api.socket_path` (or leave empty for auto-derived path).
- CLI commands (`crust status`, `crust list-rules`) work automatically via the new transport.
- The `--api-port` flag is removed.
- Local API access via `curl` requires `--unix-socket`:

```bash
curl --unix-socket ~/.crust/crust-api-9090.sock http://localhost/api/security/status
```

- As of v2.2, the API is also available on the proxy port (9090) over TCP — see [v2.0 → v2.2](#management-api-on-proxy-port-v20--v22).

### Telemetry DB Concurrency

SQLite access is now serialized with `MaxOpenConns(1)` and `PRAGMA foreign_keys = ON`. The `GetOrCreateTrace` race condition is fixed with `INSERT ... ON CONFLICT`, and `EndLLMSpan` writes are wrapped in a single transaction for atomicity.

---

## Pre-compilation Validation (v0.x → v0.y)

### What Changed

Rule patterns (regex, glob) are now validated and pre-compiled at rule load time instead of at runtime. This is more secure and faster, but it means rules with invalid patterns that previously "worked" (by silently failing to match) will now be detected and handled.

**Before:** Invalid patterns silently returned `false` at runtime. All rules loaded regardless of pattern validity.

**After:** Patterns are validated at insert time. Invalid builtin rules fail hard (startup error). Invalid user rules are skipped with a warning, and the remaining valid rules still load.

### Impact

- **Builtin rules:** No impact. All builtin rules have been validated.
- **User rules:** Rules with invalid patterns (malformed regex, invalid globs, null bytes, control characters) will be **skipped** instead of silently failing. Other valid rules in the same file continue to load.

### How to Check Your Rules

Validate your rules before upgrading. The `add-rule` command now validates automatically before adding, and `list-rules --reload` forces a reload:

```bash
# Validate by adding (auto-validates before adding)
crust add-rule /path/to/rules.yaml

# Validate via API (Unix domain socket)
curl --unix-socket ~/.crust/crust-api-9090.sock \
  -X POST http://localhost/api/crust/rules/validate \
  -d @rules.yaml
```

The `add-rule` command reports per-rule validation results including pattern compilation errors:

```text
$ crust add-rule my-rules.yaml
Linting builtin rules...
  No issues found.
Linting user rules...
  ✗ [error] bad-regex: patterns - rule "bad-regex": match.path regex "re:(?P<invalid": error parsing regexp
  ✗ [error] null-byte: patterns - rule "null-byte" block.paths[0]: pattern contains null byte at position 5
  ⚠ [warning] broad-rule: block.paths[0] - very short pattern may match too broadly
```

### Validation API Changes

The `POST /api/crust/rules/validate` endpoint now performs full pattern compilation and returns per-rule results:

```json
{
  "valid": false,
  "rules": [
    {"name": "good-rule", "valid": true},
    {"name": "bad-regex", "valid": false, "error": "match.path regex \"re:(?P<invalid\": error parsing regexp: ..."}
  ]
}
```

### Common Pattern Issues

| Issue | Example | Fix |
|-------|---------|-----|
| Invalid regex | `re:(?P<invalid` | Fix the regex syntax |
| Malformed glob bracket | `[unclosed` | Close the bracket: `[unclosed]` |
| Null bytes | `/path\x00bad` | Remove null bytes from pattern |
| Control characters | `/path\x01bad` | Remove control characters (tabs are allowed) |
| Regex too long | `re:` + 4096+ chars | Simplify the regex (max 4096 chars) |

### Behavior Summary

| Rule Source | Invalid Pattern Behavior |
|-------------|------------------------|
| Builtin | Startup fails (must be fixed) |
| User | Rule skipped with warning, others continue |
| Test (`NewTestEngine`) | Returns error (tests should catch bad patterns) |
| Validate API | Reports error per-rule, never skips silently |
| Lint | Reports error as lint issue |
