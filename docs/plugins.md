# Plugin System

## Overview

Plugins are **post-engine protection layers** (PostChecker) that run after the built-in 14-step evaluation pipeline decides to allow a tool call. They do not re-evaluate rules — they provide **additional checks** at a different layer (e.g., sandbox policy validation, rate limiting, compliance enforcement).

```text
Tool Call ──▶ [Steps 1-14: Engine Pipeline] ──▶ allowed? ──▶ [PostChecker: Plugins] ──▶ Result
                                                    │               │
                                                 ↓ BLOCK      block or allow
                                              (engine)        (plugin decision)
```

Plugins are wired into the engine via `PostChecker`, so **all evaluation paths** (PreToolUse hook, HTTP proxy, MCP/ACP wrap) automatically consult plugins — no per-caller wiring needed.

Plugins can implement sandboxing, rate limiting, audit logging, custom policy enforcement, or any other protection logic. They receive the same extracted information that the built-in pipeline computed (paths, hosts, operations, commands), plus a **read-only snapshot of all active engine rules**.

External plugins communicate over a **JSON wire protocol** (newline-delimited JSON over stdin/stdout). This means plugins can be written in **any language** — Go, Python, Rust, Node.js, etc. In-process plugins (like the sandbox plugin) implement the `plugin.Plugin` Go interface directly. Both types benefit from the **worker pool** with crash isolation, circuit breakers, and timeout handling.

---

## Wire Protocol

> **Formal specification:** [../internal/schemacheck/plugin-protocol.schema.json](../internal/schemacheck/plugin-protocol.schema.json) (JSON Schema draft 2020-12)
>
> Schema conformance is enforced at build time — `schema_test.go` validates that all Go types, fields, enums, and method constants match the schema. Any drift between the implementation and the specification fails the pre-commit check.

Plugins are external processes. Communication is **newline-delimited JSON** over stdin/stdout (one JSON object per line, each direction):

```text
crust ──stdin──▶  plugin process  ──stdout──▶ crust
       (requests)                  (responses)
```

Stderr is passed through for plugin diagnostics.

### Message Format

Request (crust → plugin):
```json
{"method": "<method>", "params": <JSON>}
```

Response (plugin → crust):
```json
{"result": <JSON>}
```

or on error:
```json
{"error": "<message>"}
```

### Lifecycle

```text
1. crust spawns plugin process
2. crust → {"method":"init","params":{"name":"sandbox","config":{...}}}
3. plugin → {"result":"ok"}
4. crust → {"method":"evaluate","params":{...}}    ← repeated per tool call
5. plugin → {"result":null}                         ← allow
   plugin → {"result":{"rule_name":"...","severity":"high","message":"..."}}  ← block
6. crust → {"method":"close"}
7. plugin → {"result":"ok"}
8. plugin exits
```

### Methods

| Method | Params | Response | Description |
|--------|--------|----------|-------------|
| `init` | `InitParams` | `"ok"` or error | One-time setup with plugin config |
| `evaluate` | `Request` | `null` (allow) or `Result` (block) | Evaluate a tool call |
| `close` | none | `"ok"` | Graceful shutdown |

---

## Data Types

### Request

Sent with `method="evaluate"`. Contains everything the engine extracted during the evaluation pipeline (including interpreter code scanning), plus a snapshot of all active rules:

```json
{
    "tool_name": "Bash",
    "arguments": {"command": "rm -rf /etc"},
    "operation": "execute",
    "operations": ["execute", "delete"],
    "command": "rm -rf /etc",
    "paths": ["/etc"],
    "hosts": [],
    "content": "{\"command\":\"rm -rf /etc\"}",
    "evasive": false,
    "rules": [
        {
            "name": "protect-etc",
            "description": "Block /etc modifications",
            "source": "builtin",
            "severity": "critical",
            "priority": 10,
            "actions": ["read", "write", "delete"],
            "block_paths": ["/etc/**"],
            "block_except": ["/etc/hostname"],
            "message": "Cannot modify system files",
            "locked": true,
            "enabled": true,
            "hit_count": 42
        }
    ]
}
```

| Field | Type | Description |
|-------|------|-------------|
| `tool_name` | string | Sanitized tool name (e.g. "Bash", "Read", "Write") |
| `arguments` | object or null | Raw JSON arguments from the tool call |
| `operation` | `rules.Operation` | Primary operation: `read`, `write`, `delete`, `copy`, `move`, `execute`, `network` |
| `operations` | `[]rules.Operation` | All operations (a command may both read and write) |
| `command` | string | Raw shell command (Bash tool only) |
| `paths` | string[] | Normalized + symlink-resolved paths |
| `hosts` | string[] | Extracted hostnames/IPs |
| `content` | string | Write content or full raw JSON of all arguments |
| `evasive` | bool | True if command uses shell tricks that prevent static analysis |
| `rules` | RuleSnapshot[] | Read-only snapshot of all active engine rules (always present, `[]` if none) |

> **No optional fields.** Every field is always present in the JSON encoding. There is no distinction between "absent" and "zero value" — `false` is `false`, empty arrays are `[]`, empty strings are `""`. This eliminates a class of bugs where plugins check for field presence instead of value.

### RuleSnapshot

Each element in `rules` describes one engine rule:

| Field | Type | Description |
|-------|------|-------------|
| `name` | string | Rule identifier (e.g. "protect-ssh-keys") |
| `description` | string | Human-readable description |
| `source` | `rules.Source` | `"builtin"`, `"user"`, or `"cli"` |
| `severity` | `rules.Severity` | `"critical"`, `"high"`, `"warning"`, `"info"` |
| `priority` | int | Lower = higher priority (default 50) |
| `actions` | `[]rules.Operation` | Operations this rule applies to |
| `block_paths` | string[] | Glob patterns this rule blocks |
| `block_except` | string[] | Exception patterns |
| `block_hosts` | string[] | Host patterns for network rules |
| `message` | string | Block message shown to the user |
| `locked` | bool | True if rule survives `--disable-builtin` |
| `enabled` | bool | True if rule is active |
| `hit_count` | int | Times this rule has matched |

The `plugin.SnapshotRule(r *rules.Rule) RuleSnapshot` function centralizes the conversion from engine rules to snapshots, ensuring all fields are correctly mapped and slices are cloned.

Plugins can use the rule snapshot for context-aware decisions, such as:
- Checking if a path is already protected by a builtin rule
- Enforcing policy that certain rules must exist (compliance)
- Adjusting severity based on what protections are already active

### Result

Returned to block a tool call. Return `null` to allow.

```json
{
    "rule_name": "sandbox:fs-deny",
    "severity": "high",
    "action": "block",
    "message": "path /etc is outside sandbox"
}
```

| Field | Type | Description |
|-------|------|-------------|
| `rule_name` | string | Plugin-namespaced rule (e.g. "sandbox:fs-deny") |
| `severity` | `rules.Severity` | `"critical"`, `"high"`, `"warning"`, `"info"` (invalid defaults to `"high"`) |
| `action` | `rules.Action` | `"block"` (default), `"log"`, or `"alert"` (invalid defaults to `"block"`) |
| `message` | string | Human-readable reason |

The `plugin` field is auto-filled by the registry — plugins don't need to set it.

### InitParams

Sent with `method="init"`:

```json
{
    "name": "sandbox",
    "config": {"allowed_dirs": ["/home/user/project"], "deny_net": true}
}
```

---

## Crash Isolation

### Worker Pool

Each plugin evaluation runs in a **pooled goroutine** with `recover()` and a context-based timeout. This isolates the engine from both in-process panics and external process crashes.

```text
Engine.Evaluate()
  │
  ▼
Registry.Evaluate(ctx, req)
  │
  ├─▶ fan out all plugins concurrently (each via worker pool)
  │     │
  │     ▼ (per plugin goroutine)
  │   acquire slot from pool (with context timeout — no indefinite blocking)
  │   goroutine {
  │     defer recover()           ← catches in-process panics
  │     ctx with timeout          ← passed to plugin for cooperative cancellation
  │     result = plugin.Evaluate(ctx, req.DeepCopy())
  │   }
  │     │
  │     ├─▶ block result          → send to results channel, cancel remaining plugins
  │     ├─▶ panic / crash         → log (with stack trace), increment failure count, skip plugin
  │     ├─▶ timeout exceeded      → log, increment failure count, skip plugin
  │     └─▶ pool exhausted        → log, skip plugin (NOT counted as plugin failure)
  │
  ├─▶ collect results — lowest registration index wins ties
  │
  └─▶ all plugins passed → return nil (allowed)
```

The pool uses a **counting semaphore** pattern (buffered channel). Slot acquisition respects the caller's context — no indefinite blocking. Default pool size: `min(GOMAXPROCS, 8)`. Default timeout: 5 seconds.

**Pool exhaustion** (all slots busy) is not the plugin's fault — it does not increment the circuit breaker failure counter. Only panics and timeouts count as plugin failures.

### Circuit Breaker

A plugin that fails repeatedly is **automatically disabled** with exponential backoff:

```text
  ┌─────────┐  3 consecutive    ┌──────────┐  cooldown elapsed   ┌─────────┐
  │ Healthy │ ── failures ────▶ │ Disabled │ ── (backoff) ─────▶ │ Retry   │
  │         │ ◀── success ───── │          │                      │         │
  └─────────┘   (reset count)   └──────────┘                      └─────────┘
                                      ▲                                │
                                      └──── fails again ───────────────┘
                                            (double cooldown)

After 5 disable cycles → Permanently Disabled
```

| Parameter | Value | Description |
|-----------|-------|-------------|
| Max consecutive failures | 3 | Disable after 3 panics/timeouts in a row |
| Base cooldown | 5 minutes | First disable cycle |
| Backoff | 2x per cycle | 5min → 10min → 20min → 40min → 1hr (cap) |
| Max disable cycles | 5 | After 5 cycles, permanently disabled |

Circuit breaker state transitions are **mutex-protected** to prevent TOCTOU races under concurrent evaluation. Plugin names are **cached at registration** to prevent spoofing via dynamic `Name()` returns. Each plugin gets a **deep copy** of the request to prevent mutation across plugins.

---

## Go Interface

For Go-based plugins (in-process or as the `ProcessPlugin` adapter), the interface is:

```go
package plugin

type Plugin interface {
    Name() string
    Init(cfg json.RawMessage) error
    Evaluate(ctx context.Context, req Request) *Result
    Close() error
}
```

The `ProcessPlugin` adapter implements this interface by spawning an external process and communicating over the wire protocol:

```go
// Launch a Python plugin
p := plugin.NewProcessPlugin("sandbox", "/usr/bin/python3", "sandbox_plugin.py")
registry.Register(p, json.RawMessage(`{"allowed_dirs":["/home/user/project"]}`))
```

### Auto-Restart

If a `ProcessPlugin`'s external process crashes or times out during IPC, it is killed and **automatically restarted** on the next `Evaluate` call (up to 3 consecutive restart failures). The init configuration is saved at startup and replayed on restart. Closing stdout on kill unblocks any goroutine waiting on the scanner, preventing goroutine leaks.

---

## Integration

The plugin registry is created via `plugin.InitDefaultRegistry()` and wired into the engine by `plugin.WirePluginPostChecker()`. Both the daemon (`security.Init`) and the mobile library (`libcrust.Init`) use this shared path. After the engine's 14-step pipeline allows a tool call, plugins enforce additional policy at exec time (e.g., OS-level sandboxing).

```text
Tool Call ──▶ [Steps 1-14: Engine Pipeline] ──▶ allowed? ──▶ [PostChecker] ──▶ Result
                                                    │              │
                                                 ↓ BLOCK    plugin.Evaluate()
                                              (engine)     (sandbox, rate-limiter, etc.)
```

### Current wiring

Plugins are wired into the engine via `PostChecker` — a callback that runs after the 14-step pipeline allows a tool call. Both functions live in `internal/plugin/`:

```go
// internal/plugin/registry.go — InitDefaultRegistry()
func InitDefaultRegistry() *Registry {
    pool := NewPool(0, 0)
    reg := NewRegistry(pool)
    if sp, err := NewSandboxPlugin(); err == nil {
        reg.Register(sp, nil)
    }
    return reg
}

// internal/plugin/wire.go — WirePluginPostChecker()
func WirePluginPostChecker(engine *rules.Engine, registry *Registry) {
    engine.SetPostChecker(func(call rules.ToolCall, info rules.ExtractedInfo) *rules.MatchResult {
        req := BuildPluginRequest(engine, call, info)
        ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        result := registry.Evaluate(ctx, req)
        if result == nil {
            return nil
        }
        m := rules.NewMatch(result.RuleName, result.Severity, result.Action, result.Message)
        return &m
    })
}
```

Because PostChecker is inside `Engine.Evaluate()`, **all callers** automatically get plugin evaluation — the HTTP proxy interceptor, MCP/ACP wrap pipe, PreToolUse hook, and direct `Evaluate()` calls.

The **sandbox plugin** (`plugin/sandbox.go`) is an in-process plugin that wraps the `bakelens-sandbox` binary. It builds an OS-level enforcement policy from the engine's rule snapshots, translating them into process-level sandbox constraints.

Plugins are registered only when their backing binary is available on `$PATH` — graceful degradation when absent.

### Sandbox plugin

The sandbox plugin implements `plugin.Plugin` in-process (not over the wire protocol). It translates crust's rule snapshots into a sandbox `InputPolicy`:

| plugin.Request field | sandbox InputPolicy field |
|---------------------|--------------------------|
| `req.Command` | `policy.command` (split into `[]string`) |
| `req.Rules[].BlockPaths` | `DenyRule.patterns` |
| `req.Rules[].BlockExcept` | `DenyRule.except` |
| `req.Rules[].Actions` | `DenyRule.operations` |
| `req.Rules[].BlockHosts` | `DenyRule.hosts` |
| `SandboxConfig.ExtraPorts` | `policy.extra_ports` |
| `SandboxConfig.Resources` | `policy.resources` |

The actual exec-time wrapping (spawning `bakelens-sandbox` with the policy on stdin) is a follow-up.

---

## Example: Sandbox Plugin (Python)

A filesystem sandbox plugin in Python, communicating over the wire protocol:

```python
#!/usr/bin/env python3
"""Sandbox plugin for crust — restricts file access to allowed directories."""

import json
import sys
import os

allowed_dirs = []
deny_net = False

def handle_init(params):
    global allowed_dirs, deny_net
    config = params.get("config") or {}
    allowed_dirs = config.get("allowed_dirs", [])
    deny_net = config.get("deny_net", False)
    return "ok"

def handle_evaluate(req):
    # Block network if configured
    if deny_net and req.get("operation") == "network":
        return {
            "rule_name": "sandbox:net-deny",
            "severity": "high",
            "message": "network access denied by sandbox policy",
        }

    # Check paths against allowed directories
    for path in req.get("paths", []):
        if not is_allowed(path):
            return {
                "rule_name": "sandbox:fs-deny",
                "severity": "high",
                "message": f"path {path} is outside sandbox",
            }

    # Example: use rule snapshot to check if path is already protected
    for rule in req.get("rules", []):
        if not rule.get("enabled"):
            return {
                "rule_name": "sandbox:disabled-rule",
                "severity": "warning",
                "message": f"rule {rule['name']} is disabled — sandbox requires it",
            }

    return None  # allow

def is_allowed(path):
    if not allowed_dirs:
        return True
    path = os.path.realpath(path)
    return any(
        os.path.commonpath([d, path]) == os.path.realpath(d)
        for d in allowed_dirs
    )

def main():
    for line in sys.stdin:
        msg = json.loads(line)
        method = msg["method"]
        params = msg.get("params")

        if method == "init":
            result = handle_init(params)
        elif method == "evaluate":
            result = handle_evaluate(params)
        elif method == "close":
            result = "ok"
        else:
            print(json.dumps({"error": f"unknown method: {method}"}), flush=True)
            continue

        print(json.dumps({"result": result}), flush=True)

        if method == "close":
            break

if __name__ == "__main__":
    main()
```

---

## Example: Rate Limiter Plugin (Go, in-process)

```go
package ratelimit

import (
    "context"
    "encoding/json"
    "fmt"
    "sync"
    "time"

    "github.com/BakeLens/crust/internal/plugin"
    "github.com/BakeLens/crust/internal/rules"
)

type Config struct {
    MaxPerMinute int `json:"max_per_minute"` // 0 = unlimited
}

type RateLimiter struct {
    config Config
    mu     sync.Mutex
    window []time.Time
}

func New() plugin.Plugin { return &RateLimiter{} }

func (r *RateLimiter) Name() string { return "rate-limiter" }

func (r *RateLimiter) Init(cfg json.RawMessage) error {
    if cfg != nil {
        return json.Unmarshal(cfg, &r.config)
    }
    return nil
}

func (r *RateLimiter) Evaluate(_ context.Context, req plugin.Request) *plugin.Result {
    if r.config.MaxPerMinute <= 0 {
        return nil
    }

    r.mu.Lock()
    defer r.mu.Unlock()

    now := time.Now()
    cutoff := now.Add(-time.Minute)

    // Trim expired entries
    i := 0
    for i < len(r.window) && r.window[i].Before(cutoff) {
        i++
    }
    r.window = r.window[i:]

    if len(r.window) >= r.config.MaxPerMinute {
        return &plugin.Result{
            RuleName: "ratelimit:exceeded",
            Severity: rules.SeverityWarning,
            Message:  fmt.Sprintf("rate limit exceeded: %d calls/min", r.config.MaxPerMinute),
        }
    }

    r.window = append(r.window, now)
    return nil
}

func (r *RateLimiter) Close() error { return nil }
```

---

## Design Principles

1. **Wire protocol first** — Plugins are external processes communicating over JSON stdin/stdout. Any language can implement a plugin. The Go `Plugin` interface is an internal adapter, not the primary API.

2. **Late-stage only** — Plugins never weaken built-in protections. They run after all built-in pipeline steps pass. A plugin can only block, never allow something the engine blocked.

3. **First-block wins** — Plugins are evaluated concurrently. The first non-nil Result cancels remaining evaluations; when multiple plugins block simultaneously, the one with the lowest registration index wins.

4. **OS-level crash isolation** — External plugins run as separate processes. A segfault, memory leak, or infinite loop in a plugin cannot crash the engine. The worker pool adds goroutine-level isolation with `recover()` + timeout on top.

5. **Circuit breaker with exponential backoff** — A plugin that fails 3 consecutive times is disabled with exponential backoff (5min → 10min → ... → 1hr). After 5 disable cycles, permanently disabled. Prevents buggy plugins from burning resources.

6. **Rule snapshot access** — Plugins receive a read-only snapshot of all active engine rules. This enables context-aware decisions: "is this path already protected?", "are required rules enabled?", "what's the current hit count?"

7. **Unified type system** — `Request` and `Result` share typed enums (`rules.Operation`, `rules.Severity`, `rules.Action`, `rules.Source`) with the YAML rules engine. These serialize to plain strings over the wire protocol, keeping external plugins language-agnostic while ensuring type safety in Go.

8. **Validated results** — Invalid severity values default to `"high"`. Invalid or empty action defaults to `"block"`. Plugin names are cached at registration to prevent spoofing. Request data is deep-copied per plugin to prevent mutation.

9. **Clean lifecycle** — `init` is called once at startup. `close` is called in reverse order during shutdown. The registry rejects new evaluations after close begins.

---

## Schema Validation

The wire protocol has a formal [JSON Schema](../internal/schemacheck/plugin-protocol.schema.json) that serves as the single source of truth. Conformance between the Go implementation and the schema is enforced by `schema_test.go`, which runs in the pre-commit hook.

### What is validated

| Check | Description |
|-------|-------------|
| **Field match** | Every Go struct field (Request, Result, RuleSnapshot, InitParams) has a corresponding schema property, and vice versa |
| **Severity enum** | `rules.ValidSeverities` map matches the schema `severity` enum exactly |
| **Action enum** | `rules.ValidResponseActions` map matches the schema `action` enum exactly |
| **Method constants** | `MethodInit`, `MethodEvaluate`, `MethodClose` match the schema `wireRequest` method constants |
| **Round-trip** | Go structs marshal to JSON containing all schema-required fields |
| **Valid JSON** | The schema file itself is valid JSON |

### Adding a new field

1. Add the field to the Go struct (e.g. `Request` in `plugin.go`)
2. Add the property to the schema (e.g. `evaluateRequest` in `../internal/schemacheck/plugin-protocol.schema.json`)
3. Run `go test ./internal/plugin/ -run TestSchema` — it will fail if either side is missing

### Adding a new enum value

1. Add the value to the Go map (e.g. `rules.ValidSeverities` in `internal/rules/`)
2. Add the value to the schema enum (e.g. `$defs/severity` in `../internal/schemacheck/plugin-protocol.schema.json`)
3. Run `go test ./internal/plugin/ -run TestSchema` — it will fail if they don't match

---

## Future Extensions

The wire protocol is designed to support future additions without breaking existing plugins. Unknown fields in JSON are silently ignored by well-behaved parsers.

| Extension | How |
|-----------|-----|
| **Plugin ordering** | Add `priority` field to init response — registry sorts by priority |
| **Config reload** | New method `reload` with updated config — hot-reload without restart |
| **Bidirectional plugins** | Add `direction` field to Request (`"request"` / `"response"`) for MCP/ACP response scanning |
| **Plugin metrics** | Registry tracks per-plugin call count, block count, latency (exposed via `Stats()`) |
| **Health check** | New method `health` — registry probes periodically to detect stuck processes |
