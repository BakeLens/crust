# TUI Design

Crust's terminal UI is an optional layer over plain CLI output. Every command works identically with or without it.

## Principles

1. **TUI is invisible when you're not looking.** Styling activates only when stdout is a terminal. Piped output, redirected files, background daemons, and CI all get clean plain text automatically. `NO_COLOR=1` forces plain mode unconditionally. The `notui` build tag removes interactive charmbracelet components (`bubbletea`) at compile time. No feature depends on TUI being present.

2. **One canonical output path.** All user-facing messages go through `PrintSuccess`, `PrintError`, `PrintWarning`, `PrintInfo`. These handle prefix, icon, and plain mode automatically. Never use raw `fmt.Println` for status output.

3. **Styles are data, not functions.** Every `Style*` export is a `lipgloss.Style` variable. Call `.Render()` on them. Capability-aware helpers (`Hyperlink()`, `Faint()`, `Italic()`, `Strikethrough()`, `WindowTitle()`) are functions because they check terminal capabilities before applying styles.

4. **Icons are universal.** All icons use Unicode BMP glyphs (U+2500-U+25CF) that render in every terminal without font installation.

5. **Colors are centralized.** All colors live in `styles.go` as `Color*` adaptive color variables. Styles reference these. No inline `lipgloss.Color()` calls outside `styles.go`. Exception: `banner.go` uses per-character inline styles for gradient rendering, which requires interpolated colors that cannot be pre-defined.

6. **Sub-packages own features, core owns primitives.** `internal/tui/` has styles, icons, print helpers, and columns. `banner/`, `spinner/`, `startup/` are self-contained features that import the core.

7. **Every `_notui.go` mirrors its counterpart.** Same package, same exported API, plain text implementation. Build tags (`//go:build !notui` / `//go:build notui`) select one or the other. They must stay in sync. The `_notui.go` files may import `internal/tui` for print helpers — the core package always compiles regardless of build tags.

8. **Commands offer `--json` for machine consumption.** Commands that produce structured data (`status`, `version`, `list-rules`) support `--json` for scripting and CI integration. JSON output bypasses all TUI styling — no colors, no icons, no prefix.

9. **Interactive components degrade gracefully.** Bubbletea-based interactive components (forms, tables, viewports) fall back to static output in plain mode, piped contexts, and `notui` builds. Interactive mode is opt-in via TTY detection — never block scripted workflows.

10. **Animations serve purpose.** Animations indicate activity (spinner), progress (progress bar), or draw attention (banner reveal, block flash). Every animation can be skipped with a keypress. No decorative-only animations that slow down the user.

## Package Layout

```text
internal/tui/
  styles.go         Centralized colors, styles, capability-aware helpers
  icons.go          Unicode BMP icon constants
  print.go          PrintSuccess/Error/Warning/Info with [crust] prefix
  columns.go        AlignColumns() for ANSI-aware two-column alignment
  banner/           Gradient ASCII art banner with reveal animation + RevealLines
  spinner/          Animated dot spinner with success glow effect
  startup/          Manual endpoint setup (huh form for --manual mode)
  terminal/         Terminal emulator detection and capability bitfield
  progress/         Determinate progress bar for multi-step operations
  dashboard/        Live status dashboard with auto-refreshing metrics + stats tab
  logview/          Scrollable log viewport with syntax highlighting + block flash
  rulelist/         Interactive filterable rules list with scroll navigation
```

## Live Dashboard

The live dashboard (`crust status --live`) is a bubbletea-based interactive TUI with three tabs, auto-refreshing every 2 seconds.

### Tabs

| Tab | Key | Content |
|-----|-----|---------|
| **Overview** | `1` | PID, rules, health, security status, blocked call counter with shimmer animation |
| **Sessions** | `2` | Split-pane: session list (left) with per-session events (right). `↑↓` to navigate sessions |
| **Stats** | `3` | Block trend chart (7 days), block distribution by rule/tool (30 days), tool coverage |

Press `tab` to cycle tabs, number keys for direct access, `r` to force refresh, `q` to quit.

### Stats Tab

The Stats tab visualizes data from the stats aggregation API endpoints:

- **Block Trend** — Horizontal bar chart showing daily total vs blocked calls over 7 days. Blocked bars render in red, allowed in green. Scaled relative to the busiest day.
- **Block Distribution** — Top 5 rules and top 5 tools ranked by block count over 30 days.
- **Tool Coverage** — Detected AI tools with total call count, blocked count, and API type. Tools with blocks show `⊘ N blocked`; clean tools show `✔`.

Data is fetched from `/api/telemetry/stats/trend`, `/api/telemetry/stats/distribution`, and `/api/telemetry/stats/coverage`.

## Plain Mode

Plain mode disables all colors, icons, borders, and animations. It is the default whenever stdout is not an interactive terminal — no ANSI escape codes leak into pipes, redirected files, log files, or CI output.

Detection precedence (evaluated once on first `IsPlainMode()` call):

1. `NO_COLOR=1` environment variable — plain ON ([no-color.org](https://no-color.org))
2. TTY detection — if stdout is not a terminal, plain ON
3. Terminal capability detection — if the emulator is unrecognized and `COLORTERM` is not set, plain ON (TUI is enabled only on supported terminals)
4. `--no-color` CLI flag — calls `tui.SetPlainMode(true)` before any output
5. `notui` build tag — compile-time, removes interactive components (spinner animation, banner reveal)

TUI is enabled by default on all supported emulators listed below. Unrecognized terminals fall back to plain mode automatically. To force TUI on an unlisted terminal, set `COLORTERM=truecolor`.

For scripting and data pipelines, use `--json` on supported commands (`status`, `version`, `list-rules`) to get structured output with no TUI artifacts at all.

Check with `tui.IsPlainMode()` before using any styled output.

## Build Tags

```bash
go build ./...              # Default: full TUI with bubbletea animations
go build -tags notui ./...  # No TUI: removes bubbletea, keeps lipgloss styling
task build                  # Default build
task build-notui            # notui build
```

The `notui` tag removes `bubbletea` and `huh` (interactive framework for spinner, banner, forms, progress, dashboard, log viewer, rule list) from sub-packages via `_notui.go` counterparts. The core `internal/tui/` package (styles, icons, print helpers, columns) always compiles with `lipgloss` — use `NO_COLOR=1` or `--no-color` to disable styling at runtime.

Install scripts support `--no-tui` (bash) or `-NoTUI` (PowerShell).

## Supported Terminals

The TUI uses Unicode BMP characters and ANSI/VT100 sequences with truecolor (24-bit) colors. All visual elements are compatible with the terminals listed below.

### Baseline (OS default)

| OS | Terminal |
|---|---|
| macOS | Terminal.app |
| Linux | GNOME Terminal |
| Linux | Konsole |
| Windows | Windows Terminal |

### Advanced (popular third-party)

| Terminal | Platforms |
|---|---|
| iTerm2 | macOS |
| Alacritty | macOS, Linux, Windows |
| Kitty | macOS, Linux |
| WezTerm | macOS, Linux, Windows |
| foot | Linux (Wayland) |
| Tilix | Linux |

Advanced terminals are a superset of baseline capabilities. Anything that renders on the baseline renders on advanced emulators.

### Visual element compatibility

| Element | Unicode block | Codepoints |
|---|---|---|
| Logo box-drawing | Box Drawings | U+2550–U+256C |
| Border (lipgloss) | Box Drawings | U+256D–U+2570, U+2500, U+2502 |
| Separator bar | Box Drawings | U+2501 |
| Icons (default) | Geometric Shapes | U+25A0–U+25CF |
| Check / Cross | Dingbats | U+2713, U+2717 |
| Block icon | Math Operators | U+2298 |
| Spinner dots | Braille Patterns | U+2800–U+28FF |

All visual elements use BMP codepoints supported by every listed terminal.

Terminals not listed here will likely work if they support VT100 sequences and Unicode BMP. For unsupported or minimal terminals, plain mode (`NO_COLOR=1` or `--no-color`) disables all styling.

### Terminal detection

At startup, `internal/tui/terminal/` detects the terminal emulator via environment variables and exposes its capabilities as a bitfield.

**Detection order** (most-specific first):

| Env var | Terminal |
|---|---|
| `WT_SESSION` | Windows Terminal |
| `KITTY_WINDOW_ID` | Kitty |
| `ALACRITTY_LOG` | Alacritty |
| `WEZTERM_EXECUTABLE` | WezTerm |
| `TILIX_ID` | Tilix |
| `KONSOLE_VERSION` | Konsole |
| `GNOME_TERMINAL_SCREEN` / `VTE_VERSION` | GNOME Terminal |
| `TERM_PROGRAM=vscode` | VS Code |
| `TERM_PROGRAM=iTerm.app` | iTerm2 |
| `TERM_PROGRAM=Apple_Terminal` | Terminal.app |
| `TERM=foot*` | foot |

**Capabilities** (bitfield — used internally by helper functions):

| Capability | Description |
|---|---|
| `CapTruecolor` | 24-bit color |
| `CapHyperlinks` | OSC 8 clickable links |
| `CapItalic` | ANSI italic attribute |
| `CapFaint` | ANSI faint/dim attribute |
| `CapStrikethrough` | ANSI strikethrough |
| `CapWindowTitle` | OSC 0/2 window title |

**Per-terminal capability exceptions:**

- **Terminal.app**: No truecolor, no hyperlinks, no strikethrough (256-color only)
- **Konsole**: No hyperlinks (disabled by default in most versions)
- **Unknown terminals**: Conservative — only `CapTruecolor` if `COLORTERM=truecolor`

**Multiplexer awareness:** When `TMUX` or `STY` (screen) is detected, `Info.Multiplexed` is set to `true`. Detection still identifies the underlying terminal, but callers should be aware capabilities may be degraded through the multiplexer.

**Known limitations:**
- SSH sessions: terminal env vars are not forwarded by default → `Unknown`
- Containers: no terminal env vars → `Unknown`; `--foreground` overrides plain mode when TTY is present (see [Docker / Containers](#docker--containers))
- tmux/screen: env vars may not propagate; detection is best-effort

**Usage:**

```go
// Use capability-aware helpers — they check detection + plain mode internally
link := tui.Hyperlink("https://example.com", "click here")
dim  := tui.Faint("secondary text")
em   := tui.Italic("emphasis")
del  := tui.Strikethrough("removed")
tui.WindowTitle("crust status")
```

## Docker / Containers

Crust's TUI adapts automatically when running inside containers with `--foreground`.

### How foreground mode works

Docker containers differ from local terminals in two ways:

1. **No terminal emulator processes escape queries.** bubbletea's package `init()` sends OSC 11 and DSR sequences to stdout. Without a terminal emulator, these appear as garbage (`^[]11;?^[\^[[6n]`) in `docker logs`.
2. **No terminal-specific env vars.** Containers lack `WT_SESSION`, `KITTY_WINDOW_ID`, `VTE_VERSION`, etc., so terminal detection returns `CapNone` → plain mode, even with a TTY via `-t`.

Crust handles both with a two-phase approach:

**Phase 1: earlyinit** (`internal/earlyinit`) — runs before bubbletea's `init()` via Go's package initialization ordering (dependency order, then lexicographic tiebreaker). When `--foreground` is in `os.Args`, saves the original `TERM` and checks if stdout is a real TTY via `term.IsTerminal()`. If stdout is **not** a TTY (e.g. `docker run -d` without `-t`), sets `TERM=dumb` to suppress terminal queries. If stdout **is** a TTY (e.g. `docker run -it`), leaves `TERM` alone so lipgloss detects color support normally.

**Phase 2: runStart()** — after bubbletea's init has safely completed:

1. If earlyinit suppressed TERM: restores original `TERM`, sets `lipgloss.SetColorProfile()` and `lipgloss.SetHasDarkBackground(true)` — configures the renderer without terminal queries
2. If earlyinit did not suppress (TTY present): no restore needed — lipgloss auto-detected correctly
3. If stdout is a TTY and `TERM` supports colors, calls `tui.SetPlainMode(false)` — overrides the `CapNone` → plain fallback
4. In `runDaemon()`, logger colors are enabled when stderr is a TTY (foreground), disabled otherwise (daemon writes to log files)

`NO_COLOR` and `--no-color` still take priority and force plain mode.

### Behavior by Docker mode

| Mode | TTY | Styled output | Logger colors | Notes |
|------|-----|---------------|---------------|-------|
| `docker run -d` | No | No (plain) | No | No TTY → earlyinit suppresses TERM |
| `docker run -d -t` | Yes | Yes (ANSI) | Yes | TTY allocated; earlyinit skips suppression |
| `docker run -t` | Yes | Yes (ANSI) | Yes | Attached with TTY |
| `docker run -it` | Yes | Yes (ANSI) | Yes | Interactive; full TUI auto-detected via TTY |

Earlyinit checks `term.IsTerminal(stdout)` at init time. With `-t`, a real TTY exists so TERM is left alone and lipgloss auto-detects color support. Without `-t`, earlyinit sets `TERM=dumb` to suppress escape queries.

### Recommended Docker usage

```bash
# Production: detached with styled logs
docker run -d -t -p 9090:9090 crust

# Production: plain text logs (no -t)
docker run -d -p 9090:9090 crust

# Interactive setup inside container (manual mode)
docker run -it --entrypoint crust crust start --foreground --manual

# View logs (styled with -t, plain without)
docker logs <container>

# Force plain even with TTY
docker run -d -t -e NO_COLOR=1 -p 9090:9090 crust
```

The default Dockerfile entrypoint includes `--listen-address 0.0.0.0` to accept host connections.

### Remote dashboard

When `--listen-address` is non-loopback (as in Docker's default `0.0.0.0`), the management API is also available on the proxy port (9090), so you can run the interactive dashboard on the host:

```bash
crust status --live --api-addr localhost:9090
```

See [docker.md](docker.md#remote-dashboard-from-host) for full details.

### What works in Docker

All rule-based blocking, tool call inspection (Layers 0 & 1), content scanning, telemetry, and auto-mode provider resolution. These operate on API traffic passing through the proxy and work regardless of where Crust runs.

### Persistent data

Telemetry and the SQLite database are stored at `/home/crust/.crust/crust.db`. Mount a volume to persist across restarts:

```bash
docker run -d -t -p 9090:9090 -v crust-data:/home/crust/.crust crust
```

If using database encryption (`DB_KEY`), the same key must be provided on every restart.

## Adding a New TUI Component

1. Create `internal/tui/yourpkg/yourpkg.go` with `//go:build !notui`
2. Create `internal/tui/yourpkg/yourpkg_notui.go` with `//go:build notui`
3. Both files must export the same public API
4. Use `tui.Print*` helpers for output, `tui.Style*` for styling
5. Check `tui.IsPlainMode()` for runtime plain fallback in the TUI build
6. Verify: `go build ./...` and `go build -tags notui ./...`
