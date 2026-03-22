# Crust Demo — real GLM-4-Plus attacks, HTTP + ACP proxy, observability
# Usage: ZHIPUAI_API_KEY=xxx vhs scripts/demo-tui.tape
# Prerequisites: go build -o crust . && go build -o cmd/mock-acp-agent/mock-acp-agent ./cmd/mock-acp-agent

Output docs/demo-tui.mp4

# ─── Settings ─────────────────────────────────────────────────────────────
Set FontSize 14
Set FontFamily "Cascadia Mono NF"
Set Width 1200
Set Height 800
Set Framerate 30
Set Theme "GruvboxDark"
Set TypingSpeed 25ms
Set Padding 20
Set LineHeight 1.2
Set Shell bash

# ─── Privacy ──────────────────────────────────────────────────────────────
Env PS1 "$ "

# ═══════════════════════════════════════════════════════════════════════════
# Hidden setup: clean slate, export API key
# ═══════════════════════════════════════════════════════════════════════════
Hide
Type "./crust stop 2>/dev/null; sleep 0.3"
Enter
Sleep 0.5s
Type "export HOME=/tmp/demo && export PATH=.:$PATH && export ZHIPUAI_API_KEY=${ZHIPUAI_API_KEY:-}"
Enter
Sleep 0.1s
# Clean DB *after* setting HOME so it targets /tmp/demo/.crust/
Type "rm -f ~/.crust/crust.db ~/.crust/crust.db-shm ~/.crust/crust.db-wal ~/.crust/config.yaml"
Enter
Sleep 0.3s
Type "mkdir -p ~/.crust"
Enter
Sleep 0.1s
Type "clear"
Enter
Sleep 0.3s
Show

# ─── Doctor: system diagnostics ──────────────────────────────────────────
Type "# Step 1: Run diagnostics"
Enter
Sleep 1.5s
Type "crust doctor"
Enter
Sleep 6s

# ─── Start gateway ───────────────────────────────────────────────────────
Type "# Step 2: Start the security gateway"
Enter
Sleep 1.5s
Type "crust start --auto"
Enter
Sleep 3s

# ─── HTTP Proxy: real GLM-4-Plus attack interception ────────────────────
Hide
Type "clear"
Enter
Sleep 0.3s
Show
Type "# Step 3: Real GLM-4-Plus — 8 attacks through the gateway"
Enter
Sleep 1.5s
Type "bash scripts/demo-attack.sh"
Enter
Sleep 25s

# ─── ACP Stdio Proxy: VS Code agent operations ─────────────────────────
Type "# Step 4: ACP stdio proxy — wrapping VS Code + GLM-4-Plus agent"
Enter
Sleep 1.5s
Type "bash scripts/demo-acp.sh"
Enter
Sleep 7s

# ─── Status overview ─────────────────────────────────────────────────────
Hide
Type "clear"
Enter
Sleep 0.3s
Show
Type "crust status"
Enter
Sleep 3s

# ─── Live dashboard: Overview ────────────────────────────────────────────
Type "crust status --live"
Enter
Sleep 3s

# ─── Live dashboard: Sessions tab ────────────────────────────────────────
Type "2"
Sleep 2s
Down
Sleep 1.5s
Type "1"
Sleep 1s
Type "q"
Sleep 0.5s

# ─── Log viewer ──────────────────────────────────────────────────────────
Type "crust logs"
Enter
Sleep 3s
Down 5
Sleep 2s
Up 3
Sleep 2s
Type "q"
Sleep 0.5s

# ─── Rule list + ssh filter ──────────────────────────────────────────────
Type "crust list-rules"
Enter
Sleep 3s
Down 3
Sleep 1s
Down 3
Sleep 1s
Type "/"
Sleep 0.5s
Type "ssh"
Sleep 2s
Escape
Sleep 0.5s
Type "q"
Sleep 0.5s

# ─── Stop ────────────────────────────────────────────────────────────────
Type "crust stop"
Enter
Sleep 2s

# ─── End ─────────────────────────────────────────────────────────────────
Sleep 1s
