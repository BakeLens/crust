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

# ─── Start gateway (clean screen → big logo) ─────────────────────────────
Type "crust start --auto"
Enter
Sleep 6s
# Pause to admire the logo
Sleep 3s

# ─── HTTP Proxy: real GLM-4-Plus attack interception ────────────────────
Hide
Type "clear"
Enter
Sleep 0.3s
Show
Type "# Real GLM-4-Plus — 6 attacks through the gateway"
Enter
Sleep 1.5s
Type "bash scripts/demo-attack.sh"
Enter
Sleep 20s
# Pause on results
Sleep 3s

# ─── ACP Stdio Proxy: VS Code agent operations ─────────────────────────
Type "# ACP stdio proxy — wrapping VS Code + GLM-4-Plus agent"
Enter
Sleep 1.5s
Type "bash scripts/demo-acp.sh"
Enter
Sleep 8s

# ─── Status overview ─────────────────────────────────────────────────────
Hide
Type "clear"
Enter
Sleep 0.3s
Show
Type "crust status"
Enter
Sleep 5s

# ─── Live dashboard: Overview ────────────────────────────────────────────
Type "crust status --live"
Enter
Sleep 4s

# ─── Live dashboard: Sessions tab ────────────────────────────────────────
Type "2"
Sleep 4s
Down
Sleep 3s
Type "1"
Sleep 2s
Type "q"
Sleep 0.5s

# ─── Rule list ───────────────────────────────────────────────────────────
Type "crust list-rules"
Enter
Sleep 4s
Down 3
Sleep 2s
Down 3
Sleep 2s
Type "/"
Sleep 0.5s
Type "ssh"
Sleep 4s
Escape
Sleep 0.5s
Type "q"
Sleep 0.5s

# ─── Log viewer ──────────────────────────────────────────────────────────
Type "crust logs"
Enter
Sleep 4s
Down 5
Sleep 3s
Up 3
Sleep 3s
Type "q"
Sleep 0.5s

# ─── Stop ────────────────────────────────────────────────────────────────
Type "crust stop"
Enter
Sleep 3s

# ─── End ─────────────────────────────────────────────────────────────────
Sleep 1s
