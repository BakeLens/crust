# ACP Integration

Crust can wrap any [ACP](https://agentclientprotocol.com)-compatible agent as a transparent stdio proxy — intercepting file reads, writes, and terminal commands before the IDE executes them. No changes to the agent or IDE required.

```bash
crust wrap -- goose acp
```

## Prerequisites

1. **Crust** installed and on your `PATH`
2. **An ACP-compatible agent** installed and configured with an LLM provider — see [ACP agent list](https://agentclientprotocol.com/get-started/agents)

## Supported Agents

| Agent | Install | ACP command | Notes |
|-------|---------|-------------|-------|
| [Goose](https://github.com/block/goose) | `brew install block-goose-cli` | `goose acp` | Run `goose configure` first to set up your LLM provider |
| [Gemini CLI](https://github.com/google-gemini/gemini-cli) | `npm install -g @google/gemini-cli` | `gemini --experimental-acp` | Requires `GEMINI_API_KEY` or Google OAuth |

> **Important:** Each agent must be independently configured with its own LLM provider and API key before use with Crust. Crust wraps the agent for security — it does not provide the LLM backend. Check each agent's documentation for setup instructions.

## JetBrains IDEs (PhpStorm, IntelliJ, WebStorm, etc.)

Requires a JetBrains IDE with AI Assistant plugin (2025.3+).

> **Note:** If you previously configured Crust as an OpenAI-compatible HTTP endpoint (e.g. `http://localhost:9090/v1`) in **Settings → AI Assistant**, PhpStorm may fail with "Failed to initialize ACP process" when you try to chat. Use the ACP agent setup below instead.

### Step 1: Install and configure an ACP agent

```bash
# Goose
brew install block-goose-cli
goose configure          # set up your LLM provider interactively

# Or Gemini CLI
npm install -g @google/gemini-cli
export GEMINI_API_KEY=...
```

### Step 2: Create `~/.jetbrains/acp.json`

**Goose example:**

```json
{
  "agent_servers": {
    "Goose via Crust": {
      "command": "crust",
      "args": ["wrap", "--", "goose", "acp"]
    }
  }
}
```

**Gemini CLI example:**

```json
{
  "agent_servers": {
    "Gemini via Crust": {
      "command": "crust",
      "args": ["wrap", "--", "gemini", "--experimental-acp"],
      "env": {
        "GEMINI_API_KEY": "..."
      }
    }
  }
}
```

### Step 3: Connect in the IDE

Open **AI Chat** → click **Add Custom Agent** → select your agent.

## VS Code

Install the [ACP Client](https://marketplace.visualstudio.com/items?itemName=formulahendry.acp-client) extension (v0.1.2+), then configure in `settings.json`:

```json
{
  "acp.agents": {
    "Goose via Crust": {
      "enabled": true,
      "command": "crust",
      "args": ["wrap", "--", "goose", "acp"]
    }
  }
}
```

> The extension ships with default configs for many agents — replace the `command` and `args` to route through Crust.

## Other Editors

Any editor that supports ACP (Zed, Neovim via CodeCompanion/avante.nvim) can use `crust wrap`. Consult your editor's ACP documentation for how to configure a custom agent command.

## Status

- ACP handshake (initialize/response) passes through correctly for Goose and Gemini CLI
- Security rules block dangerous `fs/read_text_file`, `fs/write_text_file`, and `terminal/create` requests with a `[Crust]`-prefixed message explaining the block reason and a "Do not retry" directive
- Non-security ACP methods pass through unchanged

Please [open an issue](https://github.com/BakeLens/crust/issues) if you encounter problems with a specific agent or editor.

## CLI Reference

See [CLI docs](cli.md#wrap-flags) for all `crust wrap` flags (`--log-level`, `--rules-dir`, `--disable-builtin`, etc.).
