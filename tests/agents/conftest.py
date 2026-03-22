"""Shared fixtures for agent integration tests.

Starts a Crust gateway instance, deploys test rules, and provides
API key / client fixtures for each agent SDK.

Config schema v2 (see config.yaml.example for full docs):
  crust:
    binary, proxy_port, block_mode
  backend:
    endpoint, api_key, model, agent
  tools:               (optional override)
    exec, read, write, edit, web

v1.1.0 schema (deprecated, auto-migrated):
  crust:
    binary, proxy_port, block_mode, endpoint
  api_keys:
    openai, anthropic
  models:
    openai, anthropic
"""

import os
import shutil
import subprocess
import time
import warnings
from pathlib import Path

import pytest
import yaml


# ---------------------------------------------------------------------------
# Agent tool name registry
# ---------------------------------------------------------------------------

# Maps agent shorthand → canonical operation → tool name used by that agent.
# Each agent's tool names come from their source code / documentation.
AGENT_TOOLS = {
    "claude-code": {
        "exec":  "Bash",
        "read":  "Read",
        "write": "Write",
        "edit":  "Edit",
        "web":   "WebFetch",
    },
    "codex": {
        "exec":  "shell",
        "read":  "read_file",
        "write": "apply_patch",
        "edit":  "apply_patch",
        "web":   "web_search",
    },
    "cline": {
        "exec":  "execute_command",
        "read":  "read_file",
        "write": "write_to_file",
        "edit":  "replace_in_file",
        "web":   "browser_action",
    },
    "cursor": {
        "exec":  "run_terminal_cmd",
        "read":  "read_file",
        "write": "edit_file",
        "edit":  "edit_file",
        "web":   "web_search",
    },
    "openclaw": {
        "exec":  "exec",
        "read":  "Read",
        "write": "Write",
        "edit":  "Edit",
        "web":   "web_search",
    },
    "opencode": {
        "exec":  "bash",
        "read":  "read",
        "write": "write",
        "edit":  "edit",
        "web":   "websearch",
    },
    "windsurf": {
        "exec":  "run_command",
        "read":  "read_file",
        "write": "write_to_file",
        "edit":  "edit_file",
        "web":   "read_url_content",
    },
}

# Tool parameter schemas per canonical operation (OpenAI function calling format).
_TOOL_PARAMS = {
    "exec": {
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "The command to execute"},
        },
        "required": ["command"],
    },
    "read": {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to the file"},
        },
        "required": ["file_path"],
    },
    "write": {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to the file"},
            "content": {"type": "string", "description": "Content to write"},
        },
        "required": ["file_path", "content"],
    },
    "edit": {
        "type": "object",
        "properties": {
            "file_path": {"type": "string", "description": "Absolute path to the file"},
            "old_string": {"type": "string", "description": "Text to find and replace"},
            "new_string": {"type": "string", "description": "Replacement text"},
        },
        "required": ["file_path", "old_string", "new_string"],
    },
    "web": {
        "type": "object",
        "properties": {
            "url": {"type": "string", "description": "The URL to fetch"},
        },
        "required": ["url"],
    },
}

_OP_DESCRIPTIONS = {
    "exec":  "Execute a shell command",
    "read":  "Read a file from disk",
    "write": "Write content to a file",
    "edit":  "Edit a file by replacing text",
    "web":   "Search the web or fetch a URL",
}

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
TESTS_DIR = Path(__file__).parent
RULES_SRC = TESTS_DIR / "rules" / "test_security.yaml"
CONFIG_LOCAL_PATH = TESTS_DIR / "config.local.yaml"
CONFIG_PATH = TESTS_DIR / "config.yaml"
CRUST_RULES_DIR = Path.home() / ".crust" / "rules.d"


# ---------------------------------------------------------------------------
# Config loading + v1.1.0 migration
# ---------------------------------------------------------------------------


def _migrate_v1_config(raw: dict) -> dict:
    """Detect v1.1.0 schema and migrate to v2, emitting deprecation warnings."""
    has_old_keys = "api_keys" in raw or "models" in raw
    has_old_endpoint = "endpoint" in raw.get("crust", {})

    if not has_old_keys and not has_old_endpoint:
        return raw  # Already v2 or empty

    warnings.warn(
        "Deprecated config schema (v1.1.0) detected. "
        "Migrate to v2 'backend:' section — see config.yaml.example. "
        "Old schema support will be removed in a future release.",
        DeprecationWarning,
        stacklevel=3,
    )

    # Build backend section from old fields if not already present
    if "backend" not in raw:
        raw["backend"] = {}

    backend = raw["backend"]

    # crust.endpoint → backend.endpoint
    if has_old_endpoint and not backend.get("endpoint"):
        backend["endpoint"] = raw["crust"].pop("endpoint")

    # api_keys.openai → backend.api_key
    old_keys = raw.get("api_keys", {})
    if old_keys.get("openai") and not backend.get("api_key"):
        backend["api_key"] = old_keys["openai"]

    # models.openai → backend.model
    old_models = raw.get("models", {})
    if old_models.get("openai") and not backend.get("model"):
        backend["model"] = old_models["openai"]

    return raw


def _apply_env_overrides(cfg: dict) -> dict:
    """Apply CRUST_TEST_* environment variable overrides."""
    if "backend" not in cfg:
        cfg["backend"] = {}
    backend = cfg["backend"]

    env_endpoint = os.environ.get("CRUST_TEST_ENDPOINT")
    if env_endpoint:
        backend["endpoint"] = env_endpoint

    env_key = os.environ.get("CRUST_TEST_API_KEY")
    if env_key:
        backend["api_key"] = env_key

    env_model = os.environ.get("CRUST_TEST_MODEL")
    if env_model:
        backend["model"] = env_model

    return cfg


def _validate_config(cfg: dict, source_path: str) -> None:
    """Validate config and fail with friendly messages on errors."""
    errors = []

    # -- Unknown top-level keys (catch typos like "backends:" or "cust:") --
    known_top = {"crust", "backend", "tools", "api_keys", "models"}
    unknown = set(cfg.keys()) - known_top
    if unknown:
        errors.append(
            f"Unknown top-level key(s): {', '.join(sorted(unknown))}. "
            f"Valid keys: {', '.join(sorted(known_top))}"
        )

    # -- crust section --
    crust = cfg.get("crust", {})
    if not isinstance(crust, dict):
        errors.append("'crust' must be a mapping (got {})".format(type(crust).__name__))
    else:
        known_crust = {"binary", "proxy_port", "block_mode"}
        unknown_crust = set(crust.keys()) - known_crust
        # Allow "endpoint" from v1 configs (handled by migration)
        unknown_crust.discard("endpoint")
        if unknown_crust:
            errors.append(
                f"Unknown key(s) in 'crust': {', '.join(sorted(unknown_crust))}. "
                f"Valid: {', '.join(sorted(known_crust))}"
            )

        port = crust.get("proxy_port")
        if port is not None:
            if not isinstance(port, int) or port < 1 or port > 65535:
                errors.append(f"crust.proxy_port: must be 1-65535 (got {port!r})")

        bm = crust.get("block_mode", "replace")
        if bm not in ("remove", "replace"):
            errors.append(
                f"crust.block_mode: must be 'remove' or 'replace' (got {bm!r})"
            )

    # -- backend section --
    backend = cfg.get("backend", {})
    if not isinstance(backend, dict):
        errors.append("'backend' must be a mapping (got {})".format(type(backend).__name__))
    else:
        known_backend = {"endpoint", "api_key", "model", "agent"}
        unknown_backend = set(backend.keys()) - known_backend
        if unknown_backend:
            errors.append(
                f"Unknown key(s) in 'backend': {', '.join(sorted(unknown_backend))}. "
                f"Valid: {', '.join(sorted(known_backend))}"
            )

        endpoint = backend.get("endpoint", "")
        if endpoint and not (endpoint.startswith("http://") or endpoint.startswith("https://")):
            errors.append(
                f"backend.endpoint: must start with http:// or https:// (got {endpoint!r})"
            )

        agent = backend.get("agent", "openclaw")
        if agent not in AGENT_TOOLS:
            available = ", ".join(sorted(AGENT_TOOLS.keys()))
            errors.append(
                f"backend.agent: unknown agent {agent!r}. "
                f"Available: {available}"
            )

    # -- tools section (optional overrides) --
    tools = cfg.get("tools")
    if tools is not None:
        if not isinstance(tools, dict):
            errors.append("'tools' must be a mapping (got {})".format(type(tools).__name__))
        else:
            valid_ops = {"exec", "read", "write", "edit", "web"}
            unknown_ops = set(tools.keys()) - valid_ops
            if unknown_ops:
                errors.append(
                    f"Unknown key(s) in 'tools': {', '.join(sorted(unknown_ops))}. "
                    f"Valid: {', '.join(sorted(valid_ops))}"
                )
            for op, name in tools.items():
                if op in valid_ops and (not isinstance(name, str) or not name.strip()):
                    errors.append(f"tools.{op}: must be a non-empty string (got {name!r})")

    if errors:
        msg = f"\n\nConfig validation failed ({source_path}):\n"
        for i, e in enumerate(errors, 1):
            msg += f"  {i}. {e}\n"
        msg += f"\nSee config.yaml.example for the expected schema.\n"
        pytest.fail(msg, pytrace=False)


def _load_config():
    """Load config.local.yaml (preferred) or config.yaml, or skip.

    Applies v1.1.0 migration, env var overrides, then validates.
    """
    for path in (CONFIG_LOCAL_PATH, CONFIG_PATH):
        if path.exists():
            with open(path) as f:
                raw = yaml.safe_load(f)
            if not isinstance(raw, dict):
                pytest.fail(
                    f"\n\n{path.name} is not a valid YAML mapping.\n"
                    f"See config.yaml.example for the expected schema.\n",
                    pytrace=False,
                )
            raw = _migrate_v1_config(raw)
            raw = _apply_env_overrides(raw)
            _validate_config(raw, str(path))
            return raw
    pytest.skip(
        "tests/agents/config.yaml not found — "
        "copy config.yaml.example and fill in your API keys",
        allow_module_level=True,
    )


# ---------------------------------------------------------------------------
# Session-scoped fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def config():
    """Parsed config dict (v2 schema, migrated if needed)."""
    return _load_config()


@pytest.fixture(scope="session")
def crust_binary(config):
    """Resolved path to the crust binary."""
    binary = config.get("crust", {}).get("binary", "crust")
    # If it's a bare name, look it up on PATH
    resolved = shutil.which(binary)
    if resolved is None:
        # Try building from the repo root
        repo_root = TESTS_DIR.parent.parent
        subprocess.check_call(["go", "build", "-o", "crust", "."], cwd=repo_root)
        resolved = str(repo_root / "crust")
    return resolved


@pytest.fixture(scope="session")
def test_rules():
    """Deploy test security rules to ~/.crust/rules.d/ for the session."""
    CRUST_RULES_DIR.mkdir(parents=True, exist_ok=True)
    dest = CRUST_RULES_DIR / "test_security.yaml"
    shutil.copy2(RULES_SRC, dest)
    yield dest
    # Cleanup
    dest.unlink(missing_ok=True)


@pytest.fixture(scope="session")
def crust_gateway(config, crust_binary, test_rules):
    """Start a Crust gateway for the test session, yield the base URL, then stop it."""
    crust_cfg = config.get("crust", {})
    proxy_port = crust_cfg.get("proxy_port", 9099)
    block_mode = crust_cfg.get("block_mode", "replace")

    backend = config.get("backend", {})
    endpoint = backend.get("endpoint", "")
    backend_key = backend.get("api_key", "dummy")

    base_url = f"http://localhost:{proxy_port}"

    # Stop any existing instance on this port (best-effort)
    subprocess.run(
        [crust_binary, "stop"],
        capture_output=True,
        timeout=5,
    )
    time.sleep(0.5)

    # Start Crust — use explicit endpoint if configured, otherwise auto mode
    cmd = [
        crust_binary, "start",
        "--block-mode", block_mode,
        "--proxy-port", str(proxy_port),
    ]
    if endpoint:
        cmd.extend(["--endpoint", endpoint, "--api-key", backend_key])
    else:
        cmd.append("--auto")
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if proc.returncode != 0:
        pytest.fail(f"Failed to start Crust: {proc.stderr}")

    # Wait for readiness
    health_url = f"{base_url}/health"
    for attempt in range(30):
        try:
            import urllib.request
            resp = urllib.request.urlopen(health_url, timeout=2)
            if resp.status == 200:
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        pytest.fail(f"Crust did not become ready at {health_url}")

    # Reload rules so the test rules are picked up
    subprocess.run(
        [crust_binary, "reload-rules"],
        capture_output=True,
        timeout=5,
    )

    yield base_url

    # Teardown
    subprocess.run(
        [crust_binary, "stop"],
        capture_output=True,
        timeout=5,
    )


@pytest.fixture(scope="session")
def crust_url(crust_gateway):
    """The Crust gateway base URL (e.g. http://localhost:9099)."""
    return crust_gateway


# ---------------------------------------------------------------------------
# Backend fixtures (v2)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def api_key(config):
    """Backend API key from config or env var."""
    key = config.get("backend", {}).get("api_key", "")
    if not key:
        pytest.skip("No API key configured (set backend.api_key or CRUST_TEST_API_KEY)")
    return key


@pytest.fixture(scope="session")
def model(config):
    """Backend model name from config or env var."""
    return config.get("backend", {}).get("model", "gpt-4o-mini")


@pytest.fixture
def client(crust_url, api_key):
    """OpenAI client pointing at Crust gateway."""
    from openai import OpenAI
    return OpenAI(api_key=api_key, base_url=f"{crust_url}/v1")


# ---------------------------------------------------------------------------
# Agent tool name fixtures
# ---------------------------------------------------------------------------


def _resolve_tool_names(config: dict) -> dict:
    """Resolve tool names from agent shorthand + optional overrides.

    Priority: config.tools.{op} > AGENT_TOOLS[agent] > AGENT_TOOLS["openclaw"]
    """
    backend = config.get("backend", {})
    agent = os.environ.get("CRUST_TEST_AGENT", backend.get("agent", "openclaw"))

    if agent not in AGENT_TOOLS:
        available = ", ".join(sorted(AGENT_TOOLS.keys()))
        pytest.fail(f"Unknown agent '{agent}'. Available: {available}")

    # Start with agent defaults
    names = dict(AGENT_TOOLS[agent])

    # Apply explicit overrides from config.tools
    overrides = config.get("tools", {})
    for op in ("exec", "read", "write", "edit", "web"):
        if overrides.get(op):
            names[op] = overrides[op]

    return names


@pytest.fixture(scope="session")
def agent_name(config):
    """The configured agent name (e.g. 'openclaw', 'cline', 'cursor')."""
    backend = config.get("backend", {})
    return os.environ.get("CRUST_TEST_AGENT", backend.get("agent", "openclaw"))


@pytest.fixture(scope="session")
def tool_names(config):
    """Dict mapping canonical operation → agent-specific tool name.

    Example: {"exec": "execute_command", "read": "read_file", ...}
    """
    return _resolve_tool_names(config)


def _make_tool_def(name: str, op: str) -> dict:
    """Build an OpenAI function tool definition."""
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": _OP_DESCRIPTIONS[op],
            "parameters": _TOOL_PARAMS[op],
        },
    }


@pytest.fixture(scope="session")
def tool_defs(tool_names):
    """Dict mapping canonical operation → OpenAI tool definition.

    Example usage:
        resp = client.chat.completions.create(
            tools=[tool_defs["exec"]],
            tool_choice={"type": "function", "function": {"name": tool_names["exec"]}},
            ...
        )
    """
    return {op: _make_tool_def(name, op) for op, name in tool_names.items()}


# ---------------------------------------------------------------------------
# Deprecated fixtures (v1.1.0 compat — remove in future release)
# ---------------------------------------------------------------------------


@pytest.fixture(scope="session")
def openai_api_key(api_key):
    """Deprecated: use 'api_key' fixture instead."""
    warnings.warn(
        "openai_api_key fixture is deprecated, use 'api_key' instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return api_key


@pytest.fixture(scope="session")
def openai_model(model):
    """Deprecated: use 'model' fixture instead."""
    warnings.warn(
        "openai_model fixture is deprecated, use 'model' instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return model


@pytest.fixture
def openai_client(client):
    """Deprecated: use 'client' fixture instead."""
    warnings.warn(
        "openai_client fixture is deprecated, use 'client' instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return client


@pytest.fixture(scope="session")
def anthropic_api_key(config):
    """Deprecated: Anthropic-specific fixture. Use 'api_key' instead."""
    warnings.warn(
        "anthropic_api_key fixture is deprecated — all tests use the OpenAI-compatible "
        "proxy. Use 'api_key' fixture instead.",
        DeprecationWarning,
        stacklevel=2,
    )
    # Try old schema first, then fall back to backend.api_key
    key = config.get("api_keys", {}).get("anthropic", "")
    if not key:
        key = config.get("backend", {}).get("api_key", "")
    if not key:
        pytest.skip("No Anthropic API key configured")
    return key


@pytest.fixture(scope="session")
def anthropic_model(config):
    """Deprecated: use 'model' fixture instead."""
    warnings.warn(
        "anthropic_model fixture is deprecated, use 'model' instead",
        DeprecationWarning,
        stacklevel=2,
    )
    return config.get("models", {}).get("anthropic",
           config.get("backend", {}).get("model", "claude-haiku-4-5-20251001"))


@pytest.fixture
def anthropic_client(crust_url, anthropic_api_key):
    """Deprecated: use 'client' fixture instead."""
    warnings.warn(
        "anthropic_client fixture is deprecated, use 'client' instead",
        DeprecationWarning,
        stacklevel=2,
    )
    from anthropic import Anthropic
    return Anthropic(api_key=anthropic_api_key, base_url=crust_url)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def response_contains_block_message(text: str) -> bool:
    """Check if response text contains a Crust block message."""
    indicators = ["[Crust]", "Blocked by Crust", "blocked", "BLOCKED"]
    lower = text.lower()
    return any(ind.lower() in lower for ind in indicators)


def collect_streaming_text(stream) -> str:
    """Collect all text from an OpenAI streaming response."""
    chunks = []
    for chunk in stream:
        if chunk.choices and chunk.choices[0].delta.content:
            chunks.append(chunk.choices[0].delta.content)
    return "".join(chunks)


