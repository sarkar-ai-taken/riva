"""Generic Riva hook script for any AI agent.

Reads stdin, normalizes the payload via the agent's adapter, POSTs to Riva.

Usage:
    python -m riva.hooks.hook <agent-cli-key> <EventType>

Examples:
    python -m riva.hooks.hook claude-code PostToolUse
    python -m riva.hooks.hook codex-cli   tool_call

Environment variables:
    RIVA_SERVER_URL   Base URL of the Riva server (default: http://127.0.0.1:8585)
    RIVA_AUTH_TOKEN   Bearer token if Riva is started with --auth-token
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

_SERVER_URL = os.environ.get("RIVA_SERVER_URL", "http://127.0.0.1:8585").rstrip("/")
_AUTH_TOKEN = os.environ.get("RIVA_AUTH_TOKEN", "")
_TIMEOUT = 3.0


def _post(payload: dict) -> None:
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if _AUTH_TOKEN:
        headers["Authorization"] = f"Bearer {_AUTH_TOKEN}"

    req = urllib.request.Request(
        f"{_SERVER_URL}/api/events",
        data=body,
        headers=headers,
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT):
            pass
    except (urllib.error.URLError, OSError):
        pass


def main() -> None:
    from riva.hooks.adapters import get_adapter

    agent_key = sys.argv[1] if len(sys.argv) > 1 else "claude-code"
    event_type = sys.argv[2] if len(sys.argv) > 2 else "unknown"

    # Read stdin
    try:
        raw = sys.stdin.read()
        data = json.loads(raw) if raw.strip() else {}
    except (json.JSONDecodeError, OSError):
        data = {}

    adapter = get_adapter(agent_key)
    if adapter is not None:
        payload = adapter.parse_payload(event_type, data)
    else:
        # Unknown agent — best-effort forwarding
        payload = {
            "agent_name": agent_key,
            "session_id": data.get("session_id", "unknown"),
            "event_type": event_type,
            "timestamp": time.time(),
            "tool_name": data.get("tool_name"),
            "tool_input": data.get("tool_input") if isinstance(data.get("tool_input"), dict) else None,
            "tool_output": None,
            "success": True,
            "duration_ms": None,
            "metadata": {"hook_raw_keys": list(data.keys())},
        }

    _post(payload)


if __name__ == "__main__":
    main()
