"""Agent hook adapter registry.

Each adapter describes how to install hooks for a specific AI agent
and how to parse that agent's hook payload into Riva's canonical event schema.

Adding hook support for a new agent = adding one dict to ``ADAPTERS``.
No new files, no new CLI branches, no new hook scripts.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

def _get_python_path() -> str:
    """Return the absolute path to the current Python interpreter."""
    import sys
    return sys.executable

_CMD_TEMPLATE_FMT = "{python} -m riva.hooks.hook {agent} {event} 2>/dev/null || true"


@dataclass
class AgentHookAdapter:
    """Describes how to hook into a specific AI agent."""

    agent_name: str
    cli_key: str
    settings_path: Path
    events: list[str]
    timeout_ms: int = 5000
    hooks_key: str = "hooks"

    # Map canonical field names to agent-specific ones.
    # Canonical: session_id, tool_name, tool_input, tool_output,
    #            tool_response, is_error, transcript_path
    field_map: dict[str, str] = field(default_factory=dict)

    # Short explanation shown when the agent has no hook system
    no_hooks_reason: str | None = None

    # ------------------------------------------------------------------ #
    # Hook entry builders
    # ------------------------------------------------------------------ #

    def build_entry(self, event: str) -> dict:
        """Build a hook registration entry for the agent's settings file."""
        return {
            "matcher": "",
            "hooks": [
                {
                    "type": "command",
                    "command": _CMD_TEMPLATE_FMT.format(
                        python=_get_python_path(), agent=self.cli_key, event=event,
                    ),
                    "timeout": self.timeout_ms,
                }
            ],
        }

    def riva_command(self, event: str) -> str:
        return _CMD_TEMPLATE_FMT.format(
            python=_get_python_path(), agent=self.cli_key, event=event,
        )

    def is_riva_entry(self, entry: dict) -> bool:
        """Return True if *entry* was installed by Riva."""
        return any(
            "riva.hooks.hook" in h.get("command", "")
            or "riva.hooks.claude_code_hook" in h.get("command", "")
            for h in entry.get("hooks", [])
        )

    # ------------------------------------------------------------------ #
    # Payload parsing
    # ------------------------------------------------------------------ #

    def parse_payload(self, event_type: str, data: dict) -> dict:
        """Normalize the agent's stdin payload into Riva's canonical event."""

        def _get(canonical: str) -> Any:
            mapped = self.field_map.get(canonical)
            if mapped and mapped in data:
                return data[mapped]
            if canonical in data:
                return data[canonical]
            camel = _to_camel(canonical)
            return data.get(camel)

        session_id = _get("session_id") or "unknown"

        tool_name = _get("tool_name")
        tool_input = _get("tool_input")
        if not isinstance(tool_input, dict):
            tool_input = None

        tool_output = _get("tool_output") or _get("tool_response")
        if isinstance(tool_output, dict):
            tool_output = json.dumps(tool_output)
        elif tool_output is not None:
            tool_output = str(tool_output)[:2000]

        success = not bool(_get("is_error"))

        return {
            "agent_name": self.agent_name,
            "session_id": str(session_id),
            "event_type": event_type,
            "timestamp": time.time(),
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_output": tool_output,
            "success": success,
            "duration_ms": None,
            "metadata": {
                "transcript_path": _get("transcript_path"),
                "hook_raw_keys": list(data.keys()),
            },
        }


def _to_camel(snake: str) -> str:
    parts = snake.split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


# ====================================================================== #
# Registry
# ====================================================================== #

ADAPTERS: dict[str, AgentHookAdapter] = {}


def _register(adapter: AgentHookAdapter) -> None:
    ADAPTERS[adapter.cli_key] = adapter


def get_adapter(cli_key: str) -> AgentHookAdapter | None:
    return ADAPTERS.get(cli_key)


def available_agents() -> list[str]:
    return sorted(ADAPTERS.keys())


# ====================================================================== #
# Adapters — add new agents here
# ====================================================================== #

_register(AgentHookAdapter(
    agent_name="Claude Code",
    cli_key="claude-code",
    settings_path=Path.home() / ".claude" / "settings.json",
    events=["SessionStart", "PreToolUse", "PostToolUse", "SubagentStop", "Stop"],
    timeout_ms=5000,
    field_map={"tool_output": "tool_response"},
))

# Codex CLI — uncomment when hook support is confirmed
# _register(AgentHookAdapter(
#     agent_name="Codex CLI",
#     cli_key="codex-cli",
#     settings_path=Path.home() / ".codex" / "config.json",
#     events=["session_start", "tool_call", "tool_result", "session_end"],
# ))
