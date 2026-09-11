"""OpenCode agent detector."""

from __future__ import annotations

import json
import os
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from riva.agents.base import AgentDetector
from riva.core.usage_stats import (
    DailyStats,
    ModelStats,
    TokenUsage,
    ToolCallStats,
    UsageStats,
)
from riva.utils.jsonl import find_recent_sessions


class OpenCodeDetector(AgentDetector):
    """Detect OpenCode — open-source AI coding agent for the terminal.

    OpenCode is a Go-based CLI that provides a TUI for interacting with
    various AI providers.  Config lives in ``~/.config/opencode/`` and the
    binary is simply ``opencode``.
    """

    @property
    def agent_name(self) -> str:
        return "OpenCode"

    @property
    def binary_names(self) -> list[str]:
        return ["opencode"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".config" / "opencode"

    @property
    def api_domain(self) -> str:
        return "varies"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # OpenCode may also appear in cmdline arguments
        if cmdline:
            joined = " ".join(cmdline)
            if "opencode" in joined:
                return True
        return False

    def is_installed(self) -> bool:
        if self.config_dir.exists():
            return True
        return super().is_installed()

    # ------------------------------------------------------------------
    # Usage statistics
    # ------------------------------------------------------------------

    @property
    def data_dir(self) -> Path:
        """OpenCode data directory (XDG data home)."""
        xdg = os.environ.get("XDG_DATA_HOME")
        base = Path(xdg) if xdg else Path.home() / ".local" / "share"
        return base / "opencode"

    def parse_usage(self) -> UsageStats | None:
        """Parse usage stats from OpenCode message storage.

        Scans ``<data_dir>/storage/message/<sessionID>/*.json``. Each
        assistant message records ``tokens`` (input/output/reasoning/cache),
        ``modelID``/``providerID``, and epoch-ms timestamps in ``time``.
        """
        try:
            return self._parse_usage_inner()
        except Exception:
            return None

    def _parse_usage_inner(self) -> UsageStats | None:
        msg_root = self.data_dir / "storage" / "message"
        if not msg_root.is_dir():
            return None

        msg_files = find_recent_sessions(msg_root, "**/*.json", limit=500)
        if not msg_files:
            return None

        model_tokens: dict[str, TokenUsage] = defaultdict(TokenUsage)
        tool_counts: dict[str, int] = defaultdict(int)
        tool_last_used: dict[str, str] = {}
        daily_counts: dict[str, dict] = defaultdict(lambda: {"messages": 0, "sessions": 0, "tokens": 0, "tools": 0})
        session_ids: set[str] = set()
        total_messages = 0
        total_tool_calls = 0

        for mf in msg_files:
            try:
                msg = json.loads(mf.read_text(errors="replace"))
            except (json.JSONDecodeError, OSError):
                continue
            if not isinstance(msg, dict):
                continue

            total_messages += 1
            sid = msg.get("sessionID") or mf.parent.name
            date_key = ""
            ts_iso = ""
            created = (msg.get("time") or {}).get("created")
            if isinstance(created, (int, float)) and created > 0:
                dt = datetime.fromtimestamp(created / 1000.0, tz=timezone.utc)
                date_key = dt.strftime("%Y-%m-%d")
                ts_iso = dt.isoformat()

            if date_key:
                daily_counts[date_key]["messages"] += 1
            if sid and sid not in session_ids:
                session_ids.add(sid)
                if date_key:
                    daily_counts[date_key]["sessions"] += 1

            # Token counts on assistant messages
            tokens = msg.get("tokens")
            if isinstance(tokens, dict) and msg.get("role") == "assistant":
                model_id = msg.get("modelID", "unknown")
                provider = msg.get("providerID", "")
                key = f"{provider}/{model_id}" if provider else model_id
                usage = model_tokens[key]
                usage.input_tokens += tokens.get("input", 0)
                usage.output_tokens += tokens.get("output", 0) + tokens.get("reasoning", 0)
                cache = tokens.get("cache") or {}
                if isinstance(cache, dict):
                    usage.cache_read_input_tokens += cache.get("read", 0)
                    usage.cache_creation_input_tokens += cache.get("write", 0)
                if date_key:
                    daily_counts[date_key]["tokens"] += tokens.get("input", 0) + tokens.get("output", 0)

            # Older OpenCode versions embed tool parts inline on the message
            for part in msg.get("parts", []) or []:
                if isinstance(part, dict) and part.get("type") == "tool":
                    name = part.get("tool", "unknown")
                    tool_counts[name] += 1
                    total_tool_calls += 1
                    if ts_iso:
                        tool_last_used[name] = ts_iso
                    if date_key:
                        daily_counts[date_key]["tools"] += 1

        model_stats: dict[str, ModelStats] = {}
        total_tokens = 0
        for model_id, usage in model_tokens.items():
            model_stats[model_id] = ModelStats(model_id=model_id, usage=usage)
            total_tokens += usage.total_tokens

        tool_stats = [
            ToolCallStats(tool_name=name, call_count=count, last_used=tool_last_used.get(name))
            for name, count in tool_counts.items()
        ]

        daily_activity = [
            DailyStats(
                date=date_str,
                message_count=dc["messages"],
                session_count=dc["sessions"],
                tool_call_count=dc["tools"],
                total_tokens=dc["tokens"],
            )
            for date_str, dc in sorted(daily_counts.items())
        ]

        return UsageStats(
            model_stats=model_stats,
            tool_stats=tool_stats,
            daily_activity=daily_activity,
            total_tokens=total_tokens,
            total_messages=total_messages,
            total_sessions=len(session_ids),
            total_tool_calls=total_tool_calls,
            time_range_start=daily_activity[0].date if daily_activity else None,
            time_range_end=daily_activity[-1].date if daily_activity else None,
        )

    def parse_config(self) -> dict:
        config: dict = {}

        # OpenCode uses opencode.json as its main config
        settings = self._parse_json_config("opencode.json")
        if settings:
            config["settings"] = settings

        # Also check config.yaml via a simple existence check
        config_yaml = self.config_dir / "config.yaml"
        if config_yaml.is_file():
            config["has_config_yaml"] = True

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return OpenCodeDetector()
