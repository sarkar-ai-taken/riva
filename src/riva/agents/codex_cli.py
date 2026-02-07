"""Codex CLI (OpenAI) agent detector."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from riva.agents.base import AgentDetector
from riva.core.usage_stats import (
    DailyStats,
    ModelStats,
    TokenUsage,
    ToolCallStats,
    UsageStats,
)
from riva.utils.jsonl import find_recent_sessions, stream_jsonl


class CodexCLIDetector(AgentDetector):
    """Detect and parse OpenAI Codex CLI."""

    @property
    def agent_name(self) -> str:
        return "Codex CLI"

    @property
    def binary_names(self) -> list[str]:
        return ["codex"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".codex"

    @property
    def api_domain(self) -> str:
        return "api.openai.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        return self._match_by_name(name, cmdline, exe)

    # ------------------------------------------------------------------
    # Usage statistics
    # ------------------------------------------------------------------

    def parse_usage(self) -> UsageStats | None:
        """Parse usage stats from Codex CLI session files.

        Scans ``~/.codex/sessions/**/*.jsonl`` for:
        - ``event_msg`` with ``payload.type="token_count"`` → tokens
        - ``response_item`` with ``payload.type="function_call"`` → tools
        - ``session_meta`` → session IDs
        """
        try:
            return self._parse_usage_inner()
        except Exception:
            return None

    def _parse_usage_inner(self) -> UsageStats | None:
        sessions_dir = self.config_dir / "sessions"
        if not sessions_dir.is_dir():
            return None

        session_files = find_recent_sessions(sessions_dir, "**/*.jsonl", limit=30)
        if not session_files:
            return None

        model_tokens: dict[str, TokenUsage] = defaultdict(TokenUsage)
        tool_counts: dict[str, int] = defaultdict(int)
        tool_last_used: dict[str, str] = {}
        daily_counts: dict[str, dict] = defaultdict(lambda: {"messages": 0, "sessions": 0, "tokens": 0, "tools": 0})
        session_ids: set[str] = set()
        total_messages = 0
        total_tool_calls = 0

        for sf in session_files:
            for record in stream_jsonl(sf, max_lines=2000):
                event_type = record.get("type", "")
                payload = record.get("payload", {})
                ts = record.get("timestamp", "")
                date_key = ts[:10] if len(ts) >= 10 else ""

                # Session metadata
                if event_type == "session_meta":
                    sid = payload.get("session_id", "")
                    if sid:
                        session_ids.add(sid)
                    if date_key:
                        daily_counts[date_key]["sessions"] += 1

                # Token counts
                if event_type == "event_msg" and payload.get("type") == "token_count":
                    model = payload.get("model", "unknown")
                    usage = model_tokens[model]
                    usage.input_tokens += payload.get("input_tokens", 0)
                    usage.output_tokens += payload.get("output_tokens", 0)
                    usage.cache_read_input_tokens += payload.get("cache_read_input_tokens", 0)
                    usage.cache_creation_input_tokens += payload.get("cache_creation_input_tokens", 0)
                    total_messages += 1
                    if date_key:
                        daily_counts[date_key]["messages"] += 1
                        daily_counts[date_key]["tokens"] += payload.get("input_tokens", 0) + payload.get(
                            "output_tokens", 0
                        )

                # Function calls (tools)
                if event_type == "response_item" and payload.get("type") == "function_call":
                    name = payload.get("name", "unknown")
                    tool_counts[name] += 1
                    total_tool_calls += 1
                    if ts:
                        tool_last_used[name] = ts
                    if date_key:
                        daily_counts[date_key]["tools"] += 1

        # Build model stats
        model_stats: dict[str, ModelStats] = {}
        total_tokens = 0
        for model_id, usage in model_tokens.items():
            model_stats[model_id] = ModelStats(model_id=model_id, usage=usage)
            total_tokens += usage.total_tokens

        # Build tool stats
        tool_stats = [
            ToolCallStats(
                tool_name=name,
                call_count=count,
                last_used=tool_last_used.get(name),
            )
            for name, count in tool_counts.items()
        ]

        # Build daily activity
        daily_activity = []
        for date_str in sorted(daily_counts):
            dc = daily_counts[date_str]
            daily_activity.append(
                DailyStats(
                    date=date_str,
                    message_count=dc["messages"],
                    session_count=dc["sessions"],
                    tool_call_count=dc["tools"],
                    total_tokens=dc["tokens"],
                )
            )

        time_start = daily_activity[0].date if daily_activity else None
        time_end = daily_activity[-1].date if daily_activity else None

        return UsageStats(
            model_stats=model_stats,
            tool_stats=tool_stats,
            daily_activity=daily_activity,
            total_tokens=total_tokens,
            total_messages=total_messages,
            total_sessions=len(session_ids),
            total_tool_calls=total_tool_calls,
            time_range_start=time_start,
            time_range_end=time_end,
        )

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def parse_config(self) -> dict:
        config: dict = {}
        settings = self._parse_toml_config("config.toml")
        if settings:
            config["settings"] = settings

        # Check for instructions file
        instructions = self.config_dir / "instructions.md"
        try:
            if instructions.exists():
                content = instructions.read_text()
                config["instructions_length"] = len(content)
                config["instructions_preview"] = content[:200]
        except OSError:
            pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return CodexCLIDetector()
