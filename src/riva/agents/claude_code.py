"""Claude Code agent detector."""

from __future__ import annotations

import json
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


class ClaudeCodeDetector(AgentDetector):
    """Detect and parse Claude Code (Anthropic CLI)."""

    @property
    def agent_name(self) -> str:
        return "Claude Code"

    @property
    def binary_names(self) -> list[str]:
        return ["claude"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".claude"

    @property
    def api_domain(self) -> str:
        return "api.anthropic.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        return self._match_by_name(name, cmdline, exe)

    # ------------------------------------------------------------------
    # Usage statistics
    # ------------------------------------------------------------------

    def parse_usage(self) -> UsageStats | None:
        """Parse usage stats from Claude Code data files.

        1. ``stats-cache.json`` — precomputed daily aggregates.
        2. Recent session JSONL files — tool call breakdown.
        """
        try:
            return self._parse_usage_inner()
        except Exception:
            return None

    def _parse_usage_inner(self) -> UsageStats | None:
        config = self.config_dir
        if not config.is_dir():
            return None

        model_stats: dict[str, ModelStats] = {}
        daily_activity: list[DailyStats] = []
        total_tokens = 0
        total_messages = 0
        total_sessions = 0
        time_start: str | None = None
        time_end: str | None = None

        # --- 1. stats-cache.json -------------------------------------------
        stats_cache = config / "stats-cache.json"
        if stats_cache.is_file():
            try:
                data = json.loads(stats_cache.read_text())
            except (json.JSONDecodeError, OSError):
                data = {}

            # Model token aggregates
            for model_id, info in data.get("modelTokens", {}).items():
                usage = TokenUsage(
                    input_tokens=info.get("inputTokens", 0),
                    output_tokens=info.get("outputTokens", 0),
                    cache_read_input_tokens=info.get("cacheReadInputTokens", 0),
                    cache_creation_input_tokens=info.get("cacheCreationInputTokens", 0),
                )
                model_stats[model_id] = ModelStats(model_id=model_id, usage=usage)
                total_tokens += usage.total_tokens

            # Daily activity
            for entry in data.get("dailyActivity", []):
                ds = DailyStats(
                    date=entry.get("date", ""),
                    message_count=entry.get("messageCount", 0),
                    session_count=entry.get("sessionCount", 0),
                    total_tokens=entry.get("totalTokens", 0),
                )
                daily_activity.append(ds)
                total_messages += ds.message_count
                total_sessions += ds.session_count

            if daily_activity:
                dates = [d.date for d in daily_activity if d.date]
                if dates:
                    time_start = min(dates)
                    time_end = max(dates)

            # Totals from cache (may override sum)
            total_sessions = data.get("totalSessions", total_sessions)
            total_messages = data.get("totalMessages", total_messages)

        # --- 2. Session JSONL files — tool call breakdown ------------------
        tool_counts: dict[str, int] = defaultdict(int)
        tool_last_used: dict[str, str] = {}
        total_tool_calls = 0

        projects_dir = config / "projects"
        if projects_dir.is_dir():
            session_files = find_recent_sessions(projects_dir, "**/*.jsonl", limit=20)
            for sf in session_files:
                for record in stream_jsonl(sf, max_lines=1000):
                    # tool_use entries have type "tool_use" or contain tool_use content
                    if record.get("type") == "tool_use":
                        name = record.get("name", "unknown")
                        tool_counts[name] += 1
                        total_tool_calls += 1
                        ts = record.get("timestamp", "")
                        if ts:
                            tool_last_used[name] = ts

                    # Also check nested content blocks for tool_use
                    for block in record.get("content", []):
                        if isinstance(block, dict) and block.get("type") == "tool_use":
                            name = block.get("name", "unknown")
                            tool_counts[name] += 1
                            total_tool_calls += 1

        # Update daily activity with tool counts
        for ds in daily_activity:
            ds.tool_call_count = 0  # We don't have per-day tool breakdown from cache

        tool_stats = [
            ToolCallStats(
                tool_name=name,
                call_count=count,
                last_used=tool_last_used.get(name),
            )
            for name, count in tool_counts.items()
        ]

        return UsageStats(
            model_stats=model_stats,
            tool_stats=tool_stats,
            daily_activity=daily_activity,
            total_tokens=total_tokens,
            total_messages=total_messages,
            total_sessions=total_sessions,
            total_tool_calls=total_tool_calls,
            time_range_start=time_start,
            time_range_end=time_end,
        )

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def parse_config(self) -> dict:
        config: dict = {}
        settings = self._parse_json_config("settings.json")
        if settings:
            config["settings"] = settings

        # Check for projects
        projects_dir = self.config_dir / "projects"
        try:
            if projects_dir.exists():
                projects = [p.name for p in projects_dir.iterdir() if p.is_dir()]
                config["projects_count"] = len(projects)
        except OSError:
            pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return ClaudeCodeDetector()
