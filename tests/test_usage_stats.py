"""Tests for riva.core.usage_stats and agent parse_usage methods."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from riva.agents.claude_code import ClaudeCodeDetector
from riva.agents.codex_cli import CodexCLIDetector
from riva.core.usage_stats import (
    DailyStats,
    ModelStats,
    TokenUsage,
    ToolCallStats,
    UsageStats,
)


# ---------------------------------------------------------------------------
# Dataclass unit tests
# ---------------------------------------------------------------------------


class TestTokenUsage:
    def test_empty(self):
        u = TokenUsage()
        assert u.total_tokens == 0

    def test_total(self):
        u = TokenUsage(input_tokens=100, output_tokens=50, cache_read_input_tokens=25, cache_creation_input_tokens=10)
        assert u.total_tokens == 185


class TestUsageStats:
    def test_empty_stats(self):
        s = UsageStats()
        assert s.total_tokens == 0
        assert s.top_tools == []
        assert s.daily_activity == []

    def test_top_tools_sorted(self):
        s = UsageStats(
            tool_stats=[
                ToolCallStats(tool_name="read", call_count=5),
                ToolCallStats(tool_name="write", call_count=20),
                ToolCallStats(tool_name="search", call_count=10),
            ]
        )
        top = s.top_tools
        assert top[0].tool_name == "write"
        assert top[1].tool_name == "search"
        assert top[2].tool_name == "read"


class TestDailyStats:
    def test_defaults(self):
        d = DailyStats(date="2025-01-15")
        assert d.message_count == 0
        assert d.session_count == 0
        assert d.tool_call_count == 0
        assert d.total_tokens == 0


# ---------------------------------------------------------------------------
# Claude Code parse_usage
# ---------------------------------------------------------------------------


class TestClaudeCodeParseUsage:
    def _make_detector(self, tmp_path):
        d = ClaudeCodeDetector()
        # Patch config_dir to use tmp_path
        patcher = patch.object(
            type(d), "config_dir",
            new_callable=lambda: property(lambda self: tmp_path),
        )
        patcher.start()
        return d, patcher

    def test_returns_none_for_missing_dir(self):
        d = ClaudeCodeDetector()
        with patch.object(
            type(d), "config_dir",
            new_callable=lambda: property(lambda self: Path("/tmp/riva_nonexistent_12345")),
        ):
            assert d.parse_usage() is None

    def test_stats_cache_model_tokens(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            cache = {
                "modelTokens": {
                    "claude-3-opus": {
                        "inputTokens": 1000,
                        "outputTokens": 500,
                        "cacheReadInputTokens": 200,
                        "cacheCreationInputTokens": 50,
                    }
                },
                "dailyActivity": [
                    {"date": "2025-01-10", "messageCount": 5, "sessionCount": 2, "totalTokens": 1750},
                ],
                "totalSessions": 10,
                "totalMessages": 50,
            }
            (tmp_path / "stats-cache.json").write_text(json.dumps(cache))

            result = d.parse_usage()
            assert result is not None
            assert "claude-3-opus" in result.model_stats
            ms = result.model_stats["claude-3-opus"]
            assert ms.usage.input_tokens == 1000
            assert ms.usage.output_tokens == 500
            assert ms.usage.total_tokens == 1750
            assert result.total_sessions == 10
            assert result.total_messages == 50
            assert len(result.daily_activity) == 1
            assert result.daily_activity[0].date == "2025-01-10"
            assert result.time_range_start == "2025-01-10"
            assert result.time_range_end == "2025-01-10"
        finally:
            patcher.stop()

    def test_session_jsonl_tool_use(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            # Create session JSONL with tool_use entries
            projects = tmp_path / "projects" / "proj1"
            projects.mkdir(parents=True)
            session = projects / "session.jsonl"
            lines = [
                json.dumps({"type": "tool_use", "name": "Read", "timestamp": "2025-01-10T10:00:00Z"}),
                json.dumps({"type": "tool_use", "name": "Read", "timestamp": "2025-01-10T10:05:00Z"}),
                json.dumps({"type": "tool_use", "name": "Write", "timestamp": "2025-01-10T10:10:00Z"}),
                json.dumps({"type": "assistant", "content": [
                    {"type": "tool_use", "name": "Bash"},
                    {"type": "text", "text": "hello"},
                ]}),
            ]
            session.write_text("\n".join(lines) + "\n")

            result = d.parse_usage()
            assert result is not None
            assert result.total_tool_calls == 4
            tool_names = {t.tool_name for t in result.tool_stats}
            assert "Read" in tool_names
            assert "Write" in tool_names
            assert "Bash" in tool_names
            # Read should have count 2
            read_stat = next(t for t in result.tool_stats if t.tool_name == "Read")
            assert read_stat.call_count == 2
        finally:
            patcher.stop()

    def test_combined_cache_and_sessions(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            cache = {
                "modelTokens": {"model-a": {"inputTokens": 100, "outputTokens": 50}},
                "dailyActivity": [],
            }
            (tmp_path / "stats-cache.json").write_text(json.dumps(cache))

            projects = tmp_path / "projects" / "p"
            projects.mkdir(parents=True)
            sf = projects / "s.jsonl"
            sf.write_text(json.dumps({"type": "tool_use", "name": "Grep"}) + "\n")

            result = d.parse_usage()
            assert result is not None
            assert result.total_tokens == 150  # 100 + 50
            assert result.total_tool_calls == 1
        finally:
            patcher.stop()


# ---------------------------------------------------------------------------
# Codex CLI parse_usage
# ---------------------------------------------------------------------------


class TestCodexCLIParseUsage:
    def _make_detector(self, tmp_path):
        d = CodexCLIDetector()
        patcher = patch.object(
            type(d), "config_dir",
            new_callable=lambda: property(lambda self: tmp_path),
        )
        patcher.start()
        return d, patcher

    def test_returns_none_for_missing_sessions(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            # config_dir exists but no sessions/ subdir
            assert d.parse_usage() is None
        finally:
            patcher.stop()

    def test_returns_none_for_empty_sessions(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            (tmp_path / "sessions").mkdir()
            result = d.parse_usage()
            assert result is None
        finally:
            patcher.stop()

    def test_token_count_events(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            sessions = tmp_path / "sessions" / "2025" / "01"
            sessions.mkdir(parents=True)
            sf = sessions / "session1.jsonl"
            lines = [
                json.dumps({
                    "type": "session_meta",
                    "payload": {"session_id": "abc"},
                    "timestamp": "2025-01-15T10:00:00Z",
                }),
                json.dumps({
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "model": "gpt-4",
                        "input_tokens": 200,
                        "output_tokens": 100,
                    },
                    "timestamp": "2025-01-15T10:01:00Z",
                }),
                json.dumps({
                    "type": "event_msg",
                    "payload": {
                        "type": "token_count",
                        "model": "gpt-4",
                        "input_tokens": 300,
                        "output_tokens": 150,
                    },
                    "timestamp": "2025-01-15T10:02:00Z",
                }),
            ]
            sf.write_text("\n".join(lines) + "\n")

            result = d.parse_usage()
            assert result is not None
            assert "gpt-4" in result.model_stats
            ms = result.model_stats["gpt-4"]
            assert ms.usage.input_tokens == 500
            assert ms.usage.output_tokens == 250
            assert result.total_tokens == 750
            assert result.total_sessions == 1  # one session_id
            assert result.total_messages == 2
        finally:
            patcher.stop()

    def test_function_call_events(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            sessions = tmp_path / "sessions"
            sessions.mkdir()
            sf = sessions / "s.jsonl"
            lines = [
                json.dumps({
                    "type": "response_item",
                    "payload": {"type": "function_call", "name": "shell"},
                    "timestamp": "2025-01-15T10:00:00Z",
                }),
                json.dumps({
                    "type": "response_item",
                    "payload": {"type": "function_call", "name": "shell"},
                    "timestamp": "2025-01-15T10:01:00Z",
                }),
                json.dumps({
                    "type": "response_item",
                    "payload": {"type": "function_call", "name": "file_edit"},
                    "timestamp": "2025-01-16T10:00:00Z",
                }),
            ]
            sf.write_text("\n".join(lines) + "\n")

            result = d.parse_usage()
            assert result is not None
            assert result.total_tool_calls == 3
            tool_names = {t.tool_name for t in result.tool_stats}
            assert "shell" in tool_names
            assert "file_edit" in tool_names
            shell = next(t for t in result.tool_stats if t.tool_name == "shell")
            assert shell.call_count == 2
        finally:
            patcher.stop()

    def test_daily_aggregation(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            sessions = tmp_path / "sessions"
            sessions.mkdir()
            sf = sessions / "s.jsonl"
            lines = [
                json.dumps({
                    "type": "event_msg",
                    "payload": {"type": "token_count", "model": "m", "input_tokens": 10, "output_tokens": 5},
                    "timestamp": "2025-01-15T10:00:00Z",
                }),
                json.dumps({
                    "type": "event_msg",
                    "payload": {"type": "token_count", "model": "m", "input_tokens": 20, "output_tokens": 10},
                    "timestamp": "2025-01-16T10:00:00Z",
                }),
            ]
            sf.write_text("\n".join(lines) + "\n")

            result = d.parse_usage()
            assert result is not None
            assert len(result.daily_activity) == 2
            dates = [d.date for d in result.daily_activity]
            assert "2025-01-15" in dates
            assert "2025-01-16" in dates
            assert result.time_range_start == "2025-01-15"
            assert result.time_range_end == "2025-01-16"
        finally:
            patcher.stop()
