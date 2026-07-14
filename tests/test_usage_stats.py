"""Tests for riva.core.usage_stats and agent parse_usage methods."""

import json
from pathlib import Path
from unittest.mock import patch

from riva.agents.claude_code import ClaudeCodeDetector
from riva.agents.cline import ClineDetector
from riva.agents.codex_cli import CodexCLIDetector
from riva.agents.gemini_cli import GeminiCLIDetector
from riva.agents.opencode import OpenCodeDetector
from riva.core.usage_stats import (
    DailyStats,
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
            type(d),
            "config_dir",
            new_callable=lambda: property(lambda self: tmp_path),
        )
        patcher.start()
        return d, patcher

    def test_returns_none_for_missing_dir(self):
        d = ClaudeCodeDetector()
        with patch.object(
            type(d),
            "config_dir",
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
                json.dumps(
                    {
                        "type": "assistant",
                        "content": [
                            {"type": "tool_use", "name": "Bash"},
                            {"type": "text", "text": "hello"},
                        ],
                    }
                ),
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

    def test_stats_cache_current_schema(self, tmp_path):
        """Current Claude Code writes modelUsage + dailyModelTokens instead of modelTokens."""
        d, patcher = self._make_detector(tmp_path)
        try:
            cache = {
                "version": 1,
                "modelUsage": {
                    "claude-opus-4-6": {
                        "inputTokens": 3000,
                        "outputTokens": 1500,
                        "cacheReadInputTokens": 400,
                        "cacheCreationInputTokens": 100,
                    }
                },
                "dailyModelTokens": [
                    {"date": "2026-01-13", "tokensByModel": {"claude-opus-4-6": 5000}},
                ],
                "dailyActivity": [
                    {"date": "2026-01-13", "messageCount": 10, "sessionCount": 2, "toolCallCount": 7},
                ],
                "totalSessions": 2,
                "totalMessages": 10,
            }
            (tmp_path / "stats-cache.json").write_text(json.dumps(cache))

            result = d.parse_usage()
            assert result is not None
            ms = result.model_stats["claude-opus-4-6"]
            assert ms.usage.input_tokens == 3000
            assert ms.usage.total_tokens == 5000
            assert result.total_tokens == 5000
            day = result.daily_activity[0]
            assert day.total_tokens == 5000  # from dailyModelTokens
            assert day.tool_call_count == 7  # preserved from cache
        finally:
            patcher.stop()


# ---------------------------------------------------------------------------
# Codex CLI parse_usage
# ---------------------------------------------------------------------------


class TestCodexCLIParseUsage:
    def _make_detector(self, tmp_path):
        d = CodexCLIDetector()
        patcher = patch.object(
            type(d),
            "config_dir",
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
                json.dumps(
                    {
                        "type": "session_meta",
                        "payload": {"session_id": "abc"},
                        "timestamp": "2025-01-15T10:00:00Z",
                    }
                ),
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "token_count",
                            "model": "gpt-4",
                            "input_tokens": 200,
                            "output_tokens": 100,
                        },
                        "timestamp": "2025-01-15T10:01:00Z",
                    }
                ),
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {
                            "type": "token_count",
                            "model": "gpt-4",
                            "input_tokens": 300,
                            "output_tokens": 150,
                        },
                        "timestamp": "2025-01-15T10:02:00Z",
                    }
                ),
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
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {"type": "function_call", "name": "shell"},
                        "timestamp": "2025-01-15T10:00:00Z",
                    }
                ),
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {"type": "function_call", "name": "shell"},
                        "timestamp": "2025-01-15T10:01:00Z",
                    }
                ),
                json.dumps(
                    {
                        "type": "response_item",
                        "payload": {"type": "function_call", "name": "file_edit"},
                        "timestamp": "2025-01-16T10:00:00Z",
                    }
                ),
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
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {"type": "token_count", "model": "m", "input_tokens": 10, "output_tokens": 5},
                        "timestamp": "2025-01-15T10:00:00Z",
                    }
                ),
                json.dumps(
                    {
                        "type": "event_msg",
                        "payload": {"type": "token_count", "model": "m", "input_tokens": 20, "output_tokens": 10},
                        "timestamp": "2025-01-16T10:00:00Z",
                    }
                ),
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


class TestCodexCurrentSchema:
    def _make_detector(self, tmp_path):
        d = CodexCLIDetector()
        patcher = patch.object(
            type(d),
            "config_dir",
            new_callable=lambda: property(lambda self: tmp_path),
        )
        patcher.start()
        return d, patcher

    def test_session_meta_id_and_nested_token_info(self, tmp_path):
        """Current Codex uses payload "id" and nests tokens in info.last_token_usage."""
        d, patcher = self._make_detector(tmp_path)
        try:
            sessions = tmp_path / "sessions"
            sessions.mkdir()
            sf = sessions / "rollout-1.jsonl"
            lines = [
                json.dumps(
                    {
                        "timestamp": "2026-06-15T19:53:33.296Z",
                        "type": "session_meta",
                        "payload": {"id": "sess-abc", "cli_version": "0.34.0"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-06-15T19:53:34.000Z",
                        "type": "turn_context",
                        "payload": {"model": "gpt-5-codex"},
                    }
                ),
                json.dumps(
                    {
                        "timestamp": "2026-06-15T19:54:00.000Z",
                        "type": "event_msg",
                        "payload": {
                            "type": "token_count",
                            "info": {
                                "total_token_usage": {"input_tokens": 999999, "output_tokens": 999999},
                                "last_token_usage": {
                                    "input_tokens": 400,
                                    "cached_input_tokens": 100,
                                    "output_tokens": 50,
                                    "reasoning_output_tokens": 25,
                                },
                            },
                        },
                    }
                ),
            ]
            sf.write_text("\n".join(lines) + "\n")

            result = d.parse_usage()
            assert result is not None
            assert result.total_sessions == 1
            ms = result.model_stats["gpt-5-codex"]
            assert ms.usage.input_tokens == 400
            assert ms.usage.output_tokens == 75  # output + reasoning
            assert ms.usage.cache_read_input_tokens == 100
            # cumulative total_token_usage must NOT be summed
            assert result.total_tokens == 575
        finally:
            patcher.stop()


# ---------------------------------------------------------------------------
# Gemini CLI parse_usage
# ---------------------------------------------------------------------------


class TestGeminiCLIParseUsage:
    def _make_detector(self, tmp_path):
        d = GeminiCLIDetector()
        patcher = patch.object(
            type(d),
            "config_dir",
            new_callable=lambda: property(lambda self: tmp_path),
        )
        patcher.start()
        return d, patcher

    def test_returns_none_for_missing_dir(self):
        d = GeminiCLIDetector()
        with patch.object(
            type(d),
            "config_dir",
            new_callable=lambda: property(lambda self: Path("/tmp/riva_nonexistent_12345")),
        ):
            assert d.parse_usage() is None

    def test_returns_none_when_no_data(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            (tmp_path / "tmp" / "hash1").mkdir(parents=True)
            assert d.parse_usage() is None
        finally:
            patcher.stop()

    def test_logs_json_messages_and_sessions(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            proj = tmp_path / "tmp" / "hash1"
            proj.mkdir(parents=True)
            logs = [
                {"sessionId": "s1", "messageId": 0, "type": "user", "timestamp": "2025-02-01T10:00:00.000Z"},
                {"sessionId": "s1", "messageId": 1, "type": "user", "timestamp": "2025-02-01T10:05:00.000Z"},
                {"sessionId": "s2", "messageId": 0, "type": "user", "timestamp": "2025-02-02T09:00:00.000Z"},
            ]
            (proj / "logs.json").write_text(json.dumps(logs))

            result = d.parse_usage()
            assert result is not None
            assert result.total_messages == 3
            assert result.total_sessions == 2
            assert result.time_range_start == "2025-02-01"
            assert result.time_range_end == "2025-02-02"
        finally:
            patcher.stop()

    def test_chat_session_tokens_and_tools(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            chats = tmp_path / "tmp" / "hash1" / "chats"
            chats.mkdir(parents=True)
            session = {
                "sessionId": "s1",
                "messages": [
                    {
                        "type": "gemini",
                        "model": "gemini-2.5-pro",
                        "timestamp": "2025-02-01T10:00:00.000Z",
                        "tokens": {"input": 100, "output": 50, "cached": 25, "thoughts": 10},
                        "parts": [{"functionCall": {"name": "run_shell_command"}}],
                    },
                ],
            }
            (chats / "session-1.json").write_text(json.dumps(session))

            result = d.parse_usage()
            assert result is not None
            ms = result.model_stats["gemini-2.5-pro"]
            assert ms.usage.input_tokens == 100
            assert ms.usage.output_tokens == 60  # output + thoughts
            assert ms.usage.cache_read_input_tokens == 25
            assert result.total_tool_calls == 1
            assert result.tool_stats[0].tool_name == "run_shell_command"
            assert result.total_sessions == 1
        finally:
            patcher.stop()

    def test_checkpoint_list_format(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            chats = tmp_path / "tmp" / "hash1" / "chats"
            chats.mkdir(parents=True)
            checkpoint = [
                {"role": "user", "parts": [{"text": "hi"}]},
                {"role": "model", "parts": [{"functionCall": {"name": "read_file"}}]},
            ]
            (chats / "checkpoint-x.json").write_text(json.dumps(checkpoint))

            result = d.parse_usage()
            assert result is not None
            assert result.total_tool_calls == 1
            assert result.tool_stats[0].tool_name == "read_file"
        finally:
            patcher.stop()


# ---------------------------------------------------------------------------
# OpenCode parse_usage
# ---------------------------------------------------------------------------


class TestOpenCodeParseUsage:
    def _make_detector(self, tmp_path):
        d = OpenCodeDetector()
        patcher = patch.object(
            type(d),
            "data_dir",
            new_callable=lambda: property(lambda self: tmp_path),
        )
        patcher.start()
        return d, patcher

    def test_returns_none_for_missing_dir(self):
        d = OpenCodeDetector()
        with patch.object(
            type(d),
            "data_dir",
            new_callable=lambda: property(lambda self: Path("/tmp/riva_nonexistent_12345")),
        ):
            assert d.parse_usage() is None

    def test_assistant_message_tokens(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            msg_dir = tmp_path / "storage" / "message" / "ses_1"
            msg_dir.mkdir(parents=True)
            msg = {
                "id": "msg_1",
                "role": "assistant",
                "sessionID": "ses_1",
                "modelID": "claude-sonnet-4-5",
                "providerID": "anthropic",
                "time": {"created": 1738404000000},  # 2025-02-01 UTC
                "tokens": {"input": 200, "output": 80, "reasoning": 20, "cache": {"read": 40, "write": 10}},
            }
            (msg_dir / "msg_1.json").write_text(json.dumps(msg))
            user_msg = {
                "id": "msg_0",
                "role": "user",
                "sessionID": "ses_1",
                "time": {"created": 1738403990000},
            }
            (msg_dir / "msg_0.json").write_text(json.dumps(user_msg))

            result = d.parse_usage()
            assert result is not None
            ms = result.model_stats["anthropic/claude-sonnet-4-5"]
            assert ms.usage.input_tokens == 200
            assert ms.usage.output_tokens == 100  # output + reasoning
            assert ms.usage.cache_read_input_tokens == 40
            assert ms.usage.cache_creation_input_tokens == 10
            assert result.total_messages == 2
            assert result.total_sessions == 1
            assert result.time_range_end == "2025-02-01"
        finally:
            patcher.stop()

    def test_inline_tool_parts(self, tmp_path):
        d, patcher = self._make_detector(tmp_path)
        try:
            msg_dir = tmp_path / "storage" / "message" / "ses_1"
            msg_dir.mkdir(parents=True)
            msg = {
                "role": "assistant",
                "sessionID": "ses_1",
                "time": {"created": 1738404000000},
                "parts": [{"type": "tool", "tool": "bash"}, {"type": "text", "text": "done"}],
            }
            (msg_dir / "msg_1.json").write_text(json.dumps(msg))

            result = d.parse_usage()
            assert result is not None
            assert result.total_tool_calls == 1
            assert result.tool_stats[0].tool_name == "bash"
        finally:
            patcher.stop()


# ---------------------------------------------------------------------------
# Cline parse_usage
# ---------------------------------------------------------------------------


class TestClineParseUsage:
    def test_returns_none_when_no_tasks(self):
        d = ClineDetector()
        with patch.object(ClineDetector, "_tasks_dirs", return_value=[]):
            assert d.parse_usage() is None

    def test_api_req_tokens_and_tools(self, tmp_path):
        task = tmp_path / "tasks" / "1738404000000"
        task.mkdir(parents=True)
        ui_messages = [
            {
                "ts": 1738404000000,  # 2025-02-01 UTC
                "type": "say",
                "say": "api_req_started",
                "text": json.dumps({"tokensIn": 500, "tokensOut": 120, "cacheWrites": 30, "cacheReads": 60}),
            },
            {
                "ts": 1738404060000,
                "type": "say",
                "say": "tool",
                "text": json.dumps({"tool": "readFile", "path": "x.py"}),
            },
        ]
        (task / "ui_messages.json").write_text(json.dumps(ui_messages))
        (task / "task_metadata.json").write_text(
            json.dumps({"model_usage": [{"ts": 1738404000000, "model_id": "claude-sonnet-4-5"}]})
        )

        d = ClineDetector()
        with patch.object(ClineDetector, "_tasks_dirs", return_value=[tmp_path / "tasks"]):
            result = d.parse_usage()

        assert result is not None
        ms = result.model_stats["claude-sonnet-4-5"]
        assert ms.usage.input_tokens == 500
        assert ms.usage.output_tokens == 120
        assert ms.usage.cache_creation_input_tokens == 30
        assert ms.usage.cache_read_input_tokens == 60
        assert result.total_sessions == 1
        assert result.total_messages == 1
        assert result.total_tool_calls == 1
        assert result.tool_stats[0].tool_name == "readFile"
        assert result.time_range_end == "2025-02-01"

    def test_unknown_model_without_metadata(self, tmp_path):
        task = tmp_path / "tasks" / "t1"
        task.mkdir(parents=True)
        ui_messages = [
            {
                "ts": 1738404000000,
                "type": "say",
                "say": "api_req_started",
                "text": json.dumps({"tokensIn": 10, "tokensOut": 5}),
            },
        ]
        (task / "ui_messages.json").write_text(json.dumps(ui_messages))

        d = ClineDetector()
        with patch.object(ClineDetector, "_tasks_dirs", return_value=[tmp_path / "tasks"]):
            result = d.parse_usage()

        assert result is not None
        assert "unknown" in result.model_stats
        assert result.total_tokens == 15


# ---------------------------------------------------------------------------
# supports_usage
# ---------------------------------------------------------------------------


class TestSupportsUsage:
    def test_implementers_report_true(self):
        assert ClaudeCodeDetector().supports_usage is True
        assert CodexCLIDetector().supports_usage is True
        assert GeminiCLIDetector().supports_usage is True
        assert OpenCodeDetector().supports_usage is True
        assert ClineDetector().supports_usage is True

    def test_base_default_reports_false(self):
        from riva.agents.base import SimpleAgentDetector

        d = SimpleAgentDetector(name="X", binaries=["x"], config="~/.x", api="api.x.dev")
        assert d.supports_usage is False
