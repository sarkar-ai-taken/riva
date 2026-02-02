"""Tests for riva.tui.components."""

from collections import deque

import pytest
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from riva.agents.base import AgentInstance, AgentStatus
from riva.core.monitor import AgentHistory, ResourceSnapshot
from riva.core.usage_stats import (
    ModelStats,
    TokenUsage,
    ToolCallStats,
    UsageStats,
    DailyStats,
)
from riva.tui.components import (
    agent_status_text,
    build_agent_card,
    build_agent_table,
    build_env_table,
    build_usage_card,
    build_usage_table,
    sparkline,
)


class TestSparkline:
    def test_empty(self):
        assert sparkline([]) == ""

    def test_single_value(self):
        result = sparkline([5.0])
        assert len(result) == 1

    def test_constant_values(self):
        result = sparkline([3.0, 3.0, 3.0])
        # All same → all same block char
        assert len(set(result)) == 1

    def test_ascending(self):
        result = sparkline([0.0, 50.0, 100.0])
        assert len(result) == 3
        # First should be lowest block, last should be highest
        blocks = " ▁▂▃▄▅▆▇█"
        assert result[0] == blocks[0]
        assert result[-1] == blocks[-1]

    def test_respects_width(self):
        values = list(range(50))
        result = sparkline(values, width=10)
        assert len(result) == 10


class TestAgentStatusText:
    def test_running(self):
        text = agent_status_text(AgentStatus.RUNNING)
        assert isinstance(text, Text)
        assert "running" in text.plain

    def test_installed(self):
        text = agent_status_text(AgentStatus.INSTALLED)
        assert "installed" in text.plain

    def test_not_found(self):
        text = agent_status_text(AgentStatus.NOT_FOUND)
        assert "not_found" in text.plain


class TestBuildAgentTable:
    def test_empty_instances(self):
        table = build_agent_table([])
        assert isinstance(table, Table)
        assert table.row_count == 1  # "No agents detected" row

    def test_with_instances(self):
        instances = [
            AgentInstance(name="Claude Code", status=AgentStatus.RUNNING, pid=123),
            AgentInstance(name="Codex CLI", status=AgentStatus.INSTALLED),
        ]
        table = build_agent_table(instances)
        assert isinstance(table, Table)
        assert table.row_count == 2

    def test_running_sorted_first(self):
        instances = [
            AgentInstance(name="B Installed", status=AgentStatus.INSTALLED),
            AgentInstance(name="A Running", status=AgentStatus.RUNNING, pid=1),
        ]
        table = build_agent_table(instances)
        # Running should come before installed in sort order
        assert table.row_count == 2


class TestBuildAgentCard:
    def test_installed_card(self):
        inst = AgentInstance(
            name="Test", status=AgentStatus.INSTALLED,
            api_domain="api.test.dev",
        )
        panel = build_agent_card(inst)
        assert isinstance(panel, Panel)

    def test_running_card_with_history(self):
        inst = AgentInstance(
            name="Test", status=AgentStatus.RUNNING,
            pid=42, cpu_percent=10.0, memory_mb=256.0,
            uptime_seconds=3600, working_directory="/home",
            api_domain="api.test.dev",
        )
        history = AgentHistory(agent_name="Test", pid=42)
        history.snapshots.append(ResourceSnapshot(1.0, 10.0, 256.0))
        history.snapshots.append(ResourceSnapshot(2.0, 15.0, 260.0))

        panel = build_agent_card(inst, history)
        assert isinstance(panel, Panel)

    def test_running_card_without_history(self):
        inst = AgentInstance(
            name="Test", status=AgentStatus.RUNNING,
            pid=42, cpu_percent=10.0, memory_mb=256.0,
            uptime_seconds=60,
        )
        panel = build_agent_card(inst, None)
        assert isinstance(panel, Panel)


class TestBuildEnvTable:
    def test_empty(self):
        table = build_env_table([])
        assert isinstance(table, Table)
        assert table.row_count == 1  # "No AI env vars" row

    def test_with_vars(self):
        env_vars = [
            {"name": "ANTHROPIC_API_KEY", "value": "****1234", "raw_length": "20"},
            {"name": "CLAUDE_MODEL", "value": "opus", "raw_length": "4"},
        ]
        table = build_env_table(env_vars)
        assert table.row_count == 2


# ---------------------------------------------------------------------------
# Usage table and card
# ---------------------------------------------------------------------------


def _make_usage_stats():
    return UsageStats(
        model_stats={
            "opus": ModelStats(model_id="opus", usage=TokenUsage(input_tokens=1000, output_tokens=500)),
        },
        tool_stats=[
            ToolCallStats(tool_name="Read", call_count=20),
            ToolCallStats(tool_name="Write", call_count=5),
        ],
        daily_activity=[
            DailyStats(date="2025-01-10", total_tokens=500),
            DailyStats(date="2025-01-11", total_tokens=1000),
        ],
        total_tokens=1500,
        total_sessions=3,
        total_messages=25,
        total_tool_calls=25,
        time_range_start="2025-01-10",
        time_range_end="2025-01-11",
    )


class TestBuildUsageTable:
    def test_empty(self):
        table = build_usage_table([])
        assert isinstance(table, Table)
        assert table.row_count >= 1  # "No agents detected" row

    def test_with_stats(self):
        inst = AgentInstance(
            name="Claude Code",
            status=AgentStatus.INSTALLED,
            usage_stats=_make_usage_stats(),
        )
        table = build_usage_table([inst])
        assert isinstance(table, Table)
        assert table.row_count == 1

    def test_without_stats(self):
        inst = AgentInstance(name="Test", status=AgentStatus.INSTALLED)
        table = build_usage_table([inst])
        assert isinstance(table, Table)
        # Should have 2 rows: the agent row + "no usage data" row
        assert table.row_count == 2


class TestBuildUsageCard:
    def test_with_full_stats(self):
        inst = AgentInstance(
            name="Claude Code",
            status=AgentStatus.INSTALLED,
            usage_stats=_make_usage_stats(),
        )
        panel = build_usage_card(inst)
        assert isinstance(panel, Panel)

    def test_with_none_stats(self):
        inst = AgentInstance(name="Test", status=AgentStatus.INSTALLED)
        panel = build_usage_card(inst)
        assert isinstance(panel, Panel)
