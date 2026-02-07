"""Dataclasses for token usage and tool execution tracking."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class TokenUsage:
    """Token usage counters for a model."""

    input_tokens: int = 0
    output_tokens: int = 0
    cache_read_input_tokens: int = 0
    cache_creation_input_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.input_tokens + self.output_tokens + self.cache_read_input_tokens + self.cache_creation_input_tokens


@dataclass
class ToolCallStats:
    """Aggregated stats for a single tool/command."""

    tool_name: str
    call_count: int = 0
    last_used: str | None = None


@dataclass
class DailyStats:
    """Activity stats for a single day."""

    date: str
    message_count: int = 0
    session_count: int = 0
    tool_call_count: int = 0
    total_tokens: int = 0


@dataclass
class ModelStats:
    """Token usage breakdown for a specific model."""

    model_id: str
    usage: TokenUsage = field(default_factory=TokenUsage)


@dataclass
class UsageStats:
    """Aggregated usage statistics for an agent."""

    model_stats: dict[str, ModelStats] = field(default_factory=dict)
    tool_stats: list[ToolCallStats] = field(default_factory=list)
    daily_activity: list[DailyStats] = field(default_factory=list)
    total_tokens: int = 0
    total_messages: int = 0
    total_sessions: int = 0
    total_tool_calls: int = 0
    time_range_start: str | None = None
    time_range_end: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def top_tools(self) -> list[ToolCallStats]:
        """Return tool stats sorted by call count descending."""
        return sorted(self.tool_stats, key=lambda t: t.call_count, reverse=True)
