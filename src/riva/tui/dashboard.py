"""Rich Live TUI dashboard."""

from __future__ import annotations

from rich.columns import Columns
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.text import Text

from riva.agents.base import AgentStatus
from riva.core.env_scanner import scan_env_vars
from riva.core.monitor import ResourceMonitor
from riva.tui.components import (
    build_agent_card,
    build_agent_table,
    build_env_table,
    build_network_table,
    build_security_panel,
)
from riva.utils.formatting import format_number


def _build_header() -> Panel:
    """Build the dashboard header."""
    header_text = Text("RIVA", style="bold bright_cyan")
    header_text.append(" — AI Agent Task Manager", style="dim white")
    return Panel(header_text, border_style="bright_blue", padding=(0, 1))


def _build_usage_summary(monitor: ResourceMonitor) -> Panel:
    """Build a compact usage summary panel from pre-parsed stats.

    This reads only the ``usage_stats`` attribute already attached to
    instances — it never triggers JSONL parsing in the live loop.
    """
    instances = monitor.instances
    parts: list[str] = []

    for inst in instances:
        stats = inst.usage_stats
        if stats is None:
            continue
        tokens = format_number(stats.total_tokens)
        sessions = format_number(stats.total_sessions)
        tools = format_number(stats.total_tool_calls)
        parts.append(
            f"[bold]{inst.name}[/bold]: {tokens} tokens · {sessions} sessions · {tools} tool calls"
        )

    if not parts:
        content = "[dim]No usage data available. Run [bold]riva stats[/bold] for full breakdown.[/dim]"
    else:
        content = "  |  ".join(parts)

    return Panel(
        content,
        title="Usage Summary",
        title_align="left",
        border_style="cyan",
        padding=(0, 1),
    )


def _build_layout(monitor: ResourceMonitor) -> Layout:
    """Build the full dashboard layout."""
    instances = monitor.instances
    histories = monitor.histories

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )

    layout["header"].update(_build_header())

    # Body: agent table + detail cards + network + security + usage + env
    body = Layout()
    body.split_column(
        Layout(name="table", size=len(instances) + 6),
        Layout(name="details"),
        Layout(name="network", size=8),
        Layout(name="security", size=6),
        Layout(name="usage", size=3),
        Layout(name="env", size=10),
    )

    body["table"].update(build_agent_table(instances))

    # Detail cards for running agents
    running = [i for i in instances if i.status == AgentStatus.RUNNING]
    if running:
        cards = []
        for inst in running:
            key = f"{inst.name}:{inst.pid}" if inst.pid else inst.name
            history = histories.get(key)
            cards.append(build_agent_card(inst, history))
        body["details"].update(
            Columns(cards, equal=True, expand=True)
            if len(cards) > 1
            else cards[0]
        )
    else:
        body["details"].update(
            Panel(
                "[dim]No running agents. Start an AI coding agent to see live metrics.[/dim]",
                title="Agent Details",
                border_style="dim",
            )
        )

    # Network connections panel
    body["network"].update(build_network_table(instances))

    # Security panel
    body["security"].update(build_security_panel())

    body["usage"].update(_build_usage_summary(monitor))

    env_vars = scan_env_vars()
    body["env"].update(build_env_table(env_vars))

    layout["body"].update(body)
    layout["footer"].update(
        Panel(
            "[dim]Press [bold]Ctrl+C[/bold] to exit  •  Polling every 2s[/dim]",
            border_style="dim",
        )
    )

    return layout


def run_dashboard(monitor: ResourceMonitor | None = None) -> None:
    """Run the live TUI dashboard."""
    if monitor is None:
        monitor = ResourceMonitor()

    console = Console()
    monitor.start()

    try:
        with Live(
            _build_layout(monitor),
            console=console,
            refresh_per_second=1,
            screen=True,
        ) as live:
            while True:
                live.update(_build_layout(monitor))
                import time

                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        monitor.stop()
