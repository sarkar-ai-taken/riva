"""Reusable Rich renderables for the TUI dashboard."""

from __future__ import annotations

from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from riva.agents.base import AgentInstance, AgentStatus
from riva.core.monitor import AgentHistory
from riva.utils.formatting import format_mb, format_number, format_uptime


# Status colors and icons
STATUS_STYLES = {
    AgentStatus.RUNNING: ("bold green", "●"),
    AgentStatus.INSTALLED: ("bold yellow", "○"),
    AgentStatus.NOT_FOUND: ("dim", "✗"),
}


def sparkline(values: list[float], width: int = 20) -> str:
    """Render a minimal sparkline from a list of values."""
    if not values:
        return ""
    blocks = " ▁▂▃▄▅▆▇█"
    mn = min(values)
    mx = max(values)
    rng = mx - mn if mx != mn else 1.0

    # Take last `width` values
    recent = values[-width:]
    chars = []
    for v in recent:
        idx = int((v - mn) / rng * (len(blocks) - 1))
        chars.append(blocks[idx])
    return "".join(chars)


def agent_status_text(status: AgentStatus) -> Text:
    """Render a styled status indicator."""
    style, icon = STATUS_STYLES.get(status, ("dim", "?"))
    return Text(f"{icon} {status.value}", style=style)


def build_agent_table(instances: list[AgentInstance]) -> Table:
    """Build the main agent overview table."""
    table = Table(
        title="AI Agents",
        expand=True,
        title_style="bold cyan",
        border_style="bright_blue",
    )
    table.add_column("Agent", style="bold white", min_width=14)
    table.add_column("Status", min_width=10)
    table.add_column("PID", justify="right", min_width=7)
    table.add_column("CPU %", justify="right", min_width=7)
    table.add_column("Memory", justify="right", min_width=10)
    table.add_column("Uptime", min_width=10)
    table.add_column("Working Dir", max_width=40, no_wrap=True)

    for inst in sorted(instances, key=lambda i: (i.status != AgentStatus.RUNNING, i.name)):
        style, icon = STATUS_STYLES.get(inst.status, ("dim", "?"))
        status_text = Text(f"{icon} {inst.status.value}", style=style)
        pid_str = str(inst.pid) if inst.pid else "-"
        cpu_str = f"{inst.cpu_percent:.1f}" if inst.status == AgentStatus.RUNNING else "-"
        mem_str = format_mb(inst.memory_mb) if inst.status == AgentStatus.RUNNING else "-"
        uptime_str = format_uptime(inst.uptime_seconds) if inst.status == AgentStatus.RUNNING else "-"
        cwd = inst.working_directory or "-"
        # Truncate long paths
        if len(cwd) > 40:
            cwd = "…" + cwd[-(39):]

        table.add_row(inst.name, status_text, pid_str, cpu_str, mem_str, uptime_str, cwd)

    if not instances:
        table.add_row("[dim]No agents detected[/dim]", "", "", "", "", "", "")

    return table


def build_agent_card(instance: AgentInstance, history: AgentHistory | None = None) -> Panel:
    """Build a detailed panel for a single running agent."""
    lines: list[str] = []
    style, icon = STATUS_STYLES.get(instance.status, ("dim", "?"))

    lines.append(f"[bold]PID:[/bold] {instance.pid or 'N/A'}")
    lines.append(f"[bold]Binary:[/bold] {instance.binary_path or 'N/A'}")
    lines.append(f"[bold]API:[/bold] {instance.api_domain or 'N/A'}")

    if instance.status == AgentStatus.RUNNING:
        lines.append(f"[bold]CPU:[/bold] {instance.cpu_percent:.1f}%")
        lines.append(f"[bold]Memory:[/bold] {format_mb(instance.memory_mb)}")
        lines.append(f"[bold]Uptime:[/bold] {format_uptime(instance.uptime_seconds)}")

        if history:
            cpu_spark = sparkline(history.cpu_history)
            mem_spark = sparkline(history.memory_history)
            if cpu_spark:
                lines.append(f"[bold]CPU history:[/bold]  {cpu_spark}")
            if mem_spark:
                lines.append(f"[bold]Mem history:[/bold]  {mem_spark}")

    if instance.working_directory:
        lines.append(f"[bold]Dir:[/bold] {instance.working_directory}")

    content = "\n".join(lines)
    return Panel(
        content,
        title=f"{icon} {instance.name}",
        title_align="left",
        border_style=style.replace("bold ", ""),
        expand=True,
    )


def build_env_table(env_vars: list[dict[str, str]]) -> Table:
    """Build a table of detected AI environment variables."""
    table = Table(
        title="AI Environment Variables",
        expand=True,
        title_style="bold cyan",
        border_style="bright_blue",
    )
    table.add_column("Variable", style="bold white", min_width=25)
    table.add_column("Value", min_width=30)
    table.add_column("Length", justify="right", min_width=6)

    for var in env_vars:
        table.add_row(var["name"], var["value"], var["raw_length"])

    if not env_vars:
        table.add_row("[dim]No AI env vars detected[/dim]", "", "")

    return table


def build_usage_table(instances: list[AgentInstance]) -> Table:
    """Build a summary table of usage stats across agents."""
    table = Table(
        title="Usage Statistics",
        expand=True,
        title_style="bold cyan",
        border_style="bright_blue",
    )
    table.add_column("Agent", style="bold white", min_width=14)
    table.add_column("Status", min_width=10)
    table.add_column("Total Tokens", justify="right", min_width=12)
    table.add_column("Sessions", justify="right", min_width=9)
    table.add_column("Messages", justify="right", min_width=9)
    table.add_column("Tool Calls", justify="right", min_width=10)
    table.add_column("Last Activity", min_width=12)

    has_stats = False
    for inst in sorted(instances, key=lambda i: (i.status != AgentStatus.RUNNING, i.name)):
        style, icon = STATUS_STYLES.get(inst.status, ("dim", "?"))
        status_text = Text(f"{icon} {inst.status.value}", style=style)

        stats = inst.usage_stats
        if stats:
            has_stats = True
            tokens_str = format_number(stats.total_tokens)
            sessions_str = format_number(stats.total_sessions)
            messages_str = format_number(stats.total_messages)
            tools_str = format_number(stats.total_tool_calls)
            last_activity = stats.time_range_end or "-"
        else:
            tokens_str = "-"
            sessions_str = "-"
            messages_str = "-"
            tools_str = "-"
            last_activity = "-"

        table.add_row(
            inst.name, status_text, tokens_str,
            sessions_str, messages_str, tools_str, last_activity,
        )

    if not instances:
        table.add_row("[dim]No agents detected[/dim]", "", "", "", "", "", "")
    elif not has_stats:
        table.add_row("[dim]No usage data available[/dim]", "", "", "", "", "", "")

    return table


def build_usage_card(instance: AgentInstance) -> Panel:
    """Build a detailed usage panel for a single agent."""
    stats = instance.usage_stats
    if stats is None:
        return Panel(
            "[dim]No usage data available[/dim]",
            title=f"{instance.name} Usage",
            title_align="left",
            border_style="dim",
            expand=True,
        )

    lines: list[str] = []

    # Totals
    lines.append(
        f"[bold]Tokens:[/bold] {format_number(stats.total_tokens)}  "
        f"[bold]Sessions:[/bold] {format_number(stats.total_sessions)}  "
        f"[bold]Messages:[/bold] {format_number(stats.total_messages)}"
    )

    if stats.time_range_start and stats.time_range_end:
        lines.append(
            f"[bold]Period:[/bold] {stats.time_range_start} → {stats.time_range_end}"
        )

    # Model breakdown
    if stats.model_stats:
        lines.append("")
        lines.append("[bold underline]Models[/bold underline]")
        for ms in sorted(stats.model_stats.values(), key=lambda m: m.usage.total_tokens, reverse=True):
            lines.append(
                f"  {ms.model_id}: {format_number(ms.usage.total_tokens)} tokens "
                f"(in={format_number(ms.usage.input_tokens)} "
                f"out={format_number(ms.usage.output_tokens)})"
            )

    # Top tools
    top = stats.top_tools[:10]
    if top:
        lines.append("")
        lines.append("[bold underline]Top Tools[/bold underline]")
        for ts in top:
            last = f"  (last: {ts.last_used})" if ts.last_used else ""
            lines.append(f"  {ts.tool_name}: {ts.call_count}{last}")

    # Daily sparkline
    if stats.daily_activity:
        token_values = [float(d.total_tokens) for d in stats.daily_activity]
        spark = sparkline(token_values, width=30)
        if spark.strip():
            lines.append("")
            lines.append(f"[bold]Daily tokens:[/bold] {spark}")

    content = "\n".join(lines)
    return Panel(
        content,
        title=f"{instance.name} Usage",
        title_align="left",
        border_style="cyan",
        expand=True,
    )
