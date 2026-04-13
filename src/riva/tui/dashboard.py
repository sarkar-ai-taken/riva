"""Rich Live TUI dashboard with tab switching."""

from __future__ import annotations

import select
import sys
import termios
import threading
import tty
from typing import Literal

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
    build_forensic_panel,
    build_hook_events_panel,
    build_network_table,
    build_orphan_panel,
    build_security_panel,
    build_skills_panel,
)
from riva.utils.formatting import format_number

Tab = Literal["main", "skills", "events"]

_TAB_KEYS: dict[str, Tab] = {
    "1": "main",
    "m": "main",
    "2": "skills",
    "s": "skills",
    "3": "events",
    "e": "events",
}


# ---------------------------------------------------------------------------
# Non-blocking keyboard reader (background thread)
# ---------------------------------------------------------------------------


class _KeyReader:
    """Read single keypresses from stdin without blocking the main loop."""

    def __init__(self) -> None:
        self._key: str | None = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._old_settings: list | None = None

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def pop(self) -> str | None:
        with self._lock:
            key = self._key
            self._key = None
            return key

    def _loop(self) -> None:
        fd = sys.stdin.fileno()
        try:
            self._old_settings = termios.tcgetattr(fd)
            tty.setraw(fd)
        except Exception:
            return  # not a real TTY (pipes, tests) — just exit silently

        try:
            while not self._stop.is_set():
                ready, _, _ = select.select([sys.stdin], [], [], 0.1)
                if ready:
                    ch = sys.stdin.read(1)
                    with self._lock:
                        self._key = ch
        finally:
            try:
                termios.tcsetattr(fd, termios.TCSADRAIN, self._old_settings)
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Shared builders
# ---------------------------------------------------------------------------


def _build_header(active_tab: Tab) -> Panel:
    """Header with tab bar."""
    text = Text("RIVA", style="bold bright_cyan")
    text.append(" — AI Agent Command Center", style="dim white")
    text.append("    ", style="")

    for key, label, tab in [("1", "Main", "main"), ("2", "Skills", "skills"), ("3", "Events", "events")]:
        if tab == active_tab:
            text.append(f" [{key}] {label} ", style="bold black on bright_cyan")
        else:
            text.append(f" [{key}] {label} ", style="dim")

    return Panel(text, border_style="bright_blue", padding=(0, 1))


def _build_footer(_active_tab: Tab) -> Panel:
    hints = (
        "[dim][bold]1[/bold] Main  [bold]2[/bold] Skills  [bold]3[/bold] Events"
        "  [bold]Ctrl+C[/bold] Exit  •  Polling every 2s[/dim]"
    )
    return Panel(hints, border_style="dim")


def _collect_skills(monitor: ResourceMonitor) -> list:
    """Collect all skills and attach forensic stats. Shared between both tab builders."""
    try:
        from riva.core.skills import compute_forensic_stats, load_global_skills, load_workspace_skills
        from riva.core.workspace import find_workspace

        all_skills: list = []
        all_skills.extend(load_global_skills())

        workspace_dir = find_workspace()
        if workspace_dir:
            all_skills.extend(load_workspace_skills(workspace_dir))

        existing_ids = {s.id for s in all_skills}
        for detector in monitor.registry.detectors:
            if detector.is_installed():
                try:
                    for sk in detector.parse_skills():
                        if sk.id not in existing_ids:
                            all_skills.append(sk)
                            existing_ids.add(sk.id)
                except Exception:
                    pass

        storage = monitor.storage
        if storage and all_skills:
            for skill in all_skills:
                try:
                    invocations = storage.get_skill_invocations(skill.id, workspace=skill.workspace or "")
                    skill.forensic_stats = compute_forensic_stats(invocations)
                except Exception:
                    pass

        return all_skills
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Main tab layout
# ---------------------------------------------------------------------------


def _build_usage_summary(monitor: ResourceMonitor) -> Panel:
    instances = monitor.instances
    parts: list[str] = []
    for inst in instances:
        stats = inst.usage_stats
        if stats is None:
            continue
        tokens = format_number(stats.total_tokens)
        sessions = format_number(stats.total_sessions)
        tools = format_number(stats.total_tool_calls)
        parts.append(f"[bold]{inst.name}[/bold]: {tokens} tokens · {sessions} sessions · {tools} tool calls")

    content = (
        "  |  ".join(parts)
        if parts
        else "[dim]No usage data available. Run [bold]riva stats[/bold] for full breakdown.[/dim]"
    )
    return Panel(content, title="Usage Summary", title_align="left", border_style="cyan", padding=(0, 1))


def _build_forensic_summary() -> Panel:
    try:
        from riva.core.forensic import discover_sessions

        sessions = discover_sessions(limit=5)
    except Exception:
        sessions = []
    return build_forensic_panel(sessions)


def _build_main_layout(monitor: ResourceMonitor) -> Layout:
    instances = monitor.instances
    histories = monitor.histories
    orphans = monitor.orphans

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_build_header("main"))
    layout["footer"].update(_build_footer("main"))

    orphan_size = min(len(orphans) + 4, 8) if orphans else 4
    body = Layout()
    body.split_column(
        Layout(name="table", size=len(instances) + 7),
        Layout(name="details"),
        Layout(name="orphans", size=orphan_size),
        Layout(name="network", size=8),
        Layout(name="security", size=6),
        Layout(name="usage", size=3),
        Layout(name="forensic", size=10),
        Layout(name="env", size=10),
    )

    body["table"].update(build_agent_table(instances))

    running = [i for i in instances if i.status == AgentStatus.RUNNING]
    if running:
        cards = []
        for inst in running:
            key = f"{inst.name}:{inst.pid}" if inst.pid else inst.name
            cards.append(build_agent_card(inst, histories.get(key)))
        body["details"].update(Columns(cards, equal=True, expand=True) if len(cards) > 1 else cards[0])
    else:
        body["details"].update(
            Panel(
                "[dim]No running agents. Start an AI coding agent to see live metrics.[/dim]",
                title="Agent Details",
                border_style="dim",
            )
        )

    body["orphans"].update(build_orphan_panel(orphans))
    body["network"].update(build_network_table(instances))
    body["security"].update(build_security_panel())
    body["usage"].update(_build_usage_summary(monitor))
    body["forensic"].update(_build_forensic_summary())
    body["env"].update(build_env_table(scan_env_vars()))

    layout["body"].update(body)
    return layout


# ---------------------------------------------------------------------------
# Skills tab layout
# ---------------------------------------------------------------------------


def _build_skills_layout(monitor: ResourceMonitor) -> Layout:
    skills = _collect_skills(monitor)

    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_build_header("skills"))
    layout["footer"].update(_build_footer("skills"))

    body = Layout()
    body.split_column(
        Layout(name="skills_table"),
        Layout(name="hint", size=3),
    )

    body["skills_table"].update(build_skills_panel(skills if skills else None))
    body["hint"].update(
        Panel(
            "[dim]Run [bold]riva skills scan --all-sessions[/bold] to populate stats from session history.  "
            "Add skills with [bold]riva skills add NAME[/bold]  •  "
            "Define workspace skills in [bold].riva/skills.toml[/bold][/dim]",
            border_style="dim",
            padding=(0, 1),
        )
    )

    layout["body"].update(body)
    return layout


# ---------------------------------------------------------------------------
# Events tab layout
# ---------------------------------------------------------------------------


def _build_events_layout(monitor: ResourceMonitor) -> Layout:
    """Full-screen event stream tab: all hook events, JSONL tail events, and OTLP."""
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="body"),
        Layout(name="footer", size=3),
    )
    layout["header"].update(_build_header("events"))
    layout["footer"].update(_build_footer("events"))

    events: list[dict] = []
    storage = monitor.storage
    if storage:
        try:
            events = storage.get_hook_events(hours=1.0, limit=200)
        except Exception:
            pass

    body = Layout()
    body.split_column(
        Layout(name="stream"),
        Layout(name="hint", size=3),
    )
    body["stream"].update(build_hook_events_panel(events if events else None, max_rows=40))
    body["hint"].update(
        Panel(
            "[dim]Showing last 1 h of events from Claude Code hooks, JSONL tail-watching, and OTLP receivers.  "
            "Run [bold]riva web start[/bold] and POST to [bold]/api/events[/bold] from any agent adapter.[/dim]",
            border_style="dim",
            padding=(0, 1),
        )
    )
    layout["body"].update(body)
    return layout


# ---------------------------------------------------------------------------
# Dashboard entry point
# ---------------------------------------------------------------------------


def run_dashboard(monitor: ResourceMonitor | None = None) -> None:
    """Run the live TUI dashboard with tab switching."""
    if monitor is None:
        from riva.core.storage import RivaStorage
        from riva.core.workspace import find_workspace, load_workspace_config

        workspace_dir = find_workspace()
        ws_config = load_workspace_config(workspace_dir) if workspace_dir else None
        try:
            storage = RivaStorage()
        except Exception:
            storage = None
        monitor = ResourceMonitor(workspace_config=ws_config, storage=storage)

    console = Console()
    monitor.start()

    import time

    time.sleep(1)  # let first scan complete
    try:
        from riva.hub.client import ping_hub

        ping_hub(monitor.instances)
    except Exception:
        pass

    active_tab: Tab = "main"
    key_reader = _KeyReader()
    key_reader.start()

    def _render() -> Layout:
        if active_tab == "skills":
            return _build_skills_layout(monitor)
        if active_tab == "events":
            return _build_events_layout(monitor)
        return _build_main_layout(monitor)

    try:
        with Live(_render(), console=console, refresh_per_second=1, screen=True) as live:
            while True:
                key = key_reader.pop()
                if key == "\x03":  # Ctrl+C
                    break
                if key in _TAB_KEYS:
                    active_tab = _TAB_KEYS[key]
                live.update(_render())
                time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        key_reader.stop()
        monitor.stop()
