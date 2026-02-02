"""Click CLI entry points for Riva."""

from __future__ import annotations

import json

import click
from rich.console import Console
from rich.table import Table

from riva.agents.base import AgentStatus
from riva.agents.registry import get_default_registry
from riva.core.env_scanner import scan_env_vars
from riva.core.monitor import ResourceMonitor
from riva.tui.components import (
    build_agent_table,
    build_env_table,
    build_usage_card,
    build_usage_table,
)


@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx: click.Context) -> None:
    """Riva - AI Agent Task Manager.

    Discover and monitor AI coding agents running on your machine.
    """
    if ctx.invoked_subcommand is None:
        ctx.invoke(watch)


@cli.command()
def watch() -> None:
    """Launch the live TUI dashboard."""
    from riva.tui.dashboard import run_dashboard

    run_dashboard()


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def scan(as_json: bool) -> None:
    """One-shot scan for AI agents."""
    monitor = ResourceMonitor()
    instances = monitor.scan_once()

    # Attach lightweight usage stats for each detected agent
    registry = get_default_registry()
    _attach_usage_stats(instances, registry)

    if as_json:
        output = []
        for inst in instances:
            entry: dict = {
                "name": inst.name,
                "status": inst.status.value,
                "pid": inst.pid,
                "binary_path": inst.binary_path,
                "config_dir": inst.config_dir,
                "cpu_percent": inst.cpu_percent,
                "memory_mb": round(inst.memory_mb, 1),
                "uptime_seconds": round(inst.uptime_seconds, 1),
                "working_directory": inst.working_directory,
                "api_domain": inst.api_domain,
            }
            if inst.usage_stats:
                entry["usage_summary"] = {
                    "total_tokens": inst.usage_stats.total_tokens,
                    "total_sessions": inst.usage_stats.total_sessions,
                    "total_messages": inst.usage_stats.total_messages,
                    "total_tool_calls": inst.usage_stats.total_tool_calls,
                }
            output.append(entry)
        click.echo(json.dumps(output, indent=2))
    else:
        console = Console()
        console.print()
        console.print(build_agent_table(instances))

        env_vars = scan_env_vars()
        if env_vars:
            console.print()
            console.print(build_env_table(env_vars))
        console.print()


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--agent", "agent_filter", default=None, help="Filter by agent name (case-insensitive substring).")
def stats(as_json: bool, agent_filter: str | None) -> None:
    """Show token usage and tool execution statistics."""
    registry = get_default_registry()
    instances: list = []

    for detector in registry.detectors:
        if not detector.is_installed():
            continue
        if agent_filter and agent_filter.lower() not in detector.agent_name.lower():
            continue

        inst = detector.build_instance()
        usage = detector.parse_usage()
        inst.usage_stats = usage
        instances.append(inst)

    if as_json:
        output = []
        for inst in instances:
            entry: dict = {"name": inst.name, "status": inst.status.value}
            s = inst.usage_stats
            if s:
                entry["usage"] = {
                    "total_tokens": s.total_tokens,
                    "total_sessions": s.total_sessions,
                    "total_messages": s.total_messages,
                    "total_tool_calls": s.total_tool_calls,
                    "time_range_start": s.time_range_start,
                    "time_range_end": s.time_range_end,
                    "models": {
                        mid: {
                            "input_tokens": ms.usage.input_tokens,
                            "output_tokens": ms.usage.output_tokens,
                            "cache_read_input_tokens": ms.usage.cache_read_input_tokens,
                            "cache_creation_input_tokens": ms.usage.cache_creation_input_tokens,
                            "total_tokens": ms.usage.total_tokens,
                        }
                        for mid, ms in s.model_stats.items()
                    },
                    "top_tools": [
                        {"tool_name": t.tool_name, "call_count": t.call_count, "last_used": t.last_used}
                        for t in s.top_tools[:20]
                    ],
                }
            else:
                entry["usage"] = None
            output.append(entry)
        click.echo(json.dumps(output, indent=2))
    else:
        console = Console()
        console.print()
        console.print(build_usage_table(instances))

        for inst in instances:
            if inst.usage_stats:
                console.print()
                console.print(build_usage_card(inst))
        console.print()


@cli.command(name="list")
def list_agents() -> None:
    """Show all known agent types and their install status."""
    console = Console()
    registry = get_default_registry()

    table = Table(
        title="Known AI Agent Types",
        expand=True,
        title_style="bold cyan",
        border_style="bright_blue",
    )
    table.add_column("Agent", style="bold white", min_width=14)
    table.add_column("Binaries", min_width=15)
    table.add_column("Config Dir", min_width=20)
    table.add_column("API Domain", min_width=25)
    table.add_column("Installed", min_width=10)

    for detector in registry.detectors:
        installed = detector.is_installed()
        status_text = "[bold green]Yes[/bold green]" if installed else "[dim]No[/dim]"
        config_exists = "✓" if detector.config_dir.exists() else "✗"

        table.add_row(
            detector.agent_name,
            ", ".join(detector.binary_names),
            f"{detector.config_dir} {config_exists}",
            detector.api_domain,
            status_text,
        )

    console.print()
    console.print(table)
    console.print()


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
@click.option("--network", "include_network", is_flag=True, help="Include network security checks.")
def audit(as_json: bool, include_network: bool) -> None:
    """Run a security audit and print a report."""
    from riva.core.audit import run_audit

    results = run_audit(include_network=include_network)

    if as_json:
        click.echo(json.dumps(
            [{"check": r.check, "status": r.status, "detail": r.detail, "severity": r.severity, "category": r.category} for r in results],
            indent=2,
        ))
    else:
        console = Console()
        table = Table(
            title="Security Audit Report",
            expand=True,
            title_style="bold cyan",
            border_style="bright_blue",
        )
        table.add_column("Check", style="bold white", min_width=20)
        table.add_column("Status", min_width=8)
        table.add_column("Severity", min_width=10)
        table.add_column("Detail", min_width=40)

        status_style = {"pass": "bold green", "warn": "bold yellow", "fail": "bold red"}
        severity_style = {
            "info": "dim", "low": "blue", "medium": "yellow",
            "high": "bold red", "critical": "bold red on white",
        }
        for r in results:
            style = status_style.get(r.status, "")
            sev_style = severity_style.get(r.severity, "dim")
            table.add_row(
                r.check,
                f"[{style}]{r.status.upper()}[/{style}]",
                f"[{sev_style}]{r.severity}[/{sev_style}]",
                r.detail,
            )

        console.print()
        console.print(table)
        console.print()


@cli.command()
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def network(as_json: bool) -> None:
    """Show active network connections grouped by agent."""
    from riva.core.network import collect_all_connections

    monitor = ResourceMonitor()
    instances = monitor.scan_once()
    snapshots = collect_all_connections(instances)

    if as_json:
        output = []
        for snap in snapshots:
            output.append({
                "agent": snap.agent_name,
                "pid": snap.pid,
                "connection_count": snap.connection_count,
                "connections": [
                    {
                        "local": f"{c.local_addr}:{c.local_port}",
                        "remote": f"{c.remote_addr}:{c.remote_port}",
                        "status": c.status,
                        "hostname": c.hostname,
                        "known_service": c.known_service,
                        "is_tls": c.is_tls,
                    }
                    for c in snap.connections
                ],
            })
        click.echo(json.dumps(output, indent=2))
    else:
        console = Console()
        if not snapshots:
            console.print("\n[dim]No running agents with network connections.[/dim]\n")
            return

        for snap in snapshots:
            table = Table(
                title=f"{snap.agent_name} (PID {snap.pid}) — {snap.connection_count} connections",
                expand=True,
                title_style="bold cyan",
                border_style="bright_blue",
            )
            table.add_column("Local", min_width=20)
            table.add_column("Remote", min_width=20)
            table.add_column("Status", min_width=12)
            table.add_column("Hostname", min_width=20)
            table.add_column("Service", min_width=15)
            table.add_column("TLS", min_width=5)

            for c in snap.connections:
                status_style = "green" if c.status == "ESTABLISHED" else "yellow" if c.status == "CLOSE_WAIT" else "red" if c.status == "TIME_WAIT" else ""
                tls_str = "[green]✓[/green]" if c.is_tls else "[dim]✗[/dim]"
                table.add_row(
                    f"{c.local_addr}:{c.local_port}",
                    f"{c.remote_addr}:{c.remote_port}",
                    f"[{status_style}]{c.status}[/{status_style}]" if status_style else c.status,
                    c.hostname or "—",
                    c.known_service or "—",
                    tls_str,
                )

            console.print()
            console.print(table)
        console.print()


@cli.command()
@click.option("--hours", default=1.0, type=float, help="Hours of history to show.")
@click.option("--agent", "agent_name", default=None, help="Filter by agent name.")
@click.option("--json", "as_json", is_flag=True, help="Output as JSON.")
def history(hours: float, agent_name: str | None, as_json: bool) -> None:
    """Show persisted snapshots from the database."""
    from riva.core.storage import RivaStorage

    storage = RivaStorage()
    try:
        snapshots = storage.get_snapshots(agent_name=agent_name, hours=hours)

        if as_json:
            click.echo(json.dumps(snapshots, indent=2))
        else:
            console = Console()
            if not snapshots:
                console.print(f"\n[dim]No snapshots in the last {hours} hour(s).[/dim]\n")
                return

            table = Table(
                title=f"Historical Snapshots (last {hours}h)",
                expand=True,
                title_style="bold cyan",
                border_style="bright_blue",
            )
            table.add_column("Agent", style="bold white", min_width=14)
            table.add_column("Time", min_width=20)
            table.add_column("PID", justify="right", min_width=7)
            table.add_column("CPU %", justify="right", min_width=7)
            table.add_column("Memory MB", justify="right", min_width=10)
            table.add_column("Connections", justify="right", min_width=11)
            table.add_column("Status", min_width=10)

            import datetime
            for s in snapshots[:100]:  # Limit display
                ts = datetime.datetime.fromtimestamp(s["timestamp"]).strftime("%Y-%m-%d %H:%M:%S")
                table.add_row(
                    s.get("agent_name", "?"),
                    ts,
                    str(s.get("pid", "—")),
                    f"{s.get('cpu_percent', 0):.1f}",
                    f"{s.get('memory_mb', 0):.1f}",
                    str(s.get("connection_count", 0)),
                    s.get("status", "—"),
                )

            console.print()
            console.print(table)
            if len(snapshots) > 100:
                console.print(f"  [dim]Showing 100 of {len(snapshots)} snapshots[/dim]")
            console.print()
    finally:
        storage.close()


@cli.group(invoke_without_command=True)
@click.option("--host", default="127.0.0.1", help="Host to bind to.")
@click.option("--port", default=8585, type=int, help="Port to bind to.")
@click.option("--auth-token", default=None, help="Bearer token for API authentication.")
@click.pass_context
def web(ctx: click.Context, host: str, port: int, auth_token: str | None) -> None:
    """Web dashboard (start/stop/status/logs)."""
    ctx.ensure_object(dict)
    ctx.obj["host"] = host
    ctx.obj["port"] = port
    ctx.obj["auth_token"] = auth_token
    if ctx.invoked_subcommand is None:
        ctx.invoke(web_start, foreground=True)


@web.command(name="start")
@click.option("--foreground", "-f", is_flag=True, help="Run in foreground instead of daemonizing.")
@click.pass_context
def web_start(ctx: click.Context, foreground: bool) -> None:
    """Start the web dashboard."""
    host = ctx.obj["host"]
    port = ctx.obj["port"]
    auth_token = ctx.obj.get("auth_token")
    console = Console()

    if host not in ("127.0.0.1", "localhost", "::1"):
        console.print(
            "[bold yellow]Warning:[/bold yellow] Binding to non-localhost "
            f"address {host}. The dashboard has no authentication and will "
            "be accessible to anyone on the network."
        )

    if foreground:
        from riva.web.server import run_server

        console.print(f"\n[bold cyan]RIVA Web Dashboard[/bold cyan] → http://{host}:{port}\n")
        run_server(host=host, port=port, auth_token=auth_token)
    else:
        from riva.web.daemon import start_daemon

        try:
            pid = start_daemon(host, port, auth_token=auth_token)
        except RuntimeError as exc:
            console.print(f"\n[bold red]Error:[/bold red] {exc}\n")
            raise SystemExit(1) from exc
        console.print(f"\n[bold cyan]RIVA Web Dashboard[/bold cyan] started (PID {pid})")
        console.print(f"  URL: http://{host}:{port}")
        console.print(f"  Logs: ~/.config/riva/web.log\n")


@web.command(name="stop")
def web_stop() -> None:
    """Stop the web dashboard."""
    from riva.web.daemon import stop_daemon

    console = Console()
    stopped = stop_daemon()
    if stopped:
        console.print("\n[bold green]Dashboard stopped.[/bold green]\n")
    else:
        console.print("\n[dim]Dashboard is not running.[/dim]\n")


@web.command(name="status")
def web_status() -> None:
    """Show dashboard status."""
    from riva.web.daemon import daemon_status

    console = Console()
    info = daemon_status()
    if info["running"]:
        console.print(f"\n[bold green]Running[/bold green] (PID {info['pid']})")
    else:
        console.print("\n[dim]Not running.[/dim]")
    console.print(f"  Log file: {info['log_file']}\n")


@web.command(name="logs")
@click.option("--follow", "-f", is_flag=True, help="Follow log output.")
@click.option("--lines", "-n", default=50, help="Number of lines to show.")
def web_logs(follow: bool, lines: int) -> None:
    """Show dashboard logs."""
    from riva.web.daemon import LOG_FILE

    console = Console()
    if not LOG_FILE.exists():
        console.print("\n[dim]No log file found.[/dim]\n")
        return

    # Read the last N lines
    all_lines = LOG_FILE.read_text().splitlines()
    for line in all_lines[-lines:]:
        click.echo(line)

    if follow:
        import time

        try:
            with open(LOG_FILE) as fh:
                fh.seek(0, 2)  # seek to end
                while True:
                    line = fh.readline()
                    if line:
                        click.echo(line, nl=False)
                    else:
                        time.sleep(0.3)
        except KeyboardInterrupt:
            pass


@cli.command()
def config() -> None:
    """Show parsed configurations for detected agents."""
    console = Console()
    registry = get_default_registry()

    found_any = False
    for detector in registry.detectors:
        if not detector.is_installed():
            continue

        found_any = True
        parsed = detector.parse_config()

        table = Table(
            title=f"{detector.agent_name} Configuration",
            expand=True,
            title_style="bold cyan",
            border_style="bright_blue",
        )
        table.add_column("Key", style="bold white", min_width=20)
        table.add_column("Value", min_width=40)

        for key, value in sorted(parsed.items()):
            val_str = json.dumps(value, indent=2) if isinstance(value, (dict, list)) else str(value)
            # Truncate very long values
            if len(val_str) > 200:
                val_str = val_str[:200] + "…"
            table.add_row(key, val_str)

        console.print()
        console.print(table)

    if not found_any:
        console.print("\n[dim]No installed agents found.[/dim]\n")
    else:
        console.print()


def _attach_usage_stats(instances: list, registry) -> None:
    """Attach usage stats to instances by matching agent names to detectors."""
    detector_map = {d.agent_name: d for d in registry.detectors}
    for inst in instances:
        detector = detector_map.get(inst.name)
        if detector:
            try:
                inst.usage_stats = detector.parse_usage()
            except Exception:
                pass
