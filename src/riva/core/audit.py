"""Security audit checks for Riva."""

from __future__ import annotations

import json
import os
import stat
from dataclasses import dataclass
from pathlib import Path

from riva.agents.registry import get_default_registry
from riva.core.env_scanner import scan_env_vars
from riva.web.daemon import daemon_status


@dataclass
class AuditResult:
    """Single audit check result."""

    check: str
    status: str  # "pass" | "warn" | "fail"
    detail: str
    severity: str = "info"  # "info" | "low" | "medium" | "high" | "critical"
    category: str = "general"


def run_audit(include_network: bool = False) -> list[AuditResult]:
    """Run all security audit checks and return results."""
    results: list[AuditResult] = []
    results.extend(_check_api_key_exposure())
    results.extend(_check_config_dir_permissions())
    results.extend(_check_dashboard_status())
    results.extend(_check_plugin_directory())
    results.extend(_check_mcp_configs())
    results.extend(_check_exposed_tokens_in_configs())

    if include_network:
        results.extend(_check_unencrypted_connections())
        results.extend(_check_unknown_destinations())
        results.extend(_check_excessive_connections())
        results.extend(_check_stale_sessions())

    return results


def _check_api_key_exposure() -> list[AuditResult]:
    """Check for API keys exposed in environment variables."""
    env_vars = scan_env_vars()
    secrets = [v for v in env_vars if "KEY" in v["name"].upper() or "TOKEN" in v["name"].upper() or "SECRET" in v["name"].upper()]
    if secrets:
        names = ", ".join(v["name"] for v in secrets)
        return [AuditResult(
            check="API Key Exposure",
            status="warn",
            detail=f"Found {len(secrets)} secret(s) in environment: {names}",
            severity="medium",
            category="credentials",
        )]
    return [AuditResult(
        check="API Key Exposure",
        status="pass",
        detail="No API keys or secrets found in environment variables.",
        severity="info",
        category="credentials",
    )]


def _check_config_dir_permissions() -> list[AuditResult]:
    """Check config directory permissions for installed agents."""
    results: list[AuditResult] = []
    registry = get_default_registry()
    for detector in registry.detectors:
        if not detector.is_installed():
            continue
        config_dir = detector.config_dir
        if not config_dir.exists():
            continue
        try:
            mode = os.stat(config_dir).st_mode
            if mode & 0o077:
                results.append(AuditResult(
                    check=f"Config Permissions ({detector.agent_name})",
                    status="fail",
                    detail=f"{config_dir} is group/other-readable (mode {oct(stat.S_IMODE(mode))})",
                    severity="high",
                    category="permissions",
                ))
            else:
                results.append(AuditResult(
                    check=f"Config Permissions ({detector.agent_name})",
                    status="pass",
                    detail=f"{config_dir} permissions OK ({oct(stat.S_IMODE(mode))})",
                    severity="info",
                    category="permissions",
                ))
        except OSError as exc:
            results.append(AuditResult(
                check=f"Config Permissions ({detector.agent_name})",
                status="warn",
                detail=f"Could not stat {config_dir}: {exc}",
                severity="low",
                category="permissions",
            ))
    if not results:
        results.append(AuditResult(
            check="Config Permissions",
            status="pass",
            detail="No installed agents with config directories found.",
            severity="info",
            category="permissions",
        ))
    return results


def _check_dashboard_status() -> list[AuditResult]:
    """Check if the web dashboard is running and bound to a non-localhost address."""
    info = daemon_status()
    if not info["running"]:
        return [AuditResult(
            check="Dashboard Status",
            status="pass",
            detail="Web dashboard is not running.",
            severity="info",
            category="network",
        )]
    return [AuditResult(
        check="Dashboard Status",
        status="warn",
        detail=f"Web dashboard is running (PID {info['pid']}). "
               "Verify it is not bound to a non-localhost address without authentication.",
        severity="medium",
        category="network",
    )]


def _check_plugin_directory() -> list[AuditResult]:
    """Check the plugin directory for security concerns."""
    plugin_dir = Path("~/.config/riva/plugins").expanduser()
    if not plugin_dir.exists():
        return [AuditResult(
            check="Plugin Directory",
            status="pass",
            detail="Plugin directory does not exist.",
            severity="info",
            category="general",
        )]
    results: list[AuditResult] = [AuditResult(
        check="Plugin Directory",
        status="warn",
        detail=f"{plugin_dir} exists — arbitrary code can be loaded from plugins.",
        severity="medium",
        category="general",
    )]
    try:
        mode = os.stat(plugin_dir).st_mode
        if mode & 0o077:
            results.append(AuditResult(
                check="Plugin Directory Permissions",
                status="fail",
                detail=f"{plugin_dir} is group/other-accessible (mode {oct(stat.S_IMODE(mode))})",
                severity="high",
                category="permissions",
            ))
        else:
            results.append(AuditResult(
                check="Plugin Directory Permissions",
                status="pass",
                detail=f"{plugin_dir} permissions OK ({oct(stat.S_IMODE(mode))})",
                severity="info",
                category="permissions",
            ))
    except OSError as exc:
        results.append(AuditResult(
            check="Plugin Directory Permissions",
            status="warn",
            detail=f"Could not stat {plugin_dir}: {exc}",
            severity="low",
            category="permissions",
        ))
    return results


def _check_mcp_configs() -> list[AuditResult]:
    """Check MCP configurations for HTTP (non-HTTPS) endpoints."""
    results: list[AuditResult] = []
    mcp_paths = [
        Path.home() / ".cursor" / "mcp.json",
        Path.home() / ".vscode" / "mcp.json",
    ]

    for mcp_path in mcp_paths:
        if not mcp_path.is_file():
            continue
        try:
            data = json.loads(mcp_path.read_text())
            servers = data.get("mcpServers", data.get("servers", {}))
            if isinstance(servers, dict):
                for name, server_cfg in servers.items():
                    if not isinstance(server_cfg, dict):
                        continue
                    url = server_cfg.get("url", "") or server_cfg.get("endpoint", "")
                    if isinstance(url, str) and url.startswith("http://"):
                        results.append(AuditResult(
                            check=f"MCP Config ({mcp_path.parent.name})",
                            status="fail",
                            detail=f"MCP server '{name}' uses unencrypted HTTP: {url}",
                            severity="high",
                            category="network",
                        ))
        except (json.JSONDecodeError, OSError, TypeError):
            pass

    if not results:
        results.append(AuditResult(
            check="MCP Configuration",
            status="pass",
            detail="No insecure MCP endpoints found.",
            severity="info",
            category="network",
        ))
    return results


def _check_exposed_tokens_in_configs() -> list[AuditResult]:
    """Scan agent config files for plaintext tokens/keys."""
    results: list[AuditResult] = []
    token_patterns = ["sk-", "ghp_", "ghu_", "github_pat_", "xoxb-", "xoxp-"]

    registry = get_default_registry()
    for detector in registry.detectors:
        if not detector.is_installed():
            continue
        config_dir = detector.config_dir
        if not config_dir.is_dir():
            continue

        # Check common config files
        config_files = ["config.json", "settings.json", "mcp.json", ".env"]
        for fname in config_files:
            fpath = config_dir / fname
            if not fpath.is_file():
                continue
            try:
                content = fpath.read_text(errors="replace")
                for pattern in token_patterns:
                    if pattern in content:
                        results.append(AuditResult(
                            check=f"Exposed Token ({detector.agent_name})",
                            status="fail",
                            detail=f"Possible plaintext token (pattern: '{pattern}...') in {fpath}",
                            severity="critical",
                            category="credentials",
                        ))
                        break  # One finding per file is enough
            except OSError:
                pass

    if not results:
        results.append(AuditResult(
            check="Exposed Tokens",
            status="pass",
            detail="No plaintext tokens found in agent config files.",
            severity="info",
            category="credentials",
        ))
    return results


# ---------------------------------------------------------------------------
# Network-dependent checks (require --network flag)
# ---------------------------------------------------------------------------

def _get_running_network_data() -> list[tuple[str, list[dict]]]:
    """Collect network data from currently running agents."""
    from riva.core.monitor import ResourceMonitor

    monitor = ResourceMonitor()
    instances = monitor.scan_once()
    result = []
    for inst in instances:
        network = inst.extra.get("network", [])
        if network:
            result.append((inst.name, network))
    return result


def _check_unencrypted_connections() -> list[AuditResult]:
    """Flag non-443 connections to known API domains."""
    results: list[AuditResult] = []
    from riva.core.network import KNOWN_API_DOMAINS

    for agent_name, connections in _get_running_network_data():
        for conn in connections:
            hostname = conn.get("hostname", "")
            remote_port = conn.get("remote_port", 0)
            known_service = conn.get("known_service")

            if known_service and remote_port != 443 and remote_port != 0:
                results.append(AuditResult(
                    check=f"Unencrypted Connection ({agent_name})",
                    status="fail",
                    detail=f"Connection to {known_service} on port {remote_port} (not 443/TLS)",
                    severity="high",
                    category="network",
                ))

    if not results:
        results.append(AuditResult(
            check="Unencrypted Connections",
            status="pass",
            detail="All connections to known API domains use port 443.",
            severity="info",
            category="network",
        ))
    return results


def _check_unknown_destinations() -> list[AuditResult]:
    """Flag connections to unrecognized IPs/domains."""
    results: list[AuditResult] = []

    for agent_name, connections in _get_running_network_data():
        unknown = []
        for conn in connections:
            remote_addr = conn.get("remote_addr", "")
            if not remote_addr or remote_addr in ("127.0.0.1", "::1", "0.0.0.0", "::"):
                continue
            if not conn.get("known_service") and conn.get("status") == "ESTABLISHED":
                hostname = conn.get("hostname") or remote_addr
                unknown.append(f"{hostname}:{conn.get('remote_port', '?')}")

        if unknown:
            results.append(AuditResult(
                check=f"Unknown Destinations ({agent_name})",
                status="warn",
                detail=f"{len(unknown)} connection(s) to unrecognized hosts: {', '.join(unknown[:5])}",
                severity="medium",
                category="network",
            ))

    if not results:
        results.append(AuditResult(
            check="Unknown Destinations",
            status="pass",
            detail="All agent connections are to recognized services.",
            severity="info",
            category="network",
        ))
    return results


def _check_excessive_connections() -> list[AuditResult]:
    """Flag agents with >50 connections."""
    results: list[AuditResult] = []

    for agent_name, connections in _get_running_network_data():
        if len(connections) > 50:
            results.append(AuditResult(
                check=f"Excessive Connections ({agent_name})",
                status="warn",
                detail=f"Agent has {len(connections)} active connections (threshold: 50)",
                severity="medium",
                category="network",
            ))

    if not results:
        results.append(AuditResult(
            check="Excessive Connections",
            status="pass",
            detail="No agents exceed the connection threshold.",
            severity="info",
            category="network",
        ))
    return results


def _check_stale_sessions() -> list[AuditResult]:
    """Flag agents holding connections with no activity (CLOSE_WAIT, TIME_WAIT)."""
    results: list[AuditResult] = []

    for agent_name, connections in _get_running_network_data():
        stale = [c for c in connections if c.get("status") in ("CLOSE_WAIT", "TIME_WAIT")]
        if stale:
            results.append(AuditResult(
                check=f"Stale Sessions ({agent_name})",
                status="warn",
                detail=f"Agent has {len(stale)} stale connection(s) (CLOSE_WAIT/TIME_WAIT)",
                severity="low",
                category="network",
            ))

    if not results:
        results.append(AuditResult(
            check="Stale Sessions",
            status="pass",
            detail="No stale connections found.",
            severity="info",
            category="network",
        ))
    return results
