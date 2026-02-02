"""Security audit checks for Riva."""

from __future__ import annotations

import json
import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

import psutil

from riva.agents.registry import get_default_registry
from riva.core.env_scanner import scan_env_vars
from riva.core.monitor import ResourceMonitor
from riva.web.daemon import daemon_status


# Expanded list of MCP config paths to check
_MCP_CONFIG_PATHS = [
    Path.home() / ".cursor" / "mcp.json",
    Path.home() / ".vscode" / "mcp.json",
    Path.home() / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
    Path.home() / ".config" / "claude-code" / "mcp.json",
    Path.home() / ".continue" / "config.json",
    Path.home() / ".codeium" / "windsurf" / "mcp_config.json",
    Path.home() / ".config" / "opencode" / "opencode.json",
]

# Shell commands that are suspicious when used as MCP stdio commands
_SUSPICIOUS_SHELL_COMMANDS = {"bash", "sh", "cmd", "cmd.exe", "powershell", "pwsh"}

# Config filenames to scan across all agent config directories.  Covers the
# standard JSON/TOML names plus agent-specific files that commonly hold
# credentials (AutoGen's OAI_CONFIG_LIST, Codex CLI's config.toml, etc.).
_CONFIG_FILENAMES = [
    "settings.json",
    "config.json",
    "mcp.json",
    ".env",
    "config.toml",         # Codex CLI
    "config.ts",           # Continue.dev (newer versions)
    "OAI_CONFIG_LIST",     # AutoGen — explicitly stores API keys
    "langgraph.json",      # LangGraph
    "mcp_config.json",     # Windsurf (inside config_dir subtree)
    "opencode.json",       # OpenCode
]

# VS Code extension prefixes whose config files should also be audited.
_VSCODE_EXTENSION_PREFIXES = [
    "saoudrizwan.claude-dev",   # Cline
    "github.copilot",           # GitHub Copilot
    "continue.continue",        # Continue.dev
]


def _collect_all_mcp_paths() -> list[Path]:
    """Build the full list of MCP config paths to audit.

    Combines the hard-coded well-known paths with a dynamic scan of every
    installed agent's config_dir (looking for ``mcp.json`` and
    ``mcp_config.json``).
    """
    paths = list(_MCP_CONFIG_PATHS)
    seen = {p.resolve() for p in paths if p.exists()}

    registry = get_default_registry()
    for detector in registry.detectors:
        if not detector.is_installed():
            continue
        config_dir = detector.config_dir
        if not config_dir.is_dir():
            continue
        for mcp_name in ("mcp.json", "mcp_config.json"):
            candidate = config_dir / mcp_name
            if candidate.is_file():
                resolved = candidate.resolve()
                if resolved not in seen:
                    paths.append(candidate)
                    seen.add(resolved)
    return paths


def _collect_extra_config_paths() -> list[tuple[str, Path]]:
    """Return (label, path) pairs for config files outside normal config_dir.

    Covers VS Code extension configs and macOS Application Support
    directories that detectors know about but that the generic per-agent
    scan would miss.
    """
    extra: list[tuple[str, Path]] = []

    # VS Code extension directories
    vscode_ext_dir = Path.home() / ".vscode" / "extensions"
    if vscode_ext_dir.is_dir():
        try:
            for entry in vscode_ext_dir.iterdir():
                if not entry.is_dir():
                    continue
                for prefix in _VSCODE_EXTENSION_PREFIXES:
                    if entry.name.startswith(prefix):
                        label = prefix.split(".")[0].title()
                        for fname in ("package.json", "settings.json", "config.json", ".env"):
                            fpath = entry / fname
                            if fpath.is_file():
                                extra.append((f"VSCode Extension ({label})", fpath))
        except OSError:
            pass

    # Windsurf macOS Application Support
    windsurf_user_settings = (
        Path.home() / "Library" / "Application Support" / "Windsurf" / "User" / "settings.json"
    )
    if windsurf_user_settings.is_file():
        extra.append(("Windsurf App Support", windsurf_user_settings))

    return extra


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

    results.extend(_check_orphan_processes())
    results.extend(_check_running_as_root())
    results.extend(_check_binary_permissions())
    results.extend(_check_suspicious_launcher())
    results.extend(_check_mcp_stdio_commands())
    results.extend(_check_config_file_permissions())

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

    for mcp_path in _collect_all_mcp_paths():
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
                    # Check for suspicious stdio commands
                    command = server_cfg.get("command", "")
                    if isinstance(command, str) and command:
                        cmd_base = Path(command).name
                        if cmd_base in _SUSPICIOUS_SHELL_COMMANDS:
                            results.append(AuditResult(
                                check=f"MCP Config ({mcp_path.parent.name})",
                                status="warn",
                                detail=f"MCP server '{name}' spawns a shell: {command}",
                                severity="high",
                                category="supply_chain",
                            ))
                        if "/tmp/" in command or "/tmp" in str(server_cfg.get("args", [])):
                            results.append(AuditResult(
                                check=f"MCP Config ({mcp_path.parent.name})",
                                status="warn",
                                detail=f"MCP server '{name}' references a temp directory",
                                severity="high",
                                category="supply_chain",
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
    token_patterns = [
        "sk-", "ghp_", "ghu_", "github_pat_", "xoxb-", "xoxp-",
        "sk-ant-", "AIza", "AKIA", "aws_secret", "eyJ",
        "r8_", "hf_", "gsk_",
    ]

    def _scan_file(label: str, fpath: Path) -> None:
        try:
            content = fpath.read_text(errors="replace")
            for pattern in token_patterns:
                if pattern in content:
                    results.append(AuditResult(
                        check=f"Exposed Token ({label})",
                        status="fail",
                        detail=f"Possible plaintext token (pattern: '{pattern}...') in {fpath}",
                        severity="critical",
                        category="credentials",
                    ))
                    break  # One finding per file is enough
        except OSError:
            pass

    # 1. Scan standard config files inside each agent's config_dir
    registry = get_default_registry()
    for detector in registry.detectors:
        if not detector.is_installed():
            continue
        config_dir = detector.config_dir
        if not config_dir.is_dir():
            continue
        for fname in _CONFIG_FILENAMES:
            fpath = config_dir / fname
            if fpath.is_file():
                _scan_file(detector.agent_name, fpath)

    # 2. Scan extra paths (VS Code extensions, macOS App Support)
    for label, fpath in _collect_extra_config_paths():
        _scan_file(label, fpath)

    if not results:
        results.append(AuditResult(
            check="Exposed Tokens",
            status="pass",
            detail="No plaintext tokens found in agent config files.",
            severity="info",
            category="credentials",
        ))
    return results


def _check_orphan_processes() -> list[AuditResult]:
    """Check for orphan processes from dead agent parents."""
    try:
        from riva.core.storage import RivaStorage
        storage = RivaStorage()
        try:
            orphans = storage.get_orphans(resolved=False, hours=24.0)
            if orphans:
                names = ", ".join(
                    f"PID {o['orphan_pid']} ({o.get('orphan_name', '?')})"
                    for o in orphans[:5]
                )
                suffix = f" and {len(orphans) - 5} more" if len(orphans) > 5 else ""
                return [AuditResult(
                    check="Orphan Processes",
                    status="warn",
                    detail=f"{len(orphans)} orphan process(es) detected: {names}{suffix}",
                    severity="medium",
                    category="processes",
                )]
            return [AuditResult(
                check="Orphan Processes",
                status="pass",
                detail="No orphan processes detected.",
                severity="info",
                category="processes",
            )]
        finally:
            storage.close()
    except Exception:
        return [AuditResult(
            check="Orphan Processes",
            status="pass",
            detail="No orphan processes detected (storage unavailable).",
            severity="info",
            category="processes",
        )]


def _check_running_as_root() -> list[AuditResult]:
    """Flag agent processes running as root (UID 0)."""
    results: list[AuditResult] = []
    try:
        monitor = ResourceMonitor()
        instances = monitor.scan_once()
        for inst in instances:
            if inst.pid is None:
                continue
            try:
                proc = psutil.Process(inst.pid)
                uids = proc.uids()
                if uids.real == 0:
                    results.append(AuditResult(
                        check=f"Running as Root ({inst.name})",
                        status="fail",
                        detail=f"Agent '{inst.name}' (PID {inst.pid}) is running as root (UID 0)",
                        severity="critical",
                        category="processes",
                    ))
            except (psutil.NoSuchProcess, psutil.AccessDenied, AttributeError):
                pass
    except Exception:
        pass

    if not results:
        results.append(AuditResult(
            check="Running as Root",
            status="pass",
            detail="No agents running as root.",
            severity="info",
            category="processes",
        ))
    return results


def _check_binary_permissions() -> list[AuditResult]:
    """Flag agent binaries that are world-writable or group-writable."""
    results: list[AuditResult] = []
    registry = get_default_registry()
    for detector in registry.detectors:
        if not detector.is_installed():
            continue
        binary = None
        for bname in detector.binary_names:
            binary = shutil.which(bname)
            if binary:
                break
        if binary is None:
            continue
        try:
            mode = os.stat(binary).st_mode
            if mode & 0o022:
                results.append(AuditResult(
                    check=f"Binary Permissions ({detector.agent_name})",
                    status="fail",
                    detail=f"Agent binary '{binary}' is group/world-writable (mode {oct(stat.S_IMODE(mode))}). It could be replaced with malware.",
                    severity="high",
                    category="permissions",
                ))
        except OSError:
            pass

    if not results:
        results.append(AuditResult(
            check="Binary Permissions",
            status="pass",
            detail="All agent binaries have safe permissions.",
            severity="info",
            category="permissions",
        ))
    return results


def _check_suspicious_launcher() -> list[AuditResult]:
    """Flag agents launched via unknown or suspicious mechanisms."""
    results: list[AuditResult] = []
    _SCRIPT_INTERPRETERS = {"python", "python3", "node", "ruby", "perl"}

    try:
        monitor = ResourceMonitor()
        instances = monitor.scan_once()
        for inst in instances:
            if inst.pid is None:
                continue
            launcher = inst.extra.get("launcher", {})
            launch_type = launcher.get("launch_type") or inst.launched_by

            if launch_type == "unknown":
                results.append(AuditResult(
                    check=f"Suspicious Launcher ({inst.name})",
                    status="warn",
                    detail=f"Agent '{inst.name}' (PID {inst.pid}) has unknown launch type",
                    severity="low",
                    category="processes",
                ))
            elif inst.parent_name and inst.parent_name in _SCRIPT_INTERPRETERS:
                results.append(AuditResult(
                    check=f"Suspicious Launcher ({inst.name})",
                    status="warn",
                    detail=f"Agent '{inst.name}' (PID {inst.pid}) launched by script interpreter '{inst.parent_name}'",
                    severity="medium",
                    category="processes",
                ))
    except Exception:
        pass

    if not results:
        results.append(AuditResult(
            check="Suspicious Launcher",
            status="pass",
            detail="No suspicious launch mechanisms detected.",
            severity="info",
            category="processes",
        ))
    return results


def _check_mcp_stdio_commands() -> list[AuditResult]:
    """Check MCP configs for unsafe stdio commands (shells, temp dirs)."""
    results: list[AuditResult] = []

    for mcp_path in _collect_all_mcp_paths():
        if not mcp_path.is_file():
            continue
        try:
            data = json.loads(mcp_path.read_text())
            servers = data.get("mcpServers", data.get("servers", {}))
            if not isinstance(servers, dict):
                continue
            for name, server_cfg in servers.items():
                if not isinstance(server_cfg, dict):
                    continue
                command = server_cfg.get("command", "")
                args = server_cfg.get("args", [])
                if not isinstance(command, str) or not command:
                    continue
                cmd_base = Path(command).name

                # Flag bare shell with -c
                if cmd_base in _SUSPICIOUS_SHELL_COMMANDS and "-c" in (args if isinstance(args, list) else []):
                    results.append(AuditResult(
                        check=f"MCP Stdio Command ({mcp_path.parent.name})",
                        status="warn",
                        detail=f"MCP server '{name}' runs '{cmd_base} -c ...' — arbitrary command execution",
                        severity="high",
                        category="supply_chain",
                    ))
                elif cmd_base in _SUSPICIOUS_SHELL_COMMANDS:
                    results.append(AuditResult(
                        check=f"MCP Stdio Command ({mcp_path.parent.name})",
                        status="warn",
                        detail=f"MCP server '{name}' spawns a shell ({cmd_base})",
                        severity="high",
                        category="supply_chain",
                    ))

                # Flag temp dir references
                all_parts = command + " " + " ".join(args if isinstance(args, list) else [])
                if "/tmp/" in all_parts or "/tmp" in all_parts:
                    results.append(AuditResult(
                        check=f"MCP Stdio Command ({mcp_path.parent.name})",
                        status="warn",
                        detail=f"MCP server '{name}' references a temp directory",
                        severity="high",
                        category="supply_chain",
                    ))
        except (json.JSONDecodeError, OSError, TypeError):
            pass

    if not results:
        results.append(AuditResult(
            check="MCP Stdio Commands",
            status="pass",
            detail="No unsafe MCP stdio commands found.",
            severity="info",
            category="supply_chain",
        ))
    return results


def _check_config_file_permissions() -> list[AuditResult]:
    """Check individual config file permissions for each installed agent."""
    results: list[AuditResult] = []

    def _check_perm(label: str, fpath: Path) -> None:
        try:
            mode = os.stat(fpath).st_mode
            if mode & 0o077:
                results.append(AuditResult(
                    check=f"Config File Permissions ({label})",
                    status="fail",
                    detail=f"{fpath} is group/other-accessible (mode {oct(stat.S_IMODE(mode))})",
                    severity="high",
                    category="permissions",
                ))
        except OSError:
            pass

    # 1. Standard config files inside each agent's config_dir
    registry = get_default_registry()
    for detector in registry.detectors:
        if not detector.is_installed():
            continue
        config_dir = detector.config_dir
        if not config_dir.is_dir():
            continue
        for fname in _CONFIG_FILENAMES:
            fpath = config_dir / fname
            if fpath.is_file():
                _check_perm(detector.agent_name, fpath)

    # 2. Extra paths (VS Code extensions, macOS App Support)
    for label, fpath in _collect_extra_config_paths():
        _check_perm(label, fpath)

    if not results:
        results.append(AuditResult(
            check="Config File Permissions",
            status="pass",
            detail="All agent config files have safe permissions.",
            severity="info",
            category="permissions",
        ))
    return results


# ---------------------------------------------------------------------------
# Network-dependent checks (require --network flag)
# ---------------------------------------------------------------------------

def _get_running_network_data() -> list[tuple[str, list[dict]]]:
    """Collect network data from currently running agents."""
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
