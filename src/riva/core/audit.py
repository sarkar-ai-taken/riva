"""Security audit checks for Riva."""

from __future__ import annotations

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


def run_audit() -> list[AuditResult]:
    """Run all security audit checks and return results."""
    results: list[AuditResult] = []
    results.extend(_check_api_key_exposure())
    results.extend(_check_config_dir_permissions())
    results.extend(_check_dashboard_status())
    results.extend(_check_plugin_directory())
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
        )]
    return [AuditResult(
        check="API Key Exposure",
        status="pass",
        detail="No API keys or secrets found in environment variables.",
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
                ))
            else:
                results.append(AuditResult(
                    check=f"Config Permissions ({detector.agent_name})",
                    status="pass",
                    detail=f"{config_dir} permissions OK ({oct(stat.S_IMODE(mode))})",
                ))
        except OSError as exc:
            results.append(AuditResult(
                check=f"Config Permissions ({detector.agent_name})",
                status="warn",
                detail=f"Could not stat {config_dir}: {exc}",
            ))
    if not results:
        results.append(AuditResult(
            check="Config Permissions",
            status="pass",
            detail="No installed agents with config directories found.",
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
        )]
    # The daemon status doesn't store host info, so we warn that it's running
    # and users should verify the bind address.
    return [AuditResult(
        check="Dashboard Status",
        status="warn",
        detail=f"Web dashboard is running (PID {info['pid']}). "
               "Verify it is not bound to a non-localhost address without authentication.",
    )]


def _check_plugin_directory() -> list[AuditResult]:
    """Check the plugin directory for security concerns."""
    plugin_dir = Path("~/.config/riva/plugins").expanduser()
    if not plugin_dir.exists():
        return [AuditResult(
            check="Plugin Directory",
            status="pass",
            detail="Plugin directory does not exist.",
        )]
    results: list[AuditResult] = [AuditResult(
        check="Plugin Directory",
        status="warn",
        detail=f"{plugin_dir} exists — arbitrary code can be loaded from plugins.",
    )]
    try:
        mode = os.stat(plugin_dir).st_mode
        if mode & 0o077:
            results.append(AuditResult(
                check="Plugin Directory Permissions",
                status="fail",
                detail=f"{plugin_dir} is group/other-accessible (mode {oct(stat.S_IMODE(mode))})",
            ))
        else:
            results.append(AuditResult(
                check="Plugin Directory Permissions",
                status="pass",
                detail=f"{plugin_dir} permissions OK ({oct(stat.S_IMODE(mode))})",
            ))
    except OSError as exc:
        results.append(AuditResult(
            check="Plugin Directory Permissions",
            status="warn",
            detail=f"Could not stat {plugin_dir}: {exc}",
        ))
    return results
