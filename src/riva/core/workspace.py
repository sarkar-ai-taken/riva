"""Workspace discovery and configuration loading from .riva/ directories."""

from __future__ import annotations

import logging
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

RIVA_DIR_NAME = ".riva"
CONFIG_FILE = "config.toml"
LOCAL_CONFIG_FILE = "config.local.toml"
AGENTS_DIR = "agents"


def find_workspace(start_path: Path | str | None = None) -> Path | None:
    """Walk upward from *start_path* to find the nearest ``.riva/`` folder.

    Returns the ``.riva/`` directory path, or ``None`` if not found.
    Similar to how Git discovers ``.git/``.
    """
    current = Path(start_path or Path.cwd()).resolve()
    while True:
        candidate = current / RIVA_DIR_NAME
        if candidate.is_dir():
            return candidate
        parent = current.parent
        if parent == current:
            break
        current = parent
    return None


def _slugify_agent_name(name: str) -> str:
    """Convert an agent display name to a filename slug.

    Example: ``"Claude Code"`` -> ``"claude-code"``
    """
    slug = name.lower().strip()
    slug = re.sub(r"[^a-z0-9]+", "-", slug)
    return slug.strip("-")


def _merge_toml(base: dict, override: dict) -> dict:
    """Deep-merge *override* into *base*.

    - Dicts are recursively merged.
    - Scalars and lists in *override* replace values in *base*.
    """
    merged = dict(base)
    for key, value in override.items():
        if key in merged and isinstance(merged[key], dict) and isinstance(value, dict):
            merged[key] = _merge_toml(merged[key], value)
        else:
            merged[key] = value
    return merged


@dataclass
class WorkspaceConfig:
    """Typed access to the parsed workspace configuration."""

    root_dir: Path
    riva_dir: Path

    # [workspace]
    name: str = ""
    scan_interval: float = 2.0

    # [agents]
    enabled_agents: list[str] = field(default_factory=list)
    disabled_agents: list[str] = field(default_factory=list)

    # [hooks]
    hooks_enabled: bool = True
    hooks_timeout: int = 30

    # [rules]
    rules_injection_mode: str = "manual"  # manual | on_detect | disabled
    rules_targets: list[str] = field(default_factory=list)

    # [audit]
    audit_custom_checks: list[str] = field(default_factory=list)
    audit_disabled_checks: list[str] = field(default_factory=list)

    # [otel]
    otel_enabled: bool = False
    otel_endpoint: str = "http://localhost:4318"
    otel_protocol: str = "http"
    otel_headers: dict = field(default_factory=dict)
    otel_service_name: str = "riva"
    otel_export_interval: float = 5.0
    otel_metrics: bool = True
    otel_logs: bool = True
    otel_traces: bool = False

    # Raw merged dict for advanced access
    metadata: dict = field(default_factory=dict)


def load_workspace_config(riva_dir: Path) -> WorkspaceConfig:
    """Parse ``config.toml`` and deep-merge ``config.local.toml`` on top.

    Returns a :class:`WorkspaceConfig` with typed fields.
    """
    config_path = riva_dir / CONFIG_FILE
    local_path = riva_dir / LOCAL_CONFIG_FILE

    base: dict = {}
    if config_path.is_file():
        try:
            base = tomllib.loads(config_path.read_text())
        except Exception:
            logger.warning("Failed to parse %s", config_path, exc_info=True)

    local: dict = {}
    if local_path.is_file():
        try:
            local = tomllib.loads(local_path.read_text())
        except Exception:
            logger.warning("Failed to parse %s", local_path, exc_info=True)

    merged = _merge_toml(base, local) if local else base

    ws = merged.get("workspace", {})
    agents = merged.get("agents", {})
    hooks = merged.get("hooks", {})
    rules = merged.get("rules", {})
    audit = merged.get("audit", {})
    otel = merged.get("otel", {})

    root_dir = riva_dir.parent

    return WorkspaceConfig(
        root_dir=root_dir,
        riva_dir=riva_dir,
        name=ws.get("name", root_dir.name),
        scan_interval=float(ws.get("scan_interval", 2.0)),
        enabled_agents=list(agents.get("enabled", [])),
        disabled_agents=list(agents.get("disabled", [])),
        hooks_enabled=bool(hooks.get("enabled", True)),
        hooks_timeout=int(hooks.get("timeout", 30)),
        rules_injection_mode=str(rules.get("injection_mode", "manual")),
        rules_targets=list(rules.get("targets", [])),
        audit_custom_checks=list(audit.get("custom_checks", [])),
        audit_disabled_checks=list(audit.get("disabled_checks", [])),
        otel_enabled=bool(otel.get("enabled", False)),
        otel_endpoint=str(otel.get("endpoint", "http://localhost:4318")),
        otel_protocol=str(otel.get("protocol", "http")),
        otel_headers=dict(otel.get("headers", {})),
        otel_service_name=str(otel.get("service_name", "riva")),
        otel_export_interval=float(otel.get("export_interval", 5.0)),
        otel_metrics=bool(otel.get("metrics", True)),
        otel_logs=bool(otel.get("logs", True)),
        otel_traces=bool(otel.get("traces", False)),
        metadata=merged,
    )


def load_agent_config(riva_dir: Path, agent_name: str) -> dict:
    """Load per-agent overrides from ``.riva/agents/<slug>.toml``.

    Returns an empty dict if the file does not exist.
    """
    slug = _slugify_agent_name(agent_name)
    agent_path = riva_dir / AGENTS_DIR / f"{slug}.toml"
    if not agent_path.is_file():
        return {}
    try:
        return tomllib.loads(agent_path.read_text())
    except Exception:
        logger.warning("Failed to parse agent config %s", agent_path, exc_info=True)
        return {}
