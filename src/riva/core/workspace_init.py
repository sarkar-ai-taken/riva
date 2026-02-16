"""Scaffold a new .riva/ workspace directory."""

from __future__ import annotations

from pathlib import Path

from riva.core.workspace import RIVA_DIR_NAME, _slugify_agent_name

_DEFAULT_CONFIG = """\
[workspace]
name = "{name}"
scan_interval = 2.0

[agents]
enabled = [{agents_list}]
disabled = []

[hooks]
enabled = true
timeout = 30

[rules]
injection_mode = "manual"   # manual | on_detect | disabled
targets = []

[audit]
custom_checks = []
disabled_checks = []

# [otel]
# enabled = true
# endpoint = "http://localhost:4318"
# protocol = "http"
# service_name = "riva"
# export_interval = 5.0
# metrics = true
# logs = true
# traces = false
# [otel.headers]
# Authorization = "Bearer <token>"
"""

_GITIGNORE = """\
# Riva workspace — local overrides (not committed)
config.local.toml
"""

_HOOK_TEMPLATE_SH = """\
#!/usr/bin/env bash
# Riva hook: {event}
# Receives JSON context on stdin.
# Exit 0 for success, non-zero for failure.

set -euo pipefail

CONTEXT=$(cat)
echo "[riva:{event}] hook triggered"
"""

_HOOK_TEMPLATE_PY = """\
\"\"\"Riva hook: {event}.\"\"\"


def run(context: dict) -> None:
    \"\"\"Called by Riva with event context.\"\"\"
    print(f"[riva:{event}] hook triggered")
"""

_DETECTOR_TEMPLATE = """\
\"\"\"Workspace-scoped agent detector.\"\"\"

from riva.agents.base import SimpleAgentDetector


def create_detector():
    \"\"\"Return an AgentDetector for this workspace.\"\"\"
    return SimpleAgentDetector(
        name="My Internal Agent",
        binaries=["my-agent"],
        config="/path/to/config",
        api="api.example.com",
    )
"""

_RULE_TEMPLATE = """\
# {title}

<!-- Add your rules/policies here. These can be injected into AI agents. -->
"""


def init_workspace(
    target_dir: Path | str,
    *,
    agents: list[str] | None = None,
    include_hooks: bool = True,
    include_rules: bool = True,
) -> Path:
    """Create the full ``.riva/`` scaffold with defaults.

    Returns the path to the created ``.riva/`` directory.
    """
    target = Path(target_dir).resolve()
    riva_dir = target / RIVA_DIR_NAME

    riva_dir.mkdir(parents=True, exist_ok=True)

    # config.toml
    agents_list = ""
    if agents:
        agents_list = ", ".join(f'"{a}"' for a in agents)
    config_content = _DEFAULT_CONFIG.format(name=target.name, agents_list=agents_list)
    (riva_dir / "config.toml").write_text(config_content)

    # .gitignore
    (riva_dir / ".gitignore").write_text(_GITIGNORE)

    # agents/ directory
    agents_dir = riva_dir / "agents"
    agents_dir.mkdir(exist_ok=True)
    if agents:
        for agent_name in agents:
            slug = _slugify_agent_name(agent_name)
            agent_file = agents_dir / f"{slug}.toml"
            if not agent_file.exists():
                agent_file.write_text(
                    f"# Per-agent config overrides for {agent_name}\n\n[settings]\n# Add custom settings here\n"
                )

    # hooks/ directory
    if include_hooks:
        hooks_dir = riva_dir / "hooks"
        hooks_dir.mkdir(exist_ok=True)
        on_detected = hooks_dir / "on_agent_detected.sh"
        if not on_detected.exists():
            on_detected.write_text(_HOOK_TEMPLATE_SH.format(event="agent_detected"))
            on_detected.chmod(0o755)

        on_scan = hooks_dir / "on_scan_complete.py"
        if not on_scan.exists():
            on_scan.write_text(_HOOK_TEMPLATE_PY.format(event="scan_complete"))

        on_audit = hooks_dir / "on_audit_finding.sh"
        if not on_audit.exists():
            on_audit.write_text(_HOOK_TEMPLATE_SH.format(event="audit_finding"))
            on_audit.chmod(0o755)

    # detectors/ directory
    detectors_dir = riva_dir / "detectors"
    detectors_dir.mkdir(exist_ok=True)

    # rules/ directory
    if include_rules:
        rules_dir = riva_dir / "rules"
        rules_dir.mkdir(exist_ok=True)
        security_md = rules_dir / "security.md"
        if not security_md.exists():
            security_md.write_text(_RULE_TEMPLATE.format(title="Security Rules"))
        coding_md = rules_dir / "coding-standards.md"
        if not coding_md.exists():
            coding_md.write_text(_RULE_TEMPLATE.format(title="Coding Standards"))

    return riva_dir
