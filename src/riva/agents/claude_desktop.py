"""Claude Desktop (GUI app) agent detector.

Distinct from the ``claude_code`` detector, which targets the ``claude`` CLI.
Claude Desktop is the Anthropic-published desktop app (Electron) installed as
``Claude.app`` on macOS, ``Claude.exe`` on Windows, and ``Claude`` on Linux.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from riva.agents.base import AgentDetector, filter_secrets
from riva.core.skills import Skill


class ClaudeDesktopDetector(AgentDetector):
    """Detect the Claude Desktop app."""

    @property
    def agent_name(self) -> str:
        return "Claude Desktop"

    @property
    def binary_names(self) -> list[str]:
        # Exact (case-sensitive) names — the lowercase ``claude`` CLI is owned
        # by the separate claude_code detector, so we must not match it.
        return [
            "Claude",
            "Claude Helper",
            "Claude Helper (Renderer)",
            "Claude Helper (GPU)",
            "Claude Helper (Plugin)",
            "Claude.exe",
        ]

    @property
    def config_dir(self) -> Path:
        if sys.platform == "darwin":
            return Path.home() / "Library" / "Application Support" / "Claude"
        if sys.platform == "win32":
            import os

            appdata = os.environ.get("APPDATA")
            if appdata:
                return Path(appdata) / "Claude"
            return Path.home() / "AppData" / "Roaming" / "Claude"
        return Path.home() / ".config" / "Claude"

    @property
    def api_domain(self) -> str:
        return "api.anthropic.com"

    def _app_bundle_path(self) -> Path | None:
        """Return the platform-specific install path if it exists."""
        if sys.platform == "darwin":
            p = Path("/Applications/Claude.app")
            return p if p.exists() else None
        if sys.platform == "win32":
            import os

            for env_key in ("LOCALAPPDATA", "PROGRAMFILES"):
                base = os.environ.get(env_key)
                if not base:
                    continue
                candidate = Path(base) / "Claude" / "Claude.exe"
                if candidate.exists():
                    return candidate
        return None

    def is_installed(self) -> bool:
        if self._app_bundle_path() is not None:
            return True
        if self.config_dir.exists():
            return True
        return False

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Electron helper processes on macOS don't always carry "Claude" in
        # the process name, but ``--user-data-dir`` points at our config dir.
        if cmdline and any("Application Support/Claude" in a for a in cmdline):
            return True
        if exe and "/Claude.app/" in exe:
            return True
        return False

    # ------------------------------------------------------------------
    # Configuration
    # ------------------------------------------------------------------

    def parse_config(self) -> dict:
        config: dict = {"config_dir": str(self.config_dir), "installed": self.is_installed()}

        # Main MCP-server config
        mcp_file = self.config_dir / "claude_desktop_config.json"
        try:
            if mcp_file.exists():
                raw = json.loads(mcp_file.read_text())
                mcp_servers = raw.get("mcpServers") or {}
                config["mcp_servers"] = sorted(mcp_servers.keys())
                prefs = raw.get("preferences")
                if isinstance(prefs, dict):
                    config["preferences"] = filter_secrets(prefs)
        except (json.JSONDecodeError, OSError):
            config["_error"] = "Could not parse claude_desktop_config.json"

        # General app settings
        prefs_file = self.config_dir / "config.json"
        try:
            if prefs_file.exists():
                raw = json.loads(prefs_file.read_text())
                if isinstance(raw, dict):
                    # Drop internal Electron caches that explode the output
                    trimmed = {
                        k: v
                        for k, v in raw.items()
                        if not k.startswith("dxt:allowlistCache") and not k.startswith("dxt:allowlistLastUpdated")
                    }
                    config["settings"] = filter_secrets(trimmed)
        except (json.JSONDecodeError, OSError):
            pass

        bundle = self._app_bundle_path()
        if bundle:
            config["app_path"] = str(bundle)

        return config

    # ------------------------------------------------------------------
    # Skills
    # ------------------------------------------------------------------

    def parse_skills(self) -> list[Skill]:
        """Discover Claude Desktop skills.

        Claude Desktop installs skills under
        ``<config_dir>/local-agent-mode-sessions/skills-plugin/<org-uuid>/
        <plugin-uuid>/skills/<skill-name>/SKILL.md``.
        """
        skills: list[Skill] = []
        seen_ids: set[str] = set()

        plugin_root = self.config_dir / "local-agent-mode-sessions" / "skills-plugin"
        if not plugin_root.is_dir():
            return skills

        try:
            skill_files = sorted(plugin_root.glob("*/*/skills/*/SKILL.md"))
        except OSError:
            return skills

        for skill_file in skill_files:
            skill_dir = skill_file.parent
            name = skill_dir.name
            description = ""

            try:
                text = skill_file.read_text(errors="replace")
            except OSError:
                continue

            lines = text.splitlines()
            if lines and lines[0].strip() == "---":
                for line in lines[1:]:
                    if line.strip() == "---":
                        break
                    if line.startswith("name:"):
                        name = line.split(":", 1)[1].strip().strip('"')
                    elif line.startswith("description:"):
                        description = line.split(":", 1)[1].strip().strip('"')[:120]

            skill_id = name.lower().replace(" ", "-")
            if skill_id in seen_ids:
                continue
            seen_ids.add(skill_id)
            skills.append(
                Skill(
                    id=skill_id,
                    name=name,
                    description=description,
                    agent=self.agent_name,
                    invocation=None,
                    tags=["skill"],
                    file_path=str(skill_file),
                )
            )

        return skills


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return ClaudeDesktopDetector()
