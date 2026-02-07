"""Cline (Claude Dev) agent detector."""

from __future__ import annotations

import json
from pathlib import Path

from riva.agents.base import AgentDetector


class ClineDetector(AgentDetector):
    """Detect Cline (formerly Claude Dev) VS Code extension."""

    @property
    def agent_name(self) -> str:
        return "Cline"

    @property
    def binary_names(self) -> list[str]:
        return ["cline"]

    @property
    def config_dir(self) -> Path:
        # Cline stores state in VS Code extension directory
        return Path.home() / ".vscode" / "extensions"

    @property
    def api_domain(self) -> str:
        return "api.anthropic.com"

    def _find_extension_dir(self) -> Path | None:
        """Find the Cline/Claude Dev extension directory."""
        ext_dir = self.config_dir
        if not ext_dir.is_dir():
            return None
        try:
            # Look for saoudrizwan.claude-dev-* extensions
            dirs = sorted(
                [d for d in ext_dir.iterdir() if d.name.startswith("saoudrizwan.claude-dev") and d.is_dir()],
                key=lambda p: p.name,
                reverse=True,
            )
            return dirs[0] if dirs else None
        except OSError:
            return None

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        # Cline is extension-only, no standalone process
        # But it may spawn helper processes
        if cmdline:
            joined = " ".join(cmdline)
            if "claude-dev" in joined or "saoudrizwan.claude-dev" in joined:
                return True
        return False

    def is_installed(self) -> bool:
        return self._find_extension_dir() is not None

    def parse_config(self) -> dict:
        config: dict = {}

        ext_dir = self._find_extension_dir()
        if ext_dir:
            config["extension_dir"] = str(ext_dir)

            # Extract version from package.json
            pkg_json = ext_dir / "package.json"
            if pkg_json.is_file():
                try:
                    pkg = json.loads(pkg_json.read_text())
                    config["version"] = pkg.get("version", "unknown")
                    config["display_name"] = pkg.get("displayName", "Cline")
                except (json.JSONDecodeError, OSError):
                    pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return ClineDetector()
