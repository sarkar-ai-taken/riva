"""Windsurf (Codeium) agent detector."""

from __future__ import annotations

import json
from pathlib import Path

from riva.agents.base import AgentDetector, filter_secrets


class WindsurfDetector(AgentDetector):
    """Detect Windsurf IDE (Codeium-powered editor)."""

    @property
    def agent_name(self) -> str:
        return "Windsurf"

    @property
    def binary_names(self) -> list[str]:
        return ["windsurf", "Windsurf"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".codeium"

    @property
    def api_domain(self) -> str:
        return "api.codeium.com"

    def _app_support_dir(self) -> Path:
        """macOS Application Support directory for Windsurf."""
        return Path.home() / "Library" / "Application Support" / "Windsurf"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Check exe path for Windsurf.app on macOS
        if exe and "Windsurf" in exe:
            return True
        # Windsurf Helper processes
        if "Windsurf Helper" in name:
            return True
        return False

    def is_installed(self) -> bool:
        if self.config_dir.exists():
            return True
        if self._app_support_dir().exists():
            return True
        # macOS app bundle
        if Path("/Applications/Windsurf.app").exists():
            return True
        return super().is_installed()

    def parse_config(self) -> dict:
        config: dict = {}

        # Check ~/.codeium config
        codeium_config = self._parse_json_config("config.json")
        if codeium_config:
            config["codeium_settings"] = codeium_config

        # Check Application Support directory (macOS)
        app_support = self._app_support_dir()
        if app_support.is_dir():
            config["app_support_dir"] = str(app_support)

            # User settings
            user_settings = app_support / "User" / "settings.json"
            if user_settings.is_file():
                try:
                    data = json.loads(user_settings.read_text())
                    config["user_settings"] = filter_secrets(data)
                except (json.JSONDecodeError, OSError):
                    pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


    def parse_skills(self) -> list:
        """Discover Windsurf global memories and local .windsurfrules as skills.

        Reads:
        - ~/.codeium/windsurf/memories/*.md  (global memories / persistent rules)
        - .windsurfrules in cwd  (project-level rules file)
        """
        from riva.core.skills import Skill

        skills: list[Skill] = []

        # Global memories
        memories_dir = self.config_dir / "windsurf" / "memories"
        if memories_dir.is_dir():
            try:
                for f in sorted(memories_dir.glob("*.md")):
                    skill_id = f"windsurf-{f.stem.lower().replace(' ', '-')}"
                    description = ""
                    try:
                        for line in f.read_text(errors="replace").splitlines():
                            stripped = line.strip().lstrip("#").strip()
                            if stripped:
                                description = stripped[:120]
                                break
                    except OSError:
                        pass
                    skills.append(Skill(
                        id=skill_id,
                        name=f.stem,
                        description=description,
                        agent=self.agent_name,
                        invocation=None,
                        tags=["memory"],
                        workspace=None,
                    ))
            except OSError:
                pass

        # Project .windsurfrules
        rules_file = Path.cwd() / ".windsurfrules"
        if rules_file.is_file():
            try:
                first_line = ""
                for line in rules_file.read_text(errors="replace").splitlines():
                    stripped = line.strip().lstrip("#").strip()
                    if stripped:
                        first_line = stripped[:120]
                        break
                skills.append(Skill(
                    id="windsurf-project-rules",
                    name=".windsurfrules",
                    description=first_line,
                    agent=self.agent_name,
                    invocation=None,
                    tags=["rule"],
                    workspace=str(Path.cwd()),
                ))
            except OSError:
                pass

        return skills


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return WindsurfDetector()
