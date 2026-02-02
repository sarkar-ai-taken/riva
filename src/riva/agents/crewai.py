"""CrewAI agent detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector


class CrewAIDetector(AgentDetector):
    """Detect CrewAI agents.

    CrewAI agents run as Python processes using the ``crewai`` package.
    The ``crewai`` CLI is used to create, train, and run crews.
    """

    @property
    def agent_name(self) -> str:
        return "CrewAI"

    @property
    def binary_names(self) -> list[str]:
        return ["crewai"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".crewai"

    @property
    def api_domain(self) -> str:
        return "app.crewai.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Match Python processes running crewai modules
        if name in ("python", "python3") and cmdline:
            joined = " ".join(cmdline)
            if "crewai" in joined:
                return True
        return False

    def parse_config(self) -> dict:
        config: dict = {}

        settings = self._parse_json_config("config.json")
        if settings:
            config["settings"] = settings

        # CrewAI YAML-based config (agents.yaml, tasks.yaml) lives in
        # project directories rather than a global config dir, so we just
        # report what exists in the global dir.
        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return CrewAIDetector()
