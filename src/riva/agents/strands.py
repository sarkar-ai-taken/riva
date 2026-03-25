"""Strands Agents detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector


class StrandsDetector(AgentDetector):
    """Detect Strands Agents (AWS open-source agent SDK).

    Strands agents run as Python processes that import the ``strands``
    package.  There is no dedicated CLI binary; detection relies on matching
    ``python`` processes whose command line references the framework.
    """

    @property
    def agent_name(self) -> str:
        return "Strands"

    @property
    def binary_names(self) -> list[str]:
        return ["strands"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".strands"

    @property
    def api_domain(self) -> str:
        return "bedrock-runtime.amazonaws.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Match Python processes running strands modules
        if name in ("python", "python3") and cmdline:
            joined = " ".join(cmdline)
            if "strands" in joined:
                return True
        return False

    def parse_config(self) -> dict:
        config: dict = {}

        settings = self._parse_json_config("config.json")
        if settings:
            config["settings"] = settings

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return StrandsDetector()
