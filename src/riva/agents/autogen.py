"""AutoGen (Microsoft) agent detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector


class AutoGenDetector(AgentDetector):
    """Detect Microsoft AutoGen agents.

    AutoGen agents run as Python processes using the ``autogen`` or
    ``autogen-agentchat`` packages.  Detection matches Python processes
    with ``autogen`` in their command line.
    """

    @property
    def agent_name(self) -> str:
        return "AutoGen"

    @property
    def binary_names(self) -> list[str]:
        return ["autogen"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".autogen"

    @property
    def api_domain(self) -> str:
        return "varies"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Match Python processes running autogen modules
        if name in ("python", "python3") and cmdline:
            joined = " ".join(cmdline)
            if "autogen" in joined:
                return True
        return False

    def parse_config(self) -> dict:
        config: dict = {}

        # AutoGen uses OAI_CONFIG_LIST as a JSON config file
        settings = self._parse_json_config("OAI_CONFIG_LIST")
        if settings:
            config["settings"] = settings

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return AutoGenDetector()
