"""LangGraph agent detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector


class LangGraphDetector(AgentDetector):
    """Detect LangGraph / LangChain agents.

    LangGraph agents typically run as Python processes that import
    ``langgraph`` or ``langchain``.  There is no dedicated CLI binary;
    detection relies on matching ``python`` processes whose command line
    references the framework modules.
    """

    @property
    def agent_name(self) -> str:
        return "LangGraph"

    @property
    def binary_names(self) -> list[str]:
        return ["langgraph"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".langgraph"

    @property
    def api_domain(self) -> str:
        return "api.smith.langchain.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Match Python processes running langgraph/langchain modules
        if name in ("python", "python3") and cmdline:
            joined = " ".join(cmdline)
            if "langgraph" in joined or "langchain" in joined:
                return True
        return False

    def parse_config(self) -> dict:
        config: dict = {}

        # langgraph.json is the standard LangGraph project config
        settings = self._parse_json_config("langgraph.json")
        if settings:
            config["settings"] = settings

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return LangGraphDetector()
