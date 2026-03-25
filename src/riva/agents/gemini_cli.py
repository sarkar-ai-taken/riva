"""Gemini CLI (Google) agent detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector


class GeminiCLIDetector(AgentDetector):
    """Detect and parse Google Gemini CLI."""

    @property
    def agent_name(self) -> str:
        return "Gemini CLI"

    @property
    def binary_names(self) -> list[str]:
        return ["gemini"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".gemini"

    @property
    def api_domain(self) -> str:
        return "generativelanguage.googleapis.com"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Gemini CLI also runs as a Node.js script
        if name == "node" and cmdline:
            cmdline_str = " ".join(cmdline)
            if "gemini-cli" in cmdline_str or "@google/gemini" in cmdline_str:
                return True
        return False

    def parse_config(self) -> dict:
        config: dict = {}

        settings = self._parse_json_config("settings.json")
        if settings:
            config["settings"] = settings

        extra = self._parse_json_config("config.json")
        if extra:
            config["config"] = extra

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config


    def parse_skills(self) -> list:
        """Discover Gemini CLI instruction files as skills.

        Reads:
        - ~/.gemini/GEMINI.md  (global system instructions)
        - GEMINI.md in cwd  (project-level instructions)
        """
        from riva.core.skills import Skill

        skills: list[Skill] = []

        for f, workspace in [
            (self.config_dir / "GEMINI.md", None),
            (Path.cwd() / "GEMINI.md", str(Path.cwd())),
        ]:
            if not f.is_file():
                continue
            try:
                description = ""
                for line in f.read_text(errors="replace").splitlines():
                    stripped = line.strip().lstrip("#").strip()
                    if stripped:
                        description = stripped[:120]
                        break
                skill_id = "gemini-instructions" if workspace is None else "gemini-project-instructions"
                skills.append(Skill(
                    id=skill_id,
                    name="GEMINI.md",
                    description=description,
                    agent=self.agent_name,
                    invocation=None,
                    tags=["instruction"],
                    workspace=workspace,
                    file_path=str(f),
                ))
            except OSError:
                pass

        return skills


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return GeminiCLIDetector()
