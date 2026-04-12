"""Kiro (AWS AI IDE) agent detector."""

from __future__ import annotations

from pathlib import Path

from riva.agents.base import AgentDetector
from riva.core.skills import Skill


class KiroDetector(AgentDetector):
    """Detect and parse Kiro — AWS's AI-powered IDE."""

    @property
    def agent_name(self) -> str:
        return "Kiro"

    @property
    def binary_names(self) -> list[str]:
        return ["kiro"]

    @property
    def config_dir(self) -> Path:
        return Path.home() / ".kiro"

    @property
    def api_domain(self) -> str:
        return "api.kiro.aws"

    def match_process(self, name: str, cmdline: list[str], exe: str) -> bool:
        if self._match_by_name(name, cmdline, exe):
            return True
        # Kiro runs as Electron — match on exe path containing "kiro"
        if exe and "kiro" in exe.lower():
            return True
        # Match electron processes with kiro in the cmdline
        if cmdline and any("kiro" in arg.lower() for arg in cmdline[:3]):
            return True
        return False

    def parse_config(self) -> dict:
        config: dict = {}

        # Main settings
        settings = self._parse_json_config("settings.json")
        if settings:
            config["settings"] = settings

        # Auth / profile
        auth = self._parse_json_config("auth.json")
        if auth:
            config["auth"] = auth

        # MCP servers config
        mcp = self._parse_json_config("mcp.json")
        if mcp:
            config["mcp"] = mcp

        # Check for .kiro/hooks/ (spec hooks similar to Claude's custom commands)
        hooks_dir = self.config_dir / "hooks"
        if hooks_dir.is_dir():
            try:
                hook_files = list(hooks_dir.glob("*.md")) + list(hooks_dir.glob("*.yaml")) + list(hooks_dir.glob("*.yml"))
                config["hooks_count"] = len(hook_files)
            except OSError:
                pass

        # Check for steering files (.kiro/steering/)
        steering_dir = self.config_dir / "steering"
        if steering_dir.is_dir():
            try:
                steering_files = list(steering_dir.glob("*.md"))
                config["steering_count"] = len(steering_files)
            except OSError:
                pass

        config["config_dir"] = str(self.config_dir)
        config["installed"] = self.is_installed()
        return config

    def write_skill(self, skill, workspace=None):
        """Write a skill as a ~/.kiro/specs/<name>.md file."""
        base = Path(workspace) if workspace else self.config_dir
        specs_dir = base / "specs" if (base / "specs").parent == base else base / ".kiro" / "specs"
        # Use ~/.kiro/specs/ for global, or workspace/.kiro/specs/ for project
        if workspace:
            specs_dir = Path(workspace) / ".kiro" / "specs"
        else:
            specs_dir = self.config_dir / "specs"
        specs_dir.mkdir(parents=True, exist_ok=True)

        filename = skill.id.lower().replace(" ", "-") + ".md"
        path = specs_dir / filename

        lines = [f"# {skill.name}", ""]
        if skill.description:
            lines.append(skill.description)
            lines.append("")
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def parse_skills(self) -> list[Skill]:
        """Discover Kiro skills from hooks and specs directories.

        Kiro supports:
        - `.kiro/hooks/` — hook markdown files (agent-executed on events)
        - `.kiro/specs/` — spec files (feature requirements / workflows)
        """
        skills: list[Skill] = []

        for subdir, tag in [("hooks", "hook"), ("specs", "spec")]:
            d = self.config_dir / subdir
            if not d.is_dir():
                continue
            try:
                for md_file in sorted(d.glob("*.md")):
                    skill_id = f"kiro-{md_file.stem.lower().replace(' ', '-')}"
                    description = ""
                    try:
                        for line in md_file.read_text(errors="replace").splitlines():
                            line = line.strip().lstrip("#").strip()
                            if line:
                                description = line[:120]
                                break
                    except OSError:
                        pass
                    skills.append(
                        Skill(
                            id=skill_id,
                            name=md_file.stem,
                            description=description,
                            agent=self.agent_name,
                            invocation=None,
                            tags=[tag],
                            workspace=str(self.config_dir),
                        )
                    )
            except OSError:
                pass

        return skills


def create_detector() -> AgentDetector:
    """Plugin entry point."""
    return KiroDetector()
