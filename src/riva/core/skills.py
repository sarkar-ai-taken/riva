"""Skill definitions and forensic linkage for AI agent workflows.

Skills are named, reusable agent workflows (slash commands, prompt patterns,
tool sequences) that can be tracked across sessions, linked to forensic data,
and shared between agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class SkillForensicStats:
    """Forensic stats for a skill derived from session transcripts."""

    usage_count: int = 0
    success_count: int = 0
    backtrack_count: int = 0
    avg_tokens: float = 0.0
    avg_actions: float = 0.0
    last_used: str | None = None

    @property
    def success_rate(self) -> float:
        return self.success_count / self.usage_count if self.usage_count else 0.0

    @property
    def backtrack_rate(self) -> float:
        return self.backtrack_count / self.usage_count if self.usage_count else 0.0


@dataclass
class Skill:
    """A reusable agent skill or command."""

    id: str
    name: str
    description: str = ""
    agent: str | None = None        # None = shared across all agents
    invocation: str | None = None   # trigger pattern, e.g. "/commit"
    tags: list[str] = field(default_factory=list)
    shared: bool = False
    source_agent: str | None = None  # original agent if imported/shared
    workspace: str | None = None     # workspace path; None = global
    created_at: str | None = None
    forensic_stats: SkillForensicStats = field(default_factory=SkillForensicStats)
    extra: dict = field(default_factory=dict)

    @property
    def display_agent(self) -> str:
        return self.agent or "shared"

    @property
    def trigger(self) -> str:
        return self.invocation or self.name


# ---------------------------------------------------------------------------
# TOML loading / saving
# ---------------------------------------------------------------------------


def load_workspace_skills(workspace_dir: Path | None) -> list[Skill]:
    """Load skills from .riva/skills.toml in the given workspace directory."""
    if not workspace_dir:
        return []
    skills_file = workspace_dir / "skills.toml"
    if not skills_file.exists():
        return []
    try:
        import tomllib

        data = tomllib.loads(skills_file.read_text())
        return _parse_skills_toml(data, workspace=str(workspace_dir))
    except Exception:
        return []


def load_global_skills() -> list[Skill]:
    """Load skills from ~/.riva/skills.toml (global, cross-workspace)."""
    skills_file = Path.home() / ".riva" / "skills.toml"
    if not skills_file.exists():
        return []
    try:
        import tomllib

        data = tomllib.loads(skills_file.read_text())
        return _parse_skills_toml(data, workspace=None)
    except Exception:
        return []


def save_global_skills(skills: list[Skill]) -> None:
    """Persist skills to ~/.riva/skills.toml."""
    skills_dir = Path.home() / ".riva"
    skills_dir.mkdir(parents=True, exist_ok=True)
    (skills_dir / "skills.toml").write_text(export_skills_toml(skills))


def save_workspace_skills(skills: list[Skill], workspace_dir: Path) -> None:
    """Persist skills to .riva/skills.toml in the given workspace."""
    workspace_dir.mkdir(parents=True, exist_ok=True)
    (workspace_dir / "skills.toml").write_text(export_skills_toml(skills))


def _parse_skills_toml(data: dict, workspace: str | None) -> list[Skill]:
    skills = []
    for sid, entry in data.get("skill", {}).items():
        if not isinstance(entry, dict):
            continue
        skills.append(
            Skill(
                id=sid,
                name=entry.get("name", sid),
                description=entry.get("description", ""),
                agent=entry.get("agent"),
                invocation=entry.get("invocation"),
                tags=entry.get("tags", []),
                shared=entry.get("shared", False),
                source_agent=entry.get("source_agent"),
                workspace=workspace,
                created_at=entry.get("created_at"),
            )
        )
    return skills


def export_skills_toml(skills: list[Skill]) -> str:
    """Serialize a list of skills to TOML text."""
    lines: list[str] = []
    for skill in skills:
        lines.append(f"[skill.{skill.id}]")
        lines.append(f"name = {_toml_str(skill.name)}")
        if skill.description:
            lines.append(f"description = {_toml_str(skill.description)}")
        if skill.agent:
            lines.append(f"agent = {_toml_str(skill.agent)}")
        if skill.invocation:
            lines.append(f"invocation = {_toml_str(skill.invocation)}")
        if skill.tags:
            tags_str = ", ".join(f'"{t}"' for t in skill.tags)
            lines.append(f"tags = [{tags_str}]")
        if skill.shared:
            lines.append("shared = true")
        if skill.source_agent:
            lines.append(f"source_agent = {_toml_str(skill.source_agent)}")
        if skill.created_at:
            lines.append(f"created_at = {_toml_str(skill.created_at)}")
        lines.append("")
    return "\n".join(lines)


def _toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


# ---------------------------------------------------------------------------
# Forensic stat computation from raw invocation rows
# ---------------------------------------------------------------------------


def compute_forensic_stats(invocations: list[dict]) -> SkillForensicStats:
    """Compute SkillForensicStats from a list of invocation dicts.

    Each dict must have keys: had_backtrack, token_count, action_count,
    success, timestamp (optional).
    """
    if not invocations:
        return SkillForensicStats()

    usage = len(invocations)
    success = sum(1 for i in invocations if i.get("success", 1))
    backtracks = sum(1 for i in invocations if i.get("had_backtrack", 0))
    avg_tokens = sum(i.get("token_count", 0) for i in invocations) / usage
    avg_actions = sum(i.get("action_count", 0) for i in invocations) / usage

    timestamps = [i["timestamp"] for i in invocations if i.get("timestamp")]
    last_used = max(timestamps) if timestamps else None

    return SkillForensicStats(
        usage_count=usage,
        success_count=success,
        backtrack_count=backtracks,
        avg_tokens=round(avg_tokens, 1),
        avg_actions=round(avg_actions, 1),
        last_used=last_used,
    )
