"""Tests for the skills system: data model, storage, forensic linkage, CLI, and components."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from riva.core.skills import (
    Skill,
    SkillForensicStats,
    _parse_skills_toml,
    compute_forensic_stats,
    export_skills_toml,
    load_global_skills,
    load_workspace_skills,
    save_global_skills,
    save_workspace_skills,
)
from riva.core.storage import RivaStorage
from riva.core.forensic import (
    _detect_skill_invocation,
    extract_skill_invocations,
    ForensicSession,
    Turn,
    Action,
)
from riva.tui.components import build_skills_panel


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def storage(tmp_path):
    db = RivaStorage(db_path=tmp_path / "test.db")
    yield db
    db.close()


@pytest.fixture
def sample_skill():
    return Skill(
        id="commit",
        name="commit",
        description="Create a git commit",
        agent="Claude Code",
        invocation="/commit",
        tags=["git", "workflow"],
        shared=False,
    )


@pytest.fixture
def shared_skill():
    return Skill(
        id="review",
        name="review",
        description="Review a pull request",
        agent="Claude Code",
        invocation="/review",
        shared=True,
        source_agent="Claude Code",
    )


# ---------------------------------------------------------------------------
# SkillForensicStats
# ---------------------------------------------------------------------------


class TestSkillForensicStats:
    def test_success_rate_zero_usage(self):
        st = SkillForensicStats()
        assert st.success_rate == 0.0

    def test_success_rate(self):
        st = SkillForensicStats(usage_count=4, success_count=3)
        assert st.success_rate == pytest.approx(0.75)

    def test_backtrack_rate_zero_usage(self):
        st = SkillForensicStats()
        assert st.backtrack_rate == 0.0

    def test_backtrack_rate(self):
        st = SkillForensicStats(usage_count=10, backtrack_count=2)
        assert st.backtrack_rate == pytest.approx(0.2)


# ---------------------------------------------------------------------------
# Skill dataclass
# ---------------------------------------------------------------------------


class TestSkill:
    def test_display_agent_with_agent(self, sample_skill):
        assert sample_skill.display_agent == "Claude Code"

    def test_display_agent_shared(self):
        sk = Skill(id="x", name="x", agent=None)
        assert sk.display_agent == "shared"

    def test_trigger_with_invocation(self, sample_skill):
        assert sample_skill.trigger == "/commit"

    def test_trigger_fallback_to_name(self):
        sk = Skill(id="x", name="myskill")
        assert sk.trigger == "myskill"


# ---------------------------------------------------------------------------
# TOML parsing & serialisation
# ---------------------------------------------------------------------------


class TestTomlRoundtrip:
    def test_parse_empty(self):
        assert _parse_skills_toml({}, workspace=None) == []

    def test_parse_single_skill(self):
        data = {
            "skill": {
                "commit": {
                    "name": "Commit",
                    "description": "Git commit",
                    "agent": "Claude Code",
                    "invocation": "/commit",
                    "tags": ["git"],
                    "shared": False,
                }
            }
        }
        skills = _parse_skills_toml(data, workspace="/proj")
        assert len(skills) == 1
        sk = skills[0]
        assert sk.id == "commit"
        assert sk.name == "Commit"
        assert sk.agent == "Claude Code"
        assert sk.invocation == "/commit"
        assert sk.tags == ["git"]
        assert sk.workspace == "/proj"

    def test_parse_ignores_non_dict_entries(self):
        data = {"skill": {"bad": "not a dict"}}
        assert _parse_skills_toml(data, workspace=None) == []

    def test_export_roundtrip(self, sample_skill):
        toml_text = export_skills_toml([sample_skill])
        import tomllib

        parsed = tomllib.loads(toml_text)
        restored = _parse_skills_toml(parsed, workspace=None)
        assert len(restored) == 1
        assert restored[0].id == sample_skill.id
        assert restored[0].name == sample_skill.name
        assert restored[0].invocation == sample_skill.invocation
        assert restored[0].tags == sample_skill.tags

    def test_export_multiple(self, sample_skill, shared_skill):
        toml_text = export_skills_toml([sample_skill, shared_skill])
        import tomllib

        parsed = tomllib.loads(toml_text)
        restored = _parse_skills_toml(parsed, workspace=None)
        assert len(restored) == 2
        ids = {s.id for s in restored}
        assert "commit" in ids
        assert "review" in ids


# ---------------------------------------------------------------------------
# File-based load/save
# ---------------------------------------------------------------------------


class TestLoadSave:
    def test_load_global_skills_missing_file(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        skills = load_global_skills()
        assert skills == []

    def test_save_and_load_global(self, tmp_path, monkeypatch, sample_skill):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        save_global_skills([sample_skill])
        loaded = load_global_skills()
        assert len(loaded) == 1
        assert loaded[0].id == "commit"

    def test_load_workspace_skills_missing_file(self, tmp_path):
        skills = load_workspace_skills(tmp_path)
        assert skills == []

    def test_save_and_load_workspace(self, tmp_path, sample_skill):
        save_workspace_skills([sample_skill], tmp_path)
        loaded = load_workspace_skills(tmp_path)
        assert len(loaded) == 1
        assert loaded[0].id == "commit"
        assert loaded[0].workspace == str(tmp_path)

    def test_load_workspace_bad_toml(self, tmp_path):
        (tmp_path / "skills.toml").write_text("not valid toml [[[")
        skills = load_workspace_skills(tmp_path)
        assert skills == []


# ---------------------------------------------------------------------------
# compute_forensic_stats
# ---------------------------------------------------------------------------


class TestComputeForensicStats:
    def test_empty(self):
        st = compute_forensic_stats([])
        assert st.usage_count == 0
        assert st.success_rate == 0.0

    def test_all_success(self):
        invocations = [
            {"had_backtrack": False, "token_count": 100, "action_count": 5, "success": True, "timestamp": "2026-01-01T10:00:00"},
            {"had_backtrack": False, "token_count": 200, "action_count": 8, "success": True, "timestamp": "2026-01-01T11:00:00"},
        ]
        st = compute_forensic_stats(invocations)
        assert st.usage_count == 2
        assert st.success_count == 2
        assert st.backtrack_count == 0
        assert st.success_rate == 1.0
        assert st.avg_tokens == pytest.approx(150.0)
        assert st.avg_actions == pytest.approx(6.5)
        assert st.last_used == "2026-01-01T11:00:00"

    def test_mixed_results(self):
        invocations = [
            {"had_backtrack": True, "token_count": 50, "action_count": 3, "success": False, "timestamp": "2026-01-01T09:00:00"},
            {"had_backtrack": False, "token_count": 150, "action_count": 6, "success": True, "timestamp": "2026-01-01T10:00:00"},
        ]
        st = compute_forensic_stats(invocations)
        assert st.usage_count == 2
        assert st.success_count == 1
        assert st.backtrack_count == 1
        assert st.success_rate == pytest.approx(0.5)
        assert st.backtrack_rate == pytest.approx(0.5)

    def test_last_used_is_max_timestamp(self):
        invocations = [
            {"had_backtrack": False, "token_count": 0, "action_count": 0, "success": True, "timestamp": "2026-01-03"},
            {"had_backtrack": False, "token_count": 0, "action_count": 0, "success": True, "timestamp": "2026-01-01"},
            {"had_backtrack": False, "token_count": 0, "action_count": 0, "success": True, "timestamp": "2026-01-02"},
        ]
        st = compute_forensic_stats(invocations)
        assert st.last_used == "2026-01-03"


# ---------------------------------------------------------------------------
# Storage — skills tables
# ---------------------------------------------------------------------------


class TestStorageSkills:
    def test_tables_created(self, storage):
        conn = storage._get_conn()
        tables = {row["name"] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "skills" in tables
        assert "skill_invocations" in tables

    def test_upsert_and_get_skill(self, storage, sample_skill):
        storage.upsert_skill(sample_skill)
        skills = storage.get_skills()
        assert len(skills) == 1
        assert skills[0]["id"] == "commit"
        assert skills[0]["name"] == "commit"
        assert skills[0]["agent"] == "Claude Code"
        assert skills[0]["invocation"] == "/commit"
        assert skills[0]["tags"] == ["git", "workflow"]

    def test_upsert_replaces_existing(self, storage, sample_skill):
        storage.upsert_skill(sample_skill)
        sample_skill.description = "Updated description"
        storage.upsert_skill(sample_skill)
        skills = storage.get_skills()
        assert len(skills) == 1
        assert skills[0]["description"] == "Updated description"

    def test_record_and_get_invocation(self, storage):
        storage.record_skill_invocation(
            skill_id="commit",
            session_id="sess-001",
            agent="Claude Code",
            timestamp="2026-03-01T10:00:00",
            had_backtrack=False,
            token_count=500,
            action_count=4,
            success=True,
        )
        invocations = storage.get_skill_invocations("commit")
        assert len(invocations) == 1
        inv = invocations[0]
        assert inv["skill_id"] == "commit"
        assert inv["session_id"] == "sess-001"
        assert inv["token_count"] == 500
        assert inv["success"] == 1
        assert inv["had_backtrack"] == 0

    def test_get_invocations_empty(self, storage):
        assert storage.get_skill_invocations("nonexistent") == []

    def test_get_skills_filter_by_agent(self, storage, sample_skill, shared_skill):
        storage.upsert_skill(sample_skill)
        storage.upsert_skill(shared_skill)
        skills = storage.get_skills(agent="Claude Code")
        assert len(skills) == 2
        skills_other = storage.get_skills(agent="Cursor")
        assert len(skills_other) == 0

    def test_delete_skill(self, storage, sample_skill):
        storage.upsert_skill(sample_skill)
        storage.record_skill_invocation(skill_id="commit", session_id="s1")
        storage.delete_skill("commit")
        assert storage.get_skills() == []
        assert storage.get_skill_invocations("commit") == []

    def test_get_all_skill_invocations(self, storage):
        storage.record_skill_invocation(skill_id="commit", session_id="s1")
        storage.record_skill_invocation(skill_id="review", session_id="s2")
        all_inv = storage.get_all_skill_invocations()
        assert len(all_inv) == 2

    def test_invocation_workspace_isolation(self, storage):
        storage.record_skill_invocation(skill_id="commit", workspace="ws-a", session_id="s1")
        storage.record_skill_invocation(skill_id="commit", workspace="ws-b", session_id="s2")
        assert len(storage.get_skill_invocations("commit", workspace="ws-a")) == 1
        assert len(storage.get_skill_invocations("commit", workspace="ws-b")) == 1
        assert len(storage.get_skill_invocations("commit", workspace="ws-c")) == 0


# ---------------------------------------------------------------------------
# Forensic detection
# ---------------------------------------------------------------------------


class TestDetectSkillInvocation:
    def test_slash_command(self):
        assert _detect_skill_invocation("/commit") == "commit"

    def test_slash_command_with_args(self):
        assert _detect_skill_invocation("/review-pr 42") == "review-pr"

    def test_slash_command_with_leading_whitespace(self):
        assert _detect_skill_invocation("  /commit") == "commit"

    def test_slash_command_strips_trailing_punctuation(self):
        assert _detect_skill_invocation("/commit.") == "commit"

    def test_normal_message_returns_none(self):
        assert _detect_skill_invocation("please fix the bug") is None

    def test_empty_string(self):
        assert _detect_skill_invocation("") is None

    def test_slash_alone(self):
        assert _detect_skill_invocation("/") is None

    def test_multiline_slash_command(self):
        assert _detect_skill_invocation("/commit\nsome extra context") == "commit"

    def test_uppercase_normalised(self):
        assert _detect_skill_invocation("/Commit") == "commit"


class TestExtractSkillInvocations:
    def _make_session(self, turns: list[Turn]) -> ForensicSession:
        sess = ForensicSession(session_id="test-session", agent="Claude Code")
        sess.turns = turns
        return sess

    def test_no_skill_turns(self):
        turn = Turn(index=0, prompt="fix the bug")
        sess = self._make_session([turn])
        assert extract_skill_invocations(sess) == []

    def test_skill_turn_detected(self):
        turn = Turn(
            index=0,
            prompt="/commit",
            skill_id="commit",
            timestamp_start="2026-03-01T10:00:00",
            tokens_in=100,
            tokens_out=50,
            is_dead_end=False,
        )
        turn.actions = [Action(tool_name="Bash", input_summary="git commit")]
        sess = self._make_session([turn])
        invocations = extract_skill_invocations(sess)
        assert len(invocations) == 1
        inv = invocations[0]
        assert inv["skill_id"] == "commit"
        assert inv["session_id"] == "test-session"
        assert inv["agent"] == "Claude Code"
        assert inv["had_backtrack"] is False
        assert inv["success"] is True
        assert inv["action_count"] == 1

    def test_dead_end_marks_backtrack(self):
        turn = Turn(index=0, prompt="/commit", skill_id="commit", is_dead_end=True)
        sess = self._make_session([turn])
        inv = extract_skill_invocations(sess)[0]
        assert inv["had_backtrack"] is True
        assert inv["success"] is False

    def test_multiple_skill_turns(self):
        turns = [
            Turn(index=0, prompt="/commit", skill_id="commit"),
            Turn(index=1, prompt="explain this file", skill_id=None),
            Turn(index=2, prompt="/review-pr", skill_id="review-pr"),
        ]
        sess = self._make_session(turns)
        invocations = extract_skill_invocations(sess)
        assert len(invocations) == 2
        assert invocations[0]["skill_id"] == "commit"
        assert invocations[1]["skill_id"] == "review-pr"

    def test_token_count_includes_all_token_types(self):
        turn = Turn(
            index=0,
            prompt="/commit",
            skill_id="commit",
            tokens_in=100,
            tokens_out=50,
            tokens_cache_read=20,
            tokens_cache_create=10,
        )
        sess = self._make_session([turn])
        inv = extract_skill_invocations(sess)[0]
        assert inv["token_count"] == 180


# ---------------------------------------------------------------------------
# Turn.skill_id set during parse_session
# ---------------------------------------------------------------------------


class TestTurnSkillIdParsed:
    def test_slash_command_in_turn_sets_skill_id(self, tmp_path):
        """parse_session should set skill_id on turns whose prompt starts with /."""
        import json as _json
        from riva.core.forensic import parse_session

        events = [
            {
                "type": "user",
                "message": {"role": "user", "content": "/commit\nPlease create a commit"},
                "timestamp": "2026-03-01T10:00:00Z",
            },
            {
                "type": "assistant",
                "message": {
                    "role": "assistant",
                    "content": [{"type": "text", "text": "Done!"}],
                    "usage": {"input_tokens": 10, "output_tokens": 5},
                },
                "timestamp": "2026-03-01T10:00:01Z",
            },
        ]
        f = tmp_path / "session.jsonl"
        f.write_text("\n".join(_json.dumps(e) for e in events))
        sess = parse_session(f)
        assert len(sess.turns) == 1
        assert sess.turns[0].skill_id == "commit"

    def test_normal_turn_has_no_skill_id(self, tmp_path):
        import json as _json
        from riva.core.forensic import parse_session

        events = [
            {
                "type": "user",
                "message": {"role": "user", "content": "fix the bug"},
                "timestamp": "2026-03-01T10:00:00Z",
            },
        ]
        f = tmp_path / "session.jsonl"
        f.write_text("\n".join(_json.dumps(e) for e in events))
        sess = parse_session(f)
        assert sess.turns[0].skill_id is None


# ---------------------------------------------------------------------------
# Claude Code parse_skills
# ---------------------------------------------------------------------------


class TestClaudeCodeParseSkills:
    def test_no_commands_dir(self, tmp_path, monkeypatch):
        from riva.agents.claude_code import ClaudeCodeDetector

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        det = ClaudeCodeDetector()
        skills = det.parse_skills()
        assert skills == []

    def test_reads_md_files_as_skills(self, tmp_path, monkeypatch):
        from riva.agents.claude_code import ClaudeCodeDetector

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        commands_dir = tmp_path / ".claude" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "commit.md").write_text("# Create a git commit\n\nThis skill commits staged changes.")
        (commands_dir / "review-pr.md").write_text("Review a pull request thoroughly.")

        det = ClaudeCodeDetector()
        skills = det.parse_skills()
        assert len(skills) == 2
        ids = {s.id for s in skills}
        assert "commit" in ids
        assert "review-pr" in ids

    def test_skill_invocation_is_slash_prefixed(self, tmp_path, monkeypatch):
        from riva.agents.claude_code import ClaudeCodeDetector

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        commands_dir = tmp_path / ".claude" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "commit.md").write_text("Commit staged changes")

        det = ClaudeCodeDetector()
        skills = det.parse_skills()
        assert skills[0].invocation == "/commit"

    def test_skill_description_from_first_line(self, tmp_path, monkeypatch):
        from riva.agents.claude_code import ClaudeCodeDetector

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        commands_dir = tmp_path / ".claude" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "commit.md").write_text("# My commit skill\nMore details here.")

        det = ClaudeCodeDetector()
        skills = det.parse_skills()
        assert skills[0].description == "My commit skill"

    def test_empty_md_file(self, tmp_path, monkeypatch):
        from riva.agents.claude_code import ClaudeCodeDetector

        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        commands_dir = tmp_path / ".claude" / "commands"
        commands_dir.mkdir(parents=True)
        (commands_dir / "empty.md").write_text("")

        det = ClaudeCodeDetector()
        skills = det.parse_skills()
        assert len(skills) == 1
        assert skills[0].id == "empty"
        assert skills[0].description == ""


# ---------------------------------------------------------------------------
# TUI component
# ---------------------------------------------------------------------------


class TestBuildSkillsPanel:
    def test_empty_skills_returns_panel(self):
        from rich.panel import Panel

        panel = build_skills_panel(None)
        assert isinstance(panel, Panel)

    def test_empty_list_returns_panel(self):
        from rich.panel import Panel

        panel = build_skills_panel([])
        assert isinstance(panel, Panel)

    def test_with_skills(self, sample_skill):
        from rich.panel import Panel

        sample_skill.forensic_stats = SkillForensicStats(
            usage_count=5, success_count=4, backtrack_count=1, avg_tokens=200.0
        )
        panel = build_skills_panel([sample_skill])
        assert isinstance(panel, Panel)

    def test_panel_title_includes_count(self, sample_skill, shared_skill):
        panel = build_skills_panel([sample_skill, shared_skill])
        assert "2" in str(panel.title)

    def test_success_rate_zero_usage_shows_dash(self, sample_skill):
        from rich.text import Text

        sample_skill.forensic_stats = SkillForensicStats(usage_count=0)
        panel = build_skills_panel([sample_skill])
        # Just ensure no exception is raised with zero usage
        assert panel is not None


# ---------------------------------------------------------------------------
# CLI integration
# ---------------------------------------------------------------------------


class TestSkillsCLI:
    def setup_method(self):
        self.runner = CliRunner()

    def invoke(self, *args):
        from riva.cli import cli

        return self.runner.invoke(cli, list(args))

    def test_skills_help(self):
        result = self.invoke("skills", "--help")
        assert result.exit_code == 0
        assert "Skills management" in result.output

    def test_skills_list_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)
        result = self.invoke("skills", "list")
        assert result.exit_code == 0
        assert "No skills found" in result.output

    def test_skills_add_global(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        result = self.invoke("skills", "add", "commit", "-d", "Git commit", "--global")
        assert result.exit_code == 0
        assert "commit" in result.output
        assert (tmp_path / ".riva" / "skills.toml").exists()

    def test_skills_add_duplicate_warns(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        self.invoke("skills", "add", "commit", "--global")
        result = self.invoke("skills", "add", "commit", "--global")
        assert result.exit_code == 0
        assert "already exists" in result.output

    def test_skills_list_json(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        self.invoke("skills", "add", "commit", "-d", "A commit skill", "--global")
        result = self.invoke("skills", "list", "--json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert isinstance(data, list)
        assert data[0]["id"] == "commit"
        assert "forensic_stats" in data[0]

    def test_skills_stats_no_invocations(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        result = self.invoke("skills", "stats", "no-such-skill")
        assert result.exit_code == 0
        assert "No recorded invocations" in result.output

    def test_skills_scan_no_sessions(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        result = self.invoke("skills", "scan")
        assert result.exit_code == 0

    def test_skills_export(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        self.invoke("skills", "add", "commit", "-d", "commit skill", "--global")
        out_file = str(tmp_path / "export.toml")
        result = self.invoke("skills", "export", out_file)
        assert result.exit_code == 0
        assert Path(out_file).exists()
        assert "commit" in Path(out_file).read_text()

    def test_skills_export_empty(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        out_file = str(tmp_path / "export.toml")
        result = self.invoke("skills", "export", out_file)
        assert result.exit_code == 0
        assert "No skills to export" in result.output

    def test_skills_import(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        toml_content = '[skill.test]\nname = "Test"\ndescription = "A test skill"\n'
        in_file = tmp_path / "import.toml"
        in_file.write_text(toml_content)
        result = self.invoke("skills", "import", str(in_file), "--global")
        assert result.exit_code == 0
        assert "1 skill(s)" in result.output
        loaded = load_global_skills()
        assert any(s.id == "test" for s in loaded)

    def test_skills_import_no_duplicates(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        toml_content = '[skill.test]\nname = "Test"\n'
        in_file = tmp_path / "import.toml"
        in_file.write_text(toml_content)
        self.invoke("skills", "import", str(in_file), "--global")
        result = self.invoke("skills", "import", str(in_file), "--global")
        assert result.exit_code == 0
        # Second import should add 0 new skills
        assert "0 skill(s)" in result.output

    def test_skills_share(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        self.invoke("skills", "add", "commit", "--global")
        result = self.invoke("skills", "share", "commit", "--to", "Cursor")
        assert result.exit_code == 0
        assert "shared" in result.output

    def test_skills_share_not_found(self, tmp_path, monkeypatch):
        monkeypatch.setattr(Path, "home", lambda: tmp_path)
        result = self.invoke("skills", "share", "nonexistent")
        assert result.exit_code == 0
        assert "not found" in result.output
