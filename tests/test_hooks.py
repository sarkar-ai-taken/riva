"""Tests for riva.core.hooks."""

from __future__ import annotations

import time

from riva.core.hooks import HookContext, HookEvent, HookRunner


class TestHookContext:
    def test_to_json(self):
        ctx = HookContext(
            event="scan_complete",
            timestamp=1000.0,
            workspace_root="/tmp/project",
            agents=[{"name": "Claude Code", "pid": 123}],
            extras={"count": 1},
        )
        import json

        data = json.loads(ctx.to_json())
        assert data["event"] == "scan_complete"
        assert data["workspace_root"] == "/tmp/project"
        assert data["agents"][0]["name"] == "Claude Code"
        assert data["count"] == 1


class TestHookRunner:
    def test_discover_hooks(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        hooks_dir = riva_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        (hooks_dir / "on_agent_detected.sh").write_text("#!/bin/bash\necho ok\n")
        (hooks_dir / "on_agent_detected_slack.py").write_text("def run(ctx): pass\n")
        (hooks_dir / "on_scan_complete.sh").write_text("#!/bin/bash\necho done\n")
        (hooks_dir / "README.md").write_text("# Hooks\n")

        runner = HookRunner(riva_dir)
        hooks = runner.discover_hooks(HookEvent.AGENT_DETECTED)
        names = [h.name for h in hooks]
        assert "on_agent_detected.sh" in names
        assert "on_agent_detected_slack.py" in names
        assert "on_scan_complete.sh" not in names
        assert "README.md" not in names

    def test_discover_hooks_empty_dir(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        runner = HookRunner(riva_dir)
        assert runner.discover_hooks(HookEvent.AGENT_DETECTED) == []

    def test_discover_hooks_no_dir(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        riva_dir.mkdir()
        runner = HookRunner(riva_dir)
        assert runner.discover_hooks(HookEvent.SCAN_COMPLETE) == []

    def test_execute_shell_hook(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        hooks_dir = riva_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook = hooks_dir / "on_scan_complete.sh"
        hook.write_text("#!/bin/bash\necho hello\n")
        hook.chmod(0o755)

        runner = HookRunner(riva_dir)
        ctx = HookContext(
            event="scan_complete",
            timestamp=time.time(),
            workspace_root=str(tmp_path),
        )
        results = runner.execute(HookEvent.SCAN_COMPLETE, ctx)
        assert len(results) == 1
        assert results[0].success is True
        assert "hello" in results[0].output

    def test_execute_python_hook(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        hooks_dir = riva_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook = hooks_dir / "on_workspace_loaded.py"
        hook.write_text("def run(ctx):\n    pass\n")

        runner = HookRunner(riva_dir)
        ctx = HookContext(
            event="workspace_loaded",
            timestamp=time.time(),
            workspace_root=str(tmp_path),
        )
        results = runner.execute(HookEvent.WORKSPACE_LOADED, ctx)
        assert len(results) == 1
        assert results[0].success is True

    def test_execute_python_hook_no_run(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        hooks_dir = riva_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook = hooks_dir / "on_workspace_loaded.py"
        hook.write_text("x = 1\n")

        runner = HookRunner(riva_dir)
        ctx = HookContext(
            event="workspace_loaded",
            timestamp=time.time(),
            workspace_root=str(tmp_path),
        )
        results = runner.execute(HookEvent.WORKSPACE_LOADED, ctx)
        assert len(results) == 1
        assert results[0].success is False
        assert "no run()" in results[0].error

    def test_shell_hook_failure(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        hooks_dir = riva_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook = hooks_dir / "on_scan_complete.sh"
        hook.write_text("#!/bin/bash\nexit 1\n")
        hook.chmod(0o755)

        runner = HookRunner(riva_dir)
        ctx = HookContext(
            event="scan_complete",
            timestamp=time.time(),
            workspace_root=str(tmp_path),
        )
        results = runner.execute(HookEvent.SCAN_COMPLETE, ctx)
        assert len(results) == 1
        assert results[0].success is False

    def test_shell_hook_timeout(self, tmp_path):
        riva_dir = tmp_path / ".riva"
        hooks_dir = riva_dir / "hooks"
        hooks_dir.mkdir(parents=True)
        hook = hooks_dir / "on_scan_complete.sh"
        hook.write_text("#!/bin/bash\nsleep 60\n")
        hook.chmod(0o755)

        runner = HookRunner(riva_dir, timeout=1)
        ctx = HookContext(
            event="scan_complete",
            timestamp=time.time(),
            workspace_root=str(tmp_path),
        )
        results = runner.execute(HookEvent.SCAN_COMPLETE, ctx)
        assert len(results) == 1
        assert results[0].success is False
        assert "timed out" in results[0].error
