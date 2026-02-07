"""Tests for launcher classification."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import psutil

from riva.core.launcher import LauncherInfo, LaunchType, classify_launcher


def _mock_process(pid: int, name: str, exe: str = "", cmdline: list[str] | None = None):
    """Create a mock psutil.Process."""
    proc = MagicMock()
    proc.pid = pid
    proc.name.return_value = name
    proc.exe.return_value = exe
    proc.cmdline.return_value = cmdline or []
    return proc


def _chain_parents(procs: list[MagicMock]) -> None:
    """Wire up parent() calls so procs[0].parent() -> procs[1] -> procs[2] -> ... -> None."""
    for i, proc in enumerate(procs):
        if i + 1 < len(procs):
            proc.parent.return_value = procs[i + 1]
        else:
            proc.parent.return_value = None


class TestClassifyLauncher:
    """Test classify_launcher with mocked process trees."""

    @patch("riva.core.launcher.psutil.Process")
    def test_shell_then_terminal(self, mock_process_cls):
        """Shell -> Terminal parent should be user_terminal."""
        agent = _mock_process(100, "claude")
        shell = _mock_process(99, "zsh", "/bin/zsh")
        terminal = _mock_process(50, "iTerm2", "/Applications/iTerm.app/Contents/MacOS/iTerm2")
        _chain_parents([agent, shell, terminal])

        mock_process_cls.return_value = agent
        agent.parent.return_value = shell

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.USER_TERMINAL
        assert "iTerm2" in info.launched_by
        assert info.parent_pid == 99
        assert info.parent_name == "zsh"

    @patch("riva.core.launcher.psutil.Process")
    def test_shell_then_vscode(self, mock_process_cls):
        """Shell -> VS Code parent should be ide."""
        agent = _mock_process(100, "claude")
        shell = _mock_process(99, "bash", "/bin/bash")
        vscode = _mock_process(50, "code", "/usr/bin/code")
        _chain_parents([agent, shell, vscode])

        mock_process_cls.return_value = agent
        agent.parent.return_value = shell

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.IDE
        assert "VS Code" in info.launched_by

    @patch("riva.core.launcher.psutil.Process")
    def test_shell_then_cursor(self, mock_process_cls):
        """Shell -> Cursor parent should be ide."""
        agent = _mock_process(100, "claude")
        shell = _mock_process(99, "zsh", "/bin/zsh")
        cursor = _mock_process(50, "cursor", "/Applications/Cursor.app/Contents/MacOS/cursor")
        _chain_parents([agent, shell, cursor])

        mock_process_cls.return_value = agent
        agent.parent.return_value = shell

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.IDE
        assert "Cursor" in info.launched_by

    @patch("riva.core.launcher.psutil.Process")
    def test_python_script_parent(self, mock_process_cls):
        """Python interpreter with script should be script type."""
        agent = _mock_process(100, "claude")
        python = _mock_process(99, "python3", "/usr/bin/python3", ["python3", "/home/user/deskmate.py"])
        _chain_parents([agent, python])

        mock_process_cls.return_value = agent
        agent.parent.return_value = python

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.SCRIPT
        assert "deskmate.py" in info.launched_by

    @patch("riva.core.launcher.psutil.Process")
    def test_known_launcher_deskmate(self, mock_process_cls):
        """Known tool launcher 'deskmate' should be script type."""
        agent = _mock_process(100, "claude")
        shell = _mock_process(99, "bash", "/bin/bash")
        deskmate = _mock_process(50, "deskmate", "/usr/local/bin/deskmate")
        _chain_parents([agent, shell, deskmate])

        mock_process_cls.return_value = agent
        agent.parent.return_value = shell

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.SCRIPT
        assert info.launched_by == "deskmate"

    @patch("riva.core.launcher.psutil.Process")
    def test_system_launcher_launchd(self, mock_process_cls):
        """launchd parent should be system type."""
        agent = _mock_process(100, "claude")
        shell = _mock_process(99, "zsh", "/bin/zsh")
        launchd = _mock_process(1, "launchd", "/sbin/launchd")
        _chain_parents([agent, shell, launchd])

        mock_process_cls.return_value = agent
        agent.parent.return_value = shell

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.SYSTEM
        assert info.launched_by == "launchd"

    @patch("riva.core.launcher.psutil.Process")
    def test_no_parent_graceful_fallback(self, mock_process_cls):
        """Process with no parent should return unknown gracefully."""
        agent = _mock_process(100, "claude")
        agent.parent.return_value = None

        mock_process_cls.return_value = agent

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.UNKNOWN
        assert info.parent_pid is None

    @patch("riva.core.launcher.psutil.Process")
    def test_access_denied_graceful(self, mock_process_cls):
        """AccessDenied should be handled gracefully."""
        mock_process_cls.side_effect = psutil.AccessDenied(pid=100)

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.UNKNOWN
        assert info.launched_by == "Unknown"

    @patch("riva.core.launcher.psutil.Process")
    def test_no_such_process_graceful(self, mock_process_cls):
        """NoSuchProcess should be handled gracefully."""
        mock_process_cls.side_effect = psutil.NoSuchProcess(pid=100)

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.UNKNOWN
        assert info.launched_by == "Unknown"

    @patch("riva.core.launcher.psutil.Process")
    def test_ancestor_depth_limit(self, mock_process_cls):
        """Ancestor chain should be capped at 15."""
        agent = _mock_process(100, "claude")
        # Create a chain of 20 shells
        procs = [agent]
        for i in range(20):
            procs.append(_mock_process(99 - i, "bash", "/bin/bash"))
        _chain_parents(procs)

        mock_process_cls.return_value = agent
        agent.parent.return_value = procs[1]

        info = classify_launcher(100)

        # Ancestor chain should be capped (15 shells max + initial walk)
        assert len(info.ancestor_chain) <= 16

    @patch("riva.core.launcher.psutil.Process")
    def test_direct_terminal_parent(self, mock_process_cls):
        """Terminal directly as parent (no shell) should work."""
        agent = _mock_process(100, "claude")
        terminal = _mock_process(50, "Alacritty", "/usr/bin/alacritty")
        _chain_parents([agent, terminal])

        mock_process_cls.return_value = agent
        agent.parent.return_value = terminal

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.USER_TERMINAL
        assert "Alacritty" in info.launched_by

    @patch("riva.core.launcher.psutil.Process")
    def test_tmux_parent(self, mock_process_cls):
        """tmux as ancestor should be user_terminal."""
        agent = _mock_process(100, "claude")
        shell = _mock_process(99, "zsh", "/bin/zsh")
        tmux = _mock_process(50, "tmux", "/usr/bin/tmux")
        _chain_parents([agent, shell, tmux])

        mock_process_cls.return_value = agent
        agent.parent.return_value = shell

        info = classify_launcher(100)

        assert info.launch_type == LaunchType.USER_TERMINAL
        assert "tmux" in info.launched_by


class TestLauncherInfo:
    """Test LauncherInfo dataclass."""

    def test_to_dict(self):
        info = LauncherInfo(
            parent_pid=99,
            parent_name="zsh",
            parent_exe="/bin/zsh",
            launched_by="User (iTerm2)",
            launch_type=LaunchType.USER_TERMINAL,
            ancestor_chain=[{"pid": 99, "name": "zsh", "exe": "/bin/zsh"}],
        )
        d = info.to_dict()
        assert d["parent_pid"] == 99
        assert d["parent_name"] == "zsh"
        assert d["launched_by"] == "User (iTerm2)"
        assert d["launch_type"] == "user_terminal"
        assert len(d["ancestor_chain"]) == 1

    def test_defaults(self):
        info = LauncherInfo()
        assert info.parent_pid is None
        assert info.launched_by == "Unknown"
        assert info.launch_type == LaunchType.UNKNOWN
        assert info.ancestor_chain == []
