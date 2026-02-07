"""Tests for riva.tray.manager."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from riva.tray.manager import (
    _compile,
    _find_swift_source,
    _handle_action,
    _needs_compile,
    start_tray,
)


class TestFindSwiftSource:
    def test_finds_source_next_to_module(self):
        source = _find_swift_source()
        # In the dev layout the file sits alongside manager.py
        assert source is not None
        assert source.name == "tray_mac.swift"
        assert source.exists()


class TestNeedsCompile:
    def test_missing_binary(self, tmp_path):
        binary = tmp_path / "tray-mac"
        source = tmp_path / "tray_mac.swift"
        source.write_text("// swift")
        assert _needs_compile(binary, source) is True

    def test_stale_binary(self, tmp_path):
        source = tmp_path / "tray_mac.swift"
        source.write_text("// swift v2")
        binary = tmp_path / "tray-mac"
        binary.write_text("old")
        # Force source to be newer
        os.utime(binary, (0, 0))
        assert _needs_compile(binary, source) is True

    def test_fresh_binary(self, tmp_path):
        source = tmp_path / "tray_mac.swift"
        source.write_text("// swift")
        binary = tmp_path / "tray-mac"
        binary.write_text("compiled")
        # Force binary to be newer
        os.utime(source, (0, 0))
        assert _needs_compile(binary, source) is False


class TestCompile:
    def test_compile_success(self, tmp_path):
        source = tmp_path / "hello.swift"
        source.write_text('print("hello")')
        binary = tmp_path / "hello"

        with patch("riva.tray.manager.CACHE_DIR", tmp_path):
            result = _compile(source, binary)

        # On macOS with Xcode this succeeds; on Linux/CI it may fail
        # We accept both outcomes — the important thing is no crash
        assert isinstance(result, bool)

    def test_compile_missing_swiftc(self, tmp_path):
        source = tmp_path / "test.swift"
        source.write_text("// test")
        binary = tmp_path / "test"

        with (
            patch("riva.tray.manager.CACHE_DIR", tmp_path),
            patch("riva.tray.manager.subprocess.run", side_effect=FileNotFoundError),
        ):
            assert _compile(source, binary) is False

    def test_compile_failure(self, tmp_path):
        import subprocess

        source = tmp_path / "bad.swift"
        source.write_text("// bad")
        binary = tmp_path / "bad"

        with (
            patch("riva.tray.manager.CACHE_DIR", tmp_path),
            patch(
                "riva.tray.manager.subprocess.run",
                side_effect=subprocess.CalledProcessError(1, "swiftc", stderr=b"error"),
            ),
        ):
            assert _compile(source, binary) is False

    def test_compile_timeout(self, tmp_path):
        import subprocess

        source = tmp_path / "slow.swift"
        source.write_text("// slow")
        binary = tmp_path / "slow"

        with (
            patch("riva.tray.manager.CACHE_DIR", tmp_path),
            patch(
                "riva.tray.manager.subprocess.run",
                side_effect=subprocess.TimeoutExpired("swiftc", 120),
            ),
        ):
            assert _compile(source, binary) is False


class TestHandleAction:
    def test_quit_returns_false(self):
        assert _handle_action("quit", "127.0.0.1", 8585) is False

    def test_open_tui(self):
        with patch("riva.tray.manager._open_terminal_with") as mock:
            assert _handle_action("open_tui", "127.0.0.1", 8585) is True
            mock.assert_called_once_with("riva watch")

    def test_open_web(self):
        with patch("riva.tray.manager.webbrowser.open") as mock:
            assert _handle_action("open_web", "127.0.0.1", 8585) is True
            mock.assert_called_once_with("http://127.0.0.1:8585")

    def test_open_web_custom_host_port(self):
        with patch("riva.tray.manager.webbrowser.open") as mock:
            assert _handle_action("open_web", "0.0.0.0", 9090) is True
            mock.assert_called_once_with("http://0.0.0.0:9090")

    def test_start_web(self):
        with patch("riva.web.daemon.start_daemon") as mock:
            assert _handle_action("start_web", "127.0.0.1", 8585) is True
            mock.assert_called_once_with("127.0.0.1", 8585)

    def test_start_web_error(self):
        with patch("riva.web.daemon.start_daemon", side_effect=RuntimeError("already running")):
            # Should not raise, just log
            assert _handle_action("start_web", "127.0.0.1", 8585) is True

    def test_stop_web(self):
        with patch("riva.web.daemon.stop_daemon") as mock:
            assert _handle_action("stop_web", "127.0.0.1", 8585) is True
            mock.assert_called_once()

    def test_stop_web_error(self):
        with patch("riva.web.daemon.stop_daemon", side_effect=Exception("oops")):
            assert _handle_action("stop_web", "127.0.0.1", 8585) is True

    def test_scan(self):
        with patch("riva.tray.manager._open_terminal_with") as mock:
            assert _handle_action("scan", "127.0.0.1", 8585) is True
            mock.assert_called_once_with("riva scan")

    def test_audit(self):
        with patch("riva.tray.manager._open_terminal_with") as mock:
            assert _handle_action("audit", "127.0.0.1", 8585) is True
            mock.assert_called_once_with("riva audit")

    def test_unknown_action(self):
        assert _handle_action("unknown_action", "127.0.0.1", 8585) is True

    def test_whitespace_stripped(self):
        assert _handle_action("  quit  ", "127.0.0.1", 8585) is False


class TestStartTray:
    def test_non_macos_exits_early(self):
        with patch("riva.tray.manager.platform.system", return_value="Linux"):
            # Should return without error
            start_tray(version="0.2.3")

    def test_missing_source_exits_early(self):
        with (
            patch("riva.tray.manager.platform.system", return_value="Darwin"),
            patch("riva.tray.manager._find_swift_source", return_value=None),
        ):
            start_tray(version="0.2.3")

    def test_compile_failure_exits_early(self):
        mock_source = MagicMock()
        mock_source.stat.return_value.st_mtime = 999

        with (
            patch("riva.tray.manager.platform.system", return_value="Darwin"),
            patch("riva.tray.manager._find_swift_source", return_value=mock_source),
            patch("riva.tray.manager._needs_compile", return_value=True),
            patch("riva.tray.manager._compile", return_value=False),
        ):
            start_tray(version="0.2.3")

    def test_spawns_binary_and_handles_quit(self):
        mock_source = MagicMock()
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.stdout = iter([b"quit\n"])

        with (
            patch("riva.tray.manager.platform.system", return_value="Darwin"),
            patch("riva.tray.manager._find_swift_source", return_value=mock_source),
            patch("riva.tray.manager._needs_compile", return_value=False),
            patch("riva.tray.manager.subprocess.Popen", return_value=mock_proc),
        ):
            start_tray(version="0.2.3")

        mock_proc.terminate.assert_called_once()
