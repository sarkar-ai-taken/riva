"""System tray manager — compiles and spawns the native tray binary."""

from __future__ import annotations

import logging
import os
import platform
import subprocess
import sys
import threading
import webbrowser
from pathlib import Path

log = logging.getLogger("riva.tray")

CACHE_DIR = Path("~/.cache/riva").expanduser()
BINARY_NAME = "tray-mac"


def _find_swift_source() -> Path | None:
    """Locate the Swift source file shipped alongside the package."""
    candidates = [
        Path(__file__).parent / "tray_mac.swift",
        Path(__file__).parent.parent.parent.parent / "src" / "riva" / "tray" / "tray_mac.swift",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate
    return None


def _needs_compile(binary: Path, source: Path) -> bool:
    """Check whether the cached binary needs (re)compilation."""
    if not binary.exists():
        return True
    return source.stat().st_mtime > binary.stat().st_mtime


def _compile(source: Path, binary: Path) -> bool:
    """Compile the Swift tray binary.  Returns True on success."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        subprocess.run(
            ["swiftc", "-O", "-o", str(binary), str(source)],
            capture_output=True,
            timeout=120,
            check=True,
        )
        log.info("Tray binary compiled successfully")
        return True
    except FileNotFoundError:
        log.warning("swiftc not found — install Xcode Command Line Tools")
        return False
    except subprocess.CalledProcessError as exc:
        log.warning("Failed to compile tray binary: %s", exc.stderr.decode(errors="replace")[:200])
        return False
    except subprocess.TimeoutExpired:
        log.warning("Tray compilation timed out")
        return False


def _open_terminal_with(command: str) -> None:
    """Open a new Terminal.app window running *command*."""
    apple_script = (
        'tell application "Terminal"\n'
        "  activate\n"
        f'  do script "{command}"\n'
        "end tell"
    )
    subprocess.Popen(
        ["osascript", "-e", apple_script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def _handle_action(action: str, web_host: str, web_port: int) -> bool:
    """Handle an action string emitted by the Swift tray.

    Returns False when the tray should exit.
    """
    action = action.strip()

    if action == "quit":
        log.info("Quit requested from tray")
        return False

    if action == "open_tui":
        _open_terminal_with("riva watch")
        return True

    if action == "open_web":
        url = f"http://{web_host}:{web_port}"
        webbrowser.open(url)
        return True

    if action == "start_web":
        try:
            from riva.web.daemon import start_daemon

            start_daemon(web_host, web_port)
            log.info("Web server started from tray")
        except Exception as exc:
            log.warning("Failed to start web server: %s", exc)
        return True

    if action == "stop_web":
        try:
            from riva.web.daemon import stop_daemon

            stop_daemon()
            log.info("Web server stopped from tray")
        except Exception as exc:
            log.warning("Failed to stop web server: %s", exc)
        return True

    if action == "scan":
        _open_terminal_with("riva scan")
        return True

    if action == "audit":
        _open_terminal_with("riva audit")
        return True

    log.debug("Unknown tray action: %s", action)
    return True


def start_tray(
    version: str,
    web_host: str = "127.0.0.1",
    web_port: int = 8585,
) -> None:
    """Compile (if needed) and launch the system tray.

    This function blocks until the tray is closed.
    """
    if platform.system() != "Darwin":
        log.info("System tray is only supported on macOS")
        return

    source = _find_swift_source()
    if source is None:
        log.warning("Swift source (tray_mac.swift) not found — tray disabled")
        return

    binary = CACHE_DIR / BINARY_NAME
    if _needs_compile(binary, source):
        log.info("Compiling tray binary (first run)…")
        if not _compile(source, binary):
            return

    child = subprocess.Popen(
        [
            str(binary),
            "--version", version,
            "--web-host", web_host,
            "--web-port", str(web_port),
            "--pid", str(os.getpid()),
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
    )

    log.info("System tray started (PID %d)", child.pid)

    try:
        assert child.stdout is not None  # for type checker
        for raw_line in child.stdout:
            line = raw_line.decode(errors="replace").strip()
            if not line:
                continue
            if not _handle_action(line, web_host, web_port):
                break
    except (BrokenPipeError, OSError):
        pass
    finally:
        child.terminate()
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill()

    log.info("System tray stopped")
