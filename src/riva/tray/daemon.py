"""Daemon management for the Riva system tray."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from pathlib import Path

PID_DIR = Path("~/.config/riva").expanduser()
PID_FILE = PID_DIR / "tray.pid"
LOG_FILE = PID_DIR / "tray.log"


def read_pid() -> int | None:
    """Read PID from the PID file, returning None if absent or invalid."""
    try:
        return int(PID_FILE.read_text().strip())
    except (FileNotFoundError, ValueError):
        return None


def is_running(pid: int) -> bool:
    """Check whether a process with *pid* is alive."""
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def write_pid(pid: int) -> None:
    """Write *pid* to the PID file, creating the directory if needed."""
    PID_DIR.mkdir(parents=True, exist_ok=True)
    PID_FILE.write_text(str(pid))


def remove_pid() -> None:
    """Delete the PID file if it exists."""
    try:
        PID_FILE.unlink()
    except FileNotFoundError:
        pass


def start_tray_daemon(version: str, web_host: str, web_port: int) -> int:
    """Fork the tray into a background process.

    Returns the child PID on success.
    Raises ``RuntimeError`` if the daemon is already running.
    """
    pid = read_pid()
    if pid is not None and is_running(pid):
        raise RuntimeError(f"Tray daemon already running (PID {pid})")

    PID_DIR.mkdir(parents=True, exist_ok=True)
    log_fh = open(LOG_FILE, "a")  # noqa: SIM115

    cmd = [
        sys.executable,
        "-m",
        "riva.tray.run",
        "--version",
        version,
        "--web-host",
        web_host,
        "--web-port",
        str(web_port),
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=log_fh,
        stderr=log_fh,
        start_new_session=True,
    )
    log_fh.close()

    write_pid(proc.pid)
    return proc.pid


def stop_tray_daemon() -> bool:
    """Stop the running tray daemon.

    Sends SIGTERM and waits up to 5 seconds. Falls back to SIGKILL.
    Returns True if the daemon was stopped, False if it was not running.
    """
    pid = read_pid()
    if pid is None or not is_running(pid):
        remove_pid()
        return False

    os.kill(pid, signal.SIGTERM)

    for _ in range(50):  # 50 × 0.1s = 5s
        if not is_running(pid):
            remove_pid()
            return True
        time.sleep(0.1)

    # Still alive — force kill
    try:
        os.kill(pid, signal.SIGKILL)
    except OSError:
        pass
    remove_pid()
    return True


def tray_daemon_status() -> dict:
    """Return a status dict for the tray daemon."""
    pid = read_pid()
    running = pid is not None and is_running(pid)
    return {
        "running": running,
        "pid": pid if running else None,
        "log_file": str(LOG_FILE),
    }
