"""Launcher/parent process classification for agent processes."""

from __future__ import annotations

import enum
from dataclasses import dataclass, field

import psutil


class LaunchType(enum.Enum):
    """How an agent process was launched."""

    USER_TERMINAL = "user_terminal"
    IDE = "ide"
    SCRIPT = "script"
    SYSTEM = "system"
    UNKNOWN = "unknown"


# Known shell process names (skip through these to find the real launcher)
_SHELLS = frozenset(
    {
        "bash",
        "zsh",
        "fish",
        "sh",
        "dash",
        "tcsh",
        "csh",
        "ksh",
        "elvish",
        "nu",
        "login",
        "-bash",
        "-zsh",
        "-fish",
        "-sh",
    }
)

# Known terminal emulators → user_terminal
_TERMINALS = frozenset(
    {
        "Terminal",
        "iTerm2",
        "iTerm",
        "Alacritty",
        "kitty",
        "WezTerm",
        "wezterm-gui",
        "Hyper",
        "tmux",
        "screen",
        "gnome-terminal-server",
        "konsole",
        "xterm",
        "alacritty",
        "rxvt",
        "urxvt",
        "st",
        "tilix",
        "terminator",
        "guake",
        "yakuake",
    }
)

# Known IDE process names → ide  (maps name fragment → human label)
_IDE_NAMES: dict[str, str] = {
    "code": "VS Code",
    "Code": "VS Code",
    "Code Helper": "VS Code",
    "Electron": "VS Code",
    "cursor": "Cursor",
    "Cursor": "Cursor",
    "Cursor Helper": "Cursor",
    "idea": "IntelliJ",
    "pycharm": "PyCharm",
    "webstorm": "WebStorm",
    "goland": "GoLand",
    "rider": "Rider",
    "rubymine": "RubyMine",
    "zed": "Zed",
    "windsurf": "Windsurf",
}

# Known system/launcher process names
_SYSTEM_LAUNCHERS = frozenset(
    {
        "launchd",
        "init",
        "systemd",
        "cron",
        "crond",
        "atd",
        "supervisord",
        "containerd",
        "dockerd",
        "docker",
    }
)

# Known script interpreters
_SCRIPT_INTERPRETERS = frozenset(
    {
        "python",
        "python3",
        "python3.10",
        "python3.11",
        "python3.12",
        "python3.13",
        "node",
        "ruby",
        "perl",
        "php",
        "deno",
        "bun",
    }
)

# Named tool launchers (script type but with a known label)
_KNOWN_TOOL_LAUNCHERS = frozenset(
    {
        "deskmate",
        "supervisord",
        "pm2",
        "npx",
        "pipx",
    }
)

_MAX_ANCESTOR_DEPTH = 15


@dataclass
class LauncherInfo:
    """Information about what launched an agent process."""

    parent_pid: int | None = None
    parent_name: str | None = None
    parent_exe: str | None = None
    launched_by: str = "Unknown"
    launch_type: LaunchType = LaunchType.UNKNOWN
    ancestor_chain: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "parent_pid": self.parent_pid,
            "parent_name": self.parent_name,
            "parent_exe": self.parent_exe,
            "launched_by": self.launched_by,
            "launch_type": self.launch_type.value,
            "ancestor_chain": self.ancestor_chain,
        }


def _proc_name(proc: psutil.Process) -> str:
    try:
        return proc.name() or ""
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ""


def _proc_exe(proc: psutil.Process) -> str:
    try:
        return proc.exe() or ""
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return ""


def _proc_cmdline(proc: psutil.Process) -> list[str]:
    try:
        return proc.cmdline() or []
    except (psutil.AccessDenied, psutil.NoSuchProcess, OSError):
        return []


def _script_label(proc: psutil.Process) -> str:
    """Build a human-readable label for a script-interpreter process."""
    name = _proc_name(proc)
    cmdline = _proc_cmdline(proc)
    # Try to find the script name from cmdline
    for arg in cmdline[1:]:
        if not arg.startswith("-"):
            # Use just the filename part
            script = arg.rsplit("/", 1)[-1]
            return f"{name} {script}"
    return name


def classify_launcher(pid: int) -> LauncherInfo:
    """Walk up the process tree to classify what launched the given PID.

    Returns a ``LauncherInfo`` with human-readable launcher description
    and launch type classification.
    """
    info = LauncherInfo()

    try:
        proc = psutil.Process(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return info

    # Collect the direct parent first
    try:
        parent = proc.parent()
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        return info

    if parent is None:
        return info

    info.parent_pid = parent.pid
    info.parent_name = _proc_name(parent)
    info.parent_exe = _proc_exe(parent)

    # Walk ancestors (nearest-first), capped at _MAX_ANCESTOR_DEPTH
    ancestors: list[psutil.Process] = []
    try:
        current: psutil.Process | None = parent
        for _ in range(_MAX_ANCESTOR_DEPTH):
            if current is None:
                break
            ancestors.append(current)
            try:
                current = current.parent()
            except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
                break
    except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
        pass

    # Build ancestor chain
    info.ancestor_chain = []
    for a in ancestors:
        info.ancestor_chain.append(
            {
                "pid": a.pid,
                "name": _proc_name(a),
                "exe": _proc_exe(a),
            }
        )

    # Walk ancestors (skip shells) to find the real launcher
    for ancestor in ancestors:
        name = _proc_name(ancestor)
        exe = _proc_exe(ancestor)
        exe_tail = exe.rsplit("/", 1)[-1] if exe else ""

        # Skip shells — they're just intermediaries
        if name in _SHELLS or exe_tail in _SHELLS:
            continue

        # Check for known terminals
        if name in _TERMINALS or exe_tail in _TERMINALS:
            info.launched_by = f"User ({name})"
            info.launch_type = LaunchType.USER_TERMINAL
            return info

        # Check for known IDEs
        ide_label = _IDE_NAMES.get(name) or _IDE_NAMES.get(exe_tail)
        if ide_label:
            info.launched_by = f"User ({ide_label})"
            info.launch_type = LaunchType.IDE
            return info

        # Check for known tool launchers
        if name in _KNOWN_TOOL_LAUNCHERS or exe_tail in _KNOWN_TOOL_LAUNCHERS:
            info.launched_by = name
            info.launch_type = LaunchType.SCRIPT
            return info

        # Check for system launchers
        if name in _SYSTEM_LAUNCHERS or exe_tail in _SYSTEM_LAUNCHERS:
            info.launched_by = name
            info.launch_type = LaunchType.SYSTEM
            return info

        # Check for script interpreters
        if name in _SCRIPT_INTERPRETERS or exe_tail in _SCRIPT_INTERPRETERS:
            info.launched_by = _script_label(ancestor)
            info.launch_type = LaunchType.SCRIPT
            return info

        # Non-shell, non-known — use this as the launcher
        info.launched_by = name or exe_tail or "Unknown"
        info.launch_type = LaunchType.UNKNOWN
        return info

    # If we only found shells all the way up, use the direct parent
    info.launched_by = info.parent_name or "Unknown"
    info.launch_type = LaunchType.UNKNOWN
    return info
