"""Generic hook install / uninstall / status for any agent adapter.

Called by ``riva hooks install``, ``riva hooks uninstall``, ``riva hooks status``.
"""

from __future__ import annotations

import json

from riva.hooks.adapters import get_adapter


def install(agent_key: str) -> tuple[bool, str]:
    """Merge Riva hook entries into the agent's settings file.

    Returns (success, message).
    """
    adapter = get_adapter(agent_key)
    if adapter is None:
        return False, f"Unknown agent: {agent_key}"

    settings_path = adapter.settings_path
    if not settings_path.parent.exists():
        return False, f"Config dir not found: {settings_path.parent}"

    try:
        data: dict = {}
        if settings_path.exists():
            try:
                data = json.loads(settings_path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                data = {}

        hooks: dict = data.setdefault(adapter.hooks_key, {})
        installed: list[str] = []

        for event in adapter.events:
            entries: list = hooks.setdefault(event, [])
            entry = adapter.build_entry(event)
            cmd = entry["hooks"][0]["command"]
            already = any(h.get("command") == cmd for e in entries for h in e.get("hooks", []))
            if not already:
                entries.append(entry)
                installed.append(event)

        settings_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        return False, f"Failed to write {settings_path}: {exc}"

    if installed:
        return True, f"Installed hooks for: {', '.join(installed)}"
    return True, "Hooks already installed — no changes made."


def uninstall(agent_key: str) -> tuple[bool, str]:
    """Remove Riva hook entries from the agent's settings file.

    Returns (success, message).
    """
    adapter = get_adapter(agent_key)
    if adapter is None:
        return False, f"Unknown agent: {agent_key}"

    settings_path = adapter.settings_path
    if not settings_path.exists():
        return True, f"{settings_path.name} not found — nothing to remove."

    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        return False, f"Could not read {settings_path}: {exc}"

    hooks: dict = data.get(adapter.hooks_key, {})
    removed: list[str] = []

    for event in adapter.events:
        entries: list = hooks.get(event, [])
        before = len(entries)
        filtered = [e for e in entries if not adapter.is_riva_entry(e)]
        if len(filtered) < before:
            hooks[event] = filtered
            removed.append(event)
            if not hooks[event]:
                del hooks[event]

    try:
        settings_path.write_text(
            json.dumps(data, indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
    except OSError as exc:
        return False, f"Failed to write {settings_path}: {exc}"

    if removed:
        return True, f"Removed hooks for: {', '.join(removed)}"
    return True, "No Riva hooks found — nothing removed."


def status(agent_key: str) -> tuple[list[str], int]:
    """Check which Riva hooks are installed for an agent.

    Returns (list of installed event names, total possible events).
    """
    adapter = get_adapter(agent_key)
    if adapter is None:
        return [], 0

    settings_path = adapter.settings_path
    if not settings_path.exists():
        return [], len(adapter.events)

    try:
        data = json.loads(settings_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return [], len(adapter.events)

    hooks: dict = data.get(adapter.hooks_key, {})
    installed_events: list[str] = []

    for event in adapter.events:
        entries: list = hooks.get(event, [])
        if any(adapter.is_riva_entry(e) for e in entries):
            installed_events.append(event)

    return installed_events, len(adapter.events)
