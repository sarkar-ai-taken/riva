"""Utilities for streaming JSONL files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator


def stream_jsonl(
    path: Path | str,
    max_lines: int = 0,
) -> Iterator[dict]:
    """Yield parsed dicts from a JSONL file, skipping malformed lines.

    Parameters
    ----------
    path:
        Path to the ``.jsonl`` file.
    max_lines:
        Maximum number of lines to read.  ``0`` means unlimited.
    """
    path = Path(path)
    if not path.is_file():
        return

    count = 0
    try:
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if isinstance(obj, dict):
                    yield obj
                    count += 1
                    if max_lines and count >= max_lines:
                        return
    except OSError:
        return


def find_recent_sessions(
    base_dir: Path | str,
    pattern: str = "**/*.jsonl",
    limit: int = 20,
) -> list[Path]:
    """Find the most recently modified JSONL files under *base_dir*.

    Parameters
    ----------
    base_dir:
        Root directory to search.
    pattern:
        Glob pattern relative to *base_dir*.
    limit:
        Maximum number of paths to return.

    Returns the newest *limit* files sorted by modification time (newest first).
    """
    base_dir = Path(base_dir)
    if not base_dir.is_dir():
        return []

    try:
        files = list(base_dir.glob(pattern))
    except OSError:
        return []

    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return files[:limit]
