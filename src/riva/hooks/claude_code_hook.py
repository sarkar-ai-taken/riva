"""Claude Code hook script (backward-compatibility shim).

Old usage (still works):
    python -m riva.hooks.claude_code_hook <EventType>

New usage:
    python -m riva.hooks.hook claude-code <EventType>
"""

from __future__ import annotations

import sys


def main() -> None:
    event_type = sys.argv[1] if len(sys.argv) > 1 else "unknown"
    sys.argv = [sys.argv[0], "claude-code", event_type]

    from riva.hooks.hook import main as _generic_main

    _generic_main()


if __name__ == "__main__":
    main()
