"""Riva hook: scan_complete."""


def run(context: dict) -> None:
    """Called by Riva with event context."""
    print(f"[riva:scan_complete] hook triggered")
