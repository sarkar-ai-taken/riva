"""Formatting utilities for display."""

from __future__ import annotations


def mask_secret(value: str, visible: int = 4) -> str:
    """Mask a secret string, showing only the last `visible` characters."""
    if not value:
        return ""
    if len(value) <= visible:
        return "*" * len(value)
    return "*" * (len(value) - visible) + value[-visible:]


def format_uptime(seconds: float) -> str:
    """Format seconds into a human-readable uptime string."""
    if seconds < 0:
        return "0s"
    total = int(seconds)
    days, remainder = divmod(total, 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, secs = divmod(remainder, 60)

    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)


def format_bytes(num_bytes: float) -> str:
    """Format bytes into human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(num_bytes) < 1024:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024
    return f"{num_bytes:.1f} PB"


def format_mb(mb: float) -> str:
    """Format megabytes into a readable string."""
    if mb < 1024:
        return f"{mb:.1f} MB"
    return f"{mb / 1024:.2f} GB"


def format_number(n: int | float) -> str:
    """Format a number into a compact human-readable string.

    Examples: 0→"0", 999→"999", 1500→"1.5K", 2500000→"2.5M", 3000000000→"3.0B"
    """
    n = int(n)
    if abs(n) < 1000:
        return str(n)
    for threshold, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if abs(n) >= threshold:
            value = n / threshold
            # Use one decimal, strip trailing ".0" only for exact multiples
            formatted = f"{value:.1f}"
            return f"{formatted}{suffix}"
    return str(n)
