"""Scan environment variables for AI-related configuration."""

from __future__ import annotations

import os

from riva.utils.formatting import mask_secret

# Known AI-related environment variable prefixes and exact names
AI_ENV_PATTERNS: list[str] = [
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GOOGLE_API_KEY",
    "GEMINI_API_KEY",
    "OPENCLAW_",
    "CLAUDE_",
    "CODEX_",
    "GEMINI_",
]

# Variables whose values should always be masked
SECRET_KEYWORDS = {"KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL"}


def _is_secret(name: str) -> bool:
    """Check if an env var name likely holds a secret value."""
    upper = name.upper()
    return any(kw in upper for kw in SECRET_KEYWORDS)


def scan_env_vars() -> list[dict[str, str]]:
    """Scan environment for AI-related variables.

    Returns a list of dicts with keys: name, value (masked if secret), raw_length.
    """
    results: list[dict[str, str]] = []
    for key, value in sorted(os.environ.items()):
        matched = any(
            key.upper().startswith(pattern) or key.upper() == pattern
            for pattern in AI_ENV_PATTERNS
        )
        if not matched:
            continue

        display_value = mask_secret(value) if _is_secret(key) else value
        results.append(
            {
                "name": key,
                "value": display_value,
                "raw_length": str(len(value)),
            }
        )
    return results
