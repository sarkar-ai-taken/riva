"""Hub configuration — consent, client ID, endpoint.

Stored at ~/.config/riva/hub.toml (separate from workspace config so it
persists across projects).
"""

from __future__ import annotations

import uuid
from pathlib import Path

# Sentinel values stored in the file
_CONSENTED = "yes"
_DECLINED = "no"

HUB_ENDPOINT = "https://sarkar.ai/api/v1/ping"
_CONFIG_DIR = Path.home() / ".config" / "riva"
_HUB_FILE = _CONFIG_DIR / "hub.toml"


def _read_raw() -> dict[str, str]:
    if not _HUB_FILE.is_file():
        return {}
    out: dict[str, str] = {}
    for line in _HUB_FILE.read_text().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            k, _, v = line.partition("=")
            out[k.strip()] = v.strip().strip('"')
    return out


def _write_raw(data: dict[str, str]) -> None:
    _CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    lines = ["# Riva Hub client config — do not edit manually\n"]
    for k, v in data.items():
        lines.append(f'{k} = "{v}"\n')
    _HUB_FILE.write_text("".join(lines))


def get_consent() -> bool | None:
    """Return True/False if consent is stored, None if not yet asked."""
    raw = _read_raw()
    val = raw.get("consent")
    if val == _CONSENTED:
        return True
    if val == _DECLINED:
        return False
    return None


def set_consent(agreed: bool) -> None:
    raw = _read_raw()
    raw["consent"] = _CONSENTED if agreed else _DECLINED
    if agreed and "client_id" not in raw:
        raw["client_id"] = str(uuid.uuid4())
    _write_raw(raw)


def get_client_id() -> str:
    raw = _read_raw()
    if "client_id" not in raw:
        raw["client_id"] = str(uuid.uuid4())
        _write_raw(raw)
    return raw["client_id"]


def get_endpoint() -> str:
    raw = _read_raw()
    return raw.get("endpoint", HUB_ENDPOINT)
