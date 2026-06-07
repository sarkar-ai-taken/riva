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


# ---------------------------------------------------------------------------
# Server registration — riva connect / riva report
#
# Stored in the same hub.toml under a separate set of keys:
#   server_url    = "https://riva-server.example/api/v1"
#   device_id     = "<uuid>"
#   device_token  = "<opaque secret>"
# ---------------------------------------------------------------------------


def get_server_url() -> str | None:
    return _read_raw().get("server_url") or None


def get_device_id() -> str | None:
    return _read_raw().get("device_id") or None


def get_device_token() -> str | None:
    return _read_raw().get("device_token") or None


def set_server_credentials(server_url: str, device_id: str, device_token: str) -> None:
    raw = _read_raw()
    raw["server_url"] = server_url.rstrip("/")
    raw["device_id"] = device_id
    raw["device_token"] = device_token
    _write_raw(raw)


def clear_server_credentials() -> None:
    raw = _read_raw()
    for k in ("server_url", "device_id", "device_token"):
        raw.pop(k, None)
    _write_raw(raw)


def is_connected() -> bool:
    raw = _read_raw()
    return bool(raw.get("server_url") and raw.get("device_id") and raw.get("device_token"))
