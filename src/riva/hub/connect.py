"""Device registration with a Riva Server.

`riva connect <token>` exchanges a one-time registration token (minted on the
web dashboard) for long-lived device credentials, and persists them to
``~/.config/riva/hub.toml``.
"""

from __future__ import annotations

import json
import platform
import socket
import urllib.error
import urllib.request

from riva.hub.config import set_server_credentials

DEFAULT_SERVER_URL = "https://riva-server.sarkar.ai/api/v1"
_TIMEOUT = 10


class RegistrationError(RuntimeError):
    pass


def _machine_name() -> str:
    name = socket.gethostname() or platform.node() or "unknown"
    return name.split(".")[0]


def register_device(register_token: str, server_url: str | None = None) -> dict:
    """Exchange a registration token for device credentials.

    POSTs to ``{server_url}/devices/register`` with the user's one-time token
    plus this machine's name. Server returns ``{device_id, device_token}``.
    Credentials are persisted on success and the response dict returned.
    """
    base = (server_url or DEFAULT_SERVER_URL).rstrip("/")
    payload = json.dumps(
        {
            "register_token": register_token,
            "machine_name": _machine_name(),
            "os": f"{platform.system()} {platform.release()}",
        }
    ).encode()
    req = urllib.request.Request(
        f"{base}/devices/register",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            data = json.loads(resp.read())
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        raise RegistrationError(f"server rejected token ({e.code}): {body}") from e
    except (urllib.error.URLError, OSError) as e:
        raise RegistrationError(f"cannot reach {base}: {e}") from e

    device_id = data.get("device_id")
    device_token = data.get("device_token")
    if not device_id or not device_token:
        raise RegistrationError(f"malformed server response: {data}")

    set_server_credentials(base, device_id, device_token)
    return data
