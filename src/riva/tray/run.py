"""Entry point for the tray daemon subprocess.

Invoked as ``python -m riva.tray.run`` by :func:`riva.tray.daemon.start_tray_daemon`.
"""

from __future__ import annotations

import argparse
import logging
import sys


def main() -> None:
    parser = argparse.ArgumentParser(description="Riva tray daemon")
    parser.add_argument("--version", required=True)
    parser.add_argument("--web-host", default="127.0.0.1")
    parser.add_argument("--web-port", type=int, default=8585)
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stderr,
    )

    from riva.tray.manager import start_tray

    start_tray(version=args.version, web_host=args.web_host, web_port=args.web_port)


if __name__ == "__main__":
    main()
