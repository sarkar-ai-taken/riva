"""One-time consent prompt for Riva Hub telemetry."""

from __future__ import annotations

import click


def maybe_prompt_consent() -> None:
    """Show consent prompt if the user hasn't answered yet. No-op otherwise."""
    from riva.hub.config import get_consent, set_consent

    if get_consent() is not None:
        return  # already answered

    click.echo()
    click.echo("  [Riva Hub] Share anonymous usage data with the Riva community?")
    click.echo("  This sends: agent names, OS, city (via IP lookup). No PII. Opt-in.")
    click.echo("  You can change this later in ~/.config/riva/hub.toml")
    click.echo()

    agreed = click.confirm("  Join the Riva Hub?", default=False)
    set_consent(agreed)

    if agreed:
        click.echo("  Thanks! You're on the map. 🌍")
    else:
        click.echo("  No problem — telemetry disabled.")
    click.echo()
