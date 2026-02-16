"""Minimal synchronous pub/sub event emitter."""

from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

logger = logging.getLogger(__name__)


class EventEmitter:
    """Synchronous event emitter with subscribe/emit/unsubscribe."""

    def __init__(self) -> None:
        self._listeners: dict[str, list[Callable]] = defaultdict(list)

    def on(self, event: str, callback: Callable) -> None:
        """Subscribe *callback* to *event*."""
        if callback not in self._listeners[event]:
            self._listeners[event].append(callback)

    def off(self, event: str, callback: Callable) -> None:
        """Unsubscribe *callback* from *event*."""
        try:
            self._listeners[event].remove(callback)
        except ValueError:
            pass

    def emit(self, event: str, **kwargs) -> None:
        """Emit *event*, calling all registered callbacks with **kwargs.

        Exceptions in callbacks are logged but never propagated.
        """
        for callback in list(self._listeners.get(event, [])):
            try:
                callback(**kwargs)
            except Exception:
                logger.warning(
                    "Event callback %s for '%s' raised an exception",
                    callback,
                    event,
                    exc_info=True,
                )

    @property
    def listeners(self) -> dict[str, list[Callable]]:
        """Return a snapshot of all registered listeners."""
        return dict(self._listeners)
