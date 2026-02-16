"""Tests for riva.core.events."""

from __future__ import annotations

from riva.core.events import EventEmitter


class TestEventEmitter:
    def test_on_and_emit(self):
        emitter = EventEmitter()
        results = []
        emitter.on("test", lambda **kw: results.append(kw))
        emitter.emit("test", foo="bar")
        assert results == [{"foo": "bar"}]

    def test_multiple_listeners(self):
        emitter = EventEmitter()
        results = []
        emitter.on("ev", lambda **kw: results.append("a"))
        emitter.on("ev", lambda **kw: results.append("b"))
        emitter.emit("ev")
        assert results == ["a", "b"]

    def test_off_removes_listener(self):
        emitter = EventEmitter()
        results = []

        def handler(**kw):
            results.append(1)

        emitter.on("ev", handler)
        emitter.emit("ev")
        assert len(results) == 1

        emitter.off("ev", handler)
        emitter.emit("ev")
        assert len(results) == 1  # Not called again

    def test_off_nonexistent_is_safe(self):
        emitter = EventEmitter()
        emitter.off("ev", lambda: None)  # No error

    def test_emit_unknown_event_is_safe(self):
        emitter = EventEmitter()
        emitter.emit("nonexistent")  # No error

    def test_callback_exception_does_not_propagate(self):
        emitter = EventEmitter()
        results = []

        def bad(**kw):
            raise RuntimeError("boom")

        def good(**kw):
            results.append("ok")

        emitter.on("ev", bad)
        emitter.on("ev", good)
        emitter.emit("ev")
        assert results == ["ok"]

    def test_duplicate_listener_not_added(self):
        emitter = EventEmitter()
        results = []

        def handler(**kw):
            results.append(1)

        emitter.on("ev", handler)
        emitter.on("ev", handler)
        emitter.emit("ev")
        assert results == [1]

    def test_listeners_property(self):
        emitter = EventEmitter()

        def h(**kw):
            pass

        emitter.on("a", h)
        emitter.on("b", h)
        listeners = emitter.listeners
        assert "a" in listeners
        assert "b" in listeners
