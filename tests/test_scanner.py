"""Tests for riva.core.scanner."""

import time
from unittest.mock import patch

from riva.agents.base import AgentStatus, SimpleAgentDetector
from riva.core.scanner import ProcessInfo, ProcessScanner


def _make_detector(name="Test", binaries=None):
    return SimpleAgentDetector(
        name=name,
        binaries=binaries or ["testagent"],
        config="/tmp/riva_nonexistent",
        api="api.test.dev",
    )


def _make_proc_info(**kwargs):
    defaults = dict(
        pid=1000,
        name="testagent",
        cmdline=["testagent", "--flag"],
        exe="/usr/bin/testagent",
        cpu_percent=5.0,
        memory_mb=128.0,
        create_time=time.time() - 60,
        cwd="/home/user",
    )
    defaults.update(kwargs)
    return ProcessInfo(**defaults)


class TestProcessScanner:
    def _inject_cache(self, scanner, procs):
        """Inject a fake process cache and patch _refresh_cache to keep it."""
        scanner._cache = procs
        scanner._cache_time = time.monotonic()

    def test_scan_finds_matching_process(self):
        scanner = ProcessScanner(cache_ttl=999)
        proc = _make_proc_info()
        self._inject_cache(scanner, [proc])

        detector = _make_detector()
        with patch.object(detector, "is_installed", return_value=False):
            instances = scanner.scan([detector])

        running = [i for i in instances if i.status == AgentStatus.RUNNING]
        assert len(running) == 1
        assert running[0].pid == 1000
        assert running[0].name == "Test"

    def test_scan_returns_installed_when_no_process(self):
        scanner = ProcessScanner(cache_ttl=999)
        self._inject_cache(scanner, [])

        detector = _make_detector()
        with patch.object(detector, "is_installed", return_value=True):
            instances = scanner.scan([detector])

        assert len(instances) == 1
        assert instances[0].status == AgentStatus.INSTALLED

    def test_scan_skips_not_installed_not_running(self):
        scanner = ProcessScanner(cache_ttl=999)
        self._inject_cache(scanner, [])

        detector = _make_detector()
        with patch.object(detector, "is_installed", return_value=False):
            instances = scanner.scan([detector])

        assert len(instances) == 0

    def test_multiple_detectors(self):
        scanner = ProcessScanner(cache_ttl=999)
        proc_a = _make_proc_info(pid=1, name="agentA")
        proc_b = _make_proc_info(pid=2, name="agentB")
        self._inject_cache(scanner, [proc_a, proc_b])

        det_a = _make_detector("A", ["agentA"])
        det_b = _make_detector("B", ["agentB"])

        with (
            patch.object(det_a, "is_installed", return_value=False),
            patch.object(det_b, "is_installed", return_value=False),
        ):
            instances = scanner.scan([det_a, det_b])

        names = {i.name for i in instances}
        assert "A" in names
        assert "B" in names

    def test_cache_respects_ttl(self):
        scanner = ProcessScanner(cache_ttl=10)
        scanner._cache = [_make_proc_info()]
        scanner._cache_time = time.monotonic()

        # Should not refresh since TTL not expired
        with patch("psutil.process_iter") as mock_iter:
            scanner._refresh_cache()
            mock_iter.assert_not_called()

    def test_cache_refreshes_when_stale(self):
        scanner = ProcessScanner(cache_ttl=0)
        scanner._cache = [_make_proc_info()]
        scanner._cache_time = 0  # ancient

        with patch("psutil.process_iter", return_value=[]) as mock_iter:
            scanner._refresh_cache()
            mock_iter.assert_called_once()

    def test_get_process_info(self):
        scanner = ProcessScanner(cache_ttl=10)
        proc = _make_proc_info(pid=42)
        scanner._cache = [proc]
        scanner._cache_time = time.monotonic()

        result = scanner.get_process_info(42)
        assert result is not None
        assert result.pid == 42

    def test_get_process_info_not_found(self):
        scanner = ProcessScanner(cache_ttl=10)
        scanner._cache = [_make_proc_info(pid=1)]
        scanner._cache_time = time.monotonic()

        assert scanner.get_process_info(999) is None
