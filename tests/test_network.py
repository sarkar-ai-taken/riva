"""Tests for network observation module."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from riva.agents.base import AgentInstance, AgentStatus
from riva.core.network import (
    KNOWN_API_DOMAINS,
    ConnectionInfo,
    NetworkSnapshot,
    _classify_connection,
    collect_all_connections,
    collect_connections,
)


class TestConnectionInfo:
    def test_defaults(self):
        c = ConnectionInfo()
        assert c.local_addr == ""
        assert c.remote_port == 0
        assert c.is_tls is False
        assert c.known_service is None

    def test_with_values(self):
        c = ConnectionInfo(
            remote_addr="93.184.216.34",
            remote_port=443,
            status="ESTABLISHED",
            hostname="api.anthropic.com",
            known_service="Anthropic API",
            is_tls=True,
        )
        assert c.is_tls is True
        assert c.known_service == "Anthropic API"


class TestNetworkSnapshot:
    def test_connection_count(self):
        snap = NetworkSnapshot(
            agent_name="Test",
            pid=123,
            connections=[ConnectionInfo(), ConnectionInfo()],
        )
        assert snap.connection_count == 2

    def test_empty(self):
        snap = NetworkSnapshot(agent_name="Test")
        assert snap.connection_count == 0


class TestClassifyConnection:
    def test_known_domain(self):
        service, is_tls = _classify_connection("1.2.3.4", 443, "api.anthropic.com")
        assert service == "Anthropic API"
        assert is_tls is True

    def test_known_domain_non_tls(self):
        service, is_tls = _classify_connection("1.2.3.4", 80, "api.openai.com")
        assert service == "OpenAI API"
        assert is_tls is False

    def test_unknown_hostname(self):
        service, is_tls = _classify_connection("1.2.3.4", 443, "example.com")
        assert service is None
        assert is_tls is True

    def test_no_hostname(self):
        service, is_tls = _classify_connection("1.2.3.4", 8080, None)
        assert service is None
        assert is_tls is False


class TestCollectConnections:
    def test_none_pid(self):
        assert collect_connections(None) == []

    @patch("riva.core.network.psutil.Process")
    def test_access_denied(self, mock_process):
        import psutil

        mock_process.side_effect = psutil.AccessDenied(123)
        assert collect_connections(123) == []

    @patch("riva.core.network.psutil.Process")
    def test_no_such_process(self, mock_process):
        import psutil

        mock_process.side_effect = psutil.NoSuchProcess(123)
        assert collect_connections(123) == []

    @patch("riva.core.network._reverse_dns", return_value=None)
    @patch("riva.core.network.psutil.Process")
    def test_collects_connections(self, mock_process, mock_dns):
        mock_conn = MagicMock()
        mock_conn.laddr = MagicMock(ip="127.0.0.1", port=5000)
        mock_conn.raddr = MagicMock(ip="93.184.216.34", port=443)
        mock_conn.status = "ESTABLISHED"

        mock_proc = MagicMock()
        mock_proc.net_connections.return_value = [mock_conn]
        mock_process.return_value = mock_proc

        conns = collect_connections(123)
        assert len(conns) == 1
        assert conns[0].remote_port == 443
        assert conns[0].is_tls is True


class TestCollectAllConnections:
    def test_filters_non_running(self):
        instances = [
            AgentInstance(name="Test", status=AgentStatus.INSTALLED),
            AgentInstance(name="Test2", status=AgentStatus.NOT_FOUND),
        ]
        assert collect_all_connections(instances) == []

    @patch("riva.core.network.collect_connections", return_value=[])
    def test_includes_running(self, mock_collect):
        instances = [
            AgentInstance(name="Test", status=AgentStatus.RUNNING, pid=123),
        ]
        result = collect_all_connections(instances)
        assert len(result) == 1
        assert result[0].agent_name == "Test"
        mock_collect.assert_called_once_with(123)


class TestKnownDomains:
    def test_anthropic_in_known(self):
        assert "api.anthropic.com" in KNOWN_API_DOMAINS

    def test_openai_in_known(self):
        assert "api.openai.com" in KNOWN_API_DOMAINS

    def test_cursor_in_known(self):
        assert "api2.cursor.sh" in KNOWN_API_DOMAINS
