"""Tests for the `riva fleet` CLI — tenant-key (linked) vs legacy client-key paths."""

from unittest.mock import patch

import pytest
from click.testing import CliRunner

from riva.cli import cli
from riva.hub import fleet_report, link


@pytest.fixture
def tmp_config(tmp_path, monkeypatch):
    """Redirect the link config to a temp file for the duration of a test."""
    cfg_dir = tmp_path / ".riva"
    cfg_file = cfg_dir / "server-link.json"
    monkeypatch.setattr(link, "CONFIG_DIR", cfg_dir)
    monkeypatch.setattr(link, "CONFIG_FILE", cfg_file)
    return cfg_file


@pytest.fixture
def runner():
    return CliRunner()


def _link_machine(url="https://riva.co"):
    cfg = link.LinkConfig(server_url=url, tenant_id="t1", api_key="rvt_secret1234567890")
    link.save_config(cfg)
    return cfg


class TestFleetCLI:
    def test_linked_uses_tenant_key_path(self, tmp_config, runner):
        _link_machine()
        with (
            patch.object(link, "send_security_findings", return_value=3) as m_sec,
            patch.object(link, "send_usage_rollups", return_value=2) as m_use,
            patch.object(fleet_report, "report_once") as m_legacy,
        ):
            result = runner.invoke(cli, ["fleet"])
        assert result.exit_code == 0, result.output
        assert "Pushed" in result.output
        assert "3 findings" in result.output
        assert "2 usage rollups" in result.output
        assert "https://riva.co" in result.output
        # No-arg calls: each push reloads the config rather than writing back
        # a stale startup snapshot over the heartbeat daemon's sync cursors.
        m_sec.assert_called_once_with()
        m_use.assert_called_once_with()
        m_legacy.assert_not_called()

    def test_linked_explicit_server_matching_uses_tenant_key_path(self, tmp_config, runner):
        _link_machine()
        with (
            patch.object(link, "send_security_findings", return_value=1) as m_sec,
            patch.object(link, "send_usage_rollups", return_value=0) as m_use,
            patch.object(fleet_report, "report_once") as m_legacy,
        ):
            # Trailing slash should still match the linked server.
            result = runner.invoke(cli, ["fleet", "--server", "https://riva.co/"])
        assert result.exit_code == 0, result.output
        assert "1 findings" in result.output
        m_sec.assert_called_once()
        m_use.assert_called_once()
        m_legacy.assert_not_called()

    def test_not_linked_explicit_server_uses_legacy_path(self, tmp_config, runner):
        with (
            patch.object(link, "send_security_findings") as m_sec,
            patch.object(
                fleet_report, "report_once", return_value={"security_findings": 5, "usage_rollups": 4}
            ) as m_legacy,
        ):
            result = runner.invoke(cli, ["fleet", "--server", "https://other.co", "--org", "acme"])
        assert result.exit_code == 0, result.output
        assert "5 findings" in result.output
        assert "4 usage rollups" in result.output
        assert "https://other.co" in result.output
        m_legacy.assert_called_once_with("https://other.co", "acme", lat=None, lon=None)
        m_sec.assert_not_called()

    def test_linked_explicit_other_server_uses_legacy_path(self, tmp_config, runner):
        _link_machine()
        with (
            patch.object(link, "send_security_findings") as m_sec,
            patch.object(
                fleet_report, "report_once", return_value={"security_findings": 0, "usage_rollups": 0}
            ) as m_legacy,
        ):
            result = runner.invoke(cli, ["fleet", "--server", "https://other.co"])
        assert result.exit_code == 0, result.output
        assert "https://other.co" in result.output
        m_legacy.assert_called_once()
        m_sec.assert_not_called()

    def test_linked_warns_when_org_and_coords_ignored(self, tmp_config, runner):
        _link_machine()
        with (
            patch.object(link, "send_security_findings", return_value=0),
            patch.object(link, "send_usage_rollups", return_value=0),
        ):
            result = runner.invoke(cli, ["fleet", "--org", "acme-ai", "--lat", "40.7", "--lon", "-74.0"])
        assert result.exit_code == 0, result.output
        assert "ignored on the linked path" in result.output

    def test_corrupt_link_config_falls_back_to_legacy_path(self, tmp_config, runner):
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text("[1, 2]\n")  # valid JSON, wrong shape
        with patch.object(
            fleet_report, "report_once", return_value={"security_findings": 0, "usage_rollups": 0}
        ) as m_legacy:
            result = runner.invoke(cli, ["fleet", "--server", "https://other.co"])
        assert result.exit_code == 0, result.output
        m_legacy.assert_called_once()

    def test_not_linked_no_server_fails(self, tmp_config, runner):
        result = runner.invoke(cli, ["fleet"])
        assert result.exit_code == 1
        assert "No server URL" in result.output

    def test_linked_push_failure_exits_nonzero(self, tmp_config, runner):
        _link_machine()
        with patch.object(link, "send_security_findings", side_effect=link.LinkError("boom")):
            result = runner.invoke(cli, ["fleet"])
        assert result.exit_code == 1
        assert "Fleet report failed" in result.output
