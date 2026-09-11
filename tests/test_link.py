"""Tests for riva.hub.link — remote Riva Server linking."""

import json
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from riva.cli import cli
from riva.hub import link


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


# ---------------------------------------------------------------------------
# Config store
# ---------------------------------------------------------------------------


class TestConfigStore:
    def test_not_linked_by_default(self, tmp_config):
        assert link.load_config() is None
        assert link.is_linked() is False

    def test_save_and_load(self, tmp_config):
        cfg = link.LinkConfig(server_url="https://riva.co", tenant_id="t1", api_key="secretkey123456")
        link.save_config(cfg)
        assert tmp_config.exists()

        loaded = link.load_config()
        assert loaded is not None
        assert loaded.server_url == "https://riva.co"
        assert loaded.tenant_id == "t1"
        assert loaded.api_key == "secretkey123456"
        assert link.is_linked() is True

    def test_save_strips_trailing_slash_on_load(self, tmp_config):
        link.save_config(link.LinkConfig(server_url="https://riva.co/", tenant_id="t1", api_key="k"))
        assert link.load_config().server_url == "https://riva.co"

    def test_clear(self, tmp_config):
        link.save_config(link.LinkConfig(server_url="https://riva.co", tenant_id="t1", api_key="k"))
        assert link.clear_config() is True
        assert link.is_linked() is False
        assert link.clear_config() is False  # already gone

    def test_incomplete_config_is_none(self, tmp_config):
        tmp_config.parent.mkdir(parents=True, exist_ok=True)
        tmp_config.write_text(json.dumps({"server_url": "https://riva.co"}))
        assert link.load_config() is None

    def test_redacted_masks_api_key(self, tmp_config):
        cfg = link.LinkConfig(server_url="https://riva.co", tenant_id="t1", api_key="abcd1234wxyz")
        r = cfg.redacted()
        assert r["api_key_masked"] == "abcd…wxyz"
        assert "api_key" not in r


# ---------------------------------------------------------------------------
# Pairing handshake
# ---------------------------------------------------------------------------


class TestPairing:
    def test_start_link(self, tmp_config):
        with patch.object(link, "_request", return_value={"pairing_token": "pt1", "code": "ABC-123"}) as m:
            out = link.start_link("https://riva.co/")
        assert out["pairing_token"] == "pt1"
        # trailing slash stripped in URL
        assert m.call_args[0][1] == "https://riva.co/api/v1/pair"

    def test_start_link_missing_token(self, tmp_config):
        with patch.object(link, "_request", return_value={}):
            with pytest.raises(link.LinkError):
                link.start_link("https://riva.co")

    def test_redeem_persists_credentials(self, tmp_config):
        resp = {"tenant_id": "tenant-xyz", "api_key": "key-abc-123456"}
        with patch.object(link, "_request", return_value=resp):
            cfg = link.redeem_link("https://riva.co", "pt1")
        assert cfg.tenant_id == "tenant-xyz"
        assert cfg.api_key == "key-abc-123456"
        assert cfg.linked_at > 0
        # persisted to disk
        assert link.load_config().tenant_id == "tenant-xyz"

    def test_redeem_uses_server_provided_url(self, tmp_config):
        resp = {"tenant_id": "t", "api_key": "k", "server_url": "https://canonical.riva.co"}
        with patch.object(link, "_request", return_value=resp):
            cfg = link.redeem_link("https://riva.co", "pt1")
        assert cfg.server_url == "https://canonical.riva.co"

    def test_redeem_missing_fields(self, tmp_config):
        with patch.object(link, "_request", return_value={"tenant_id": "t"}):
            with pytest.raises(link.LinkError):
                link.redeem_link("https://riva.co", "pt1")

    def test_link_full_flow_auto_approve(self, tmp_config):
        def fake_request(method, url, payload=None, api_key=None):
            if url.endswith("/pair"):
                return {"pairing_token": "pt1"}
            if url.endswith("/link/redeem"):
                return {"tenant_id": "t", "api_key": "k"}
            return {}

        with patch.object(link, "_request", side_effect=fake_request):
            cfg = link.link("https://riva.co", poll=False)
        assert cfg.tenant_id == "t"


# ---------------------------------------------------------------------------
# Heartbeat / agent registration
# ---------------------------------------------------------------------------


class TestHeartbeat:
    def test_build_status_payload_shape(self, tmp_config):
        with patch.object(link, "_collect_agents", return_value=[{"name": "Claude Code", "status": "running"}]):
            payload = link.build_status_payload()
        assert set(payload.keys()) == {"agents", "leases", "health"}
        assert payload["health"]["agent_count"] == 1
        assert payload["health"]["running_count"] == 1
        assert isinstance(payload["leases"], list)

    def test_send_heartbeat_not_linked(self, tmp_config):
        with pytest.raises(link.LinkError):
            link.send_heartbeat()

    def test_send_heartbeat_posts_with_auth(self, tmp_config):
        link.save_config(link.LinkConfig(server_url="https://riva.co", tenant_id="t1", api_key="k1"))
        with (
            patch.object(link, "_request", return_value={"ok": True}) as m,
            patch.object(link, "_collect_agents", return_value=[]),
        ):
            link.send_heartbeat()
        method, url = m.call_args[0][0], m.call_args[0][1]
        assert method == "POST"
        assert url == "https://riva.co/api/v1/tenants/t1/status"
        assert m.call_args[1]["api_key"] == "k1"
        # last_synced was recorded
        assert link.load_config().last_synced > 0

    def test_register_agents(self, tmp_config):
        link.save_config(link.LinkConfig(server_url="https://riva.co", tenant_id="t1", api_key="k1"))
        agents = [{"name": "A"}, {"name": "B"}]
        with (
            patch.object(link, "_collect_agents", return_value=agents),
            patch.object(link, "_request", return_value={}) as m,
        ):
            count = link.register_agents()
        assert count == 2
        assert m.call_args[0][1] == "https://riva.co/api/v1/tenants/t1/agents"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestLinkCLI:
    def test_status_not_linked(self, tmp_config, runner):
        result = runner.invoke(cli, ["link", "status"])
        assert result.exit_code == 0
        assert "Not linked" in result.output

    def test_status_linked(self, tmp_config, runner):
        link.save_config(link.LinkConfig(server_url="https://riva.co", tenant_id="tX", api_key="k1234567890"))
        result = runner.invoke(cli, ["link", "status"])
        assert result.exit_code == 0
        assert "Linked" in result.output
        assert "tX" in result.output

    def test_start_auto_approve(self, tmp_config, runner):
        def fake_request(method, url, payload=None, api_key=None):
            if url.endswith("/pair"):
                return {"pairing_token": "pt1"}
            if url.endswith("/link/redeem"):
                return {"tenant_id": "tenant-1", "api_key": "key-1"}
            return {}

        with (
            patch.object(link, "_request", side_effect=fake_request),
            patch.object(link, "_collect_agents", return_value=[]),
        ):
            result = runner.invoke(cli, ["link", "start", "https://riva.co", "--no-wait"])
        assert result.exit_code == 0, result.output
        assert "Linked" in result.output
        assert link.is_linked()

    def test_unlink(self, tmp_config, runner):
        link.save_config(link.LinkConfig(server_url="https://riva.co", tenant_id="t1", api_key="k"))
        result = runner.invoke(cli, ["link", "unlink"])
        assert result.exit_code == 0
        assert "Unlinked" in result.output
        assert not link.is_linked()

    def test_sync_not_linked(self, tmp_config, runner):
        result = runner.invoke(cli, ["link", "sync"])
        assert result.exit_code == 1
        assert "Not linked" in result.output


# ---------------------------------------------------------------------------
# Web API
# ---------------------------------------------------------------------------


class TestLinkWebAPI:
    @pytest.fixture
    def client(self):
        from riva.web.server import create_app

        app = create_app()
        app.config["TESTING"] = True
        return app.test_client()

    def test_status_endpoint_not_linked(self, tmp_config, client):
        resp = client.get("/api/link/status")
        assert resp.status_code == 200
        assert resp.get_json()["linked"] is False

    def test_status_endpoint_linked(self, tmp_config, client):
        link.save_config(link.LinkConfig(server_url="https://riva.co", tenant_id="tY", api_key="k1234567890"))
        data = client.get("/api/link/status").get_json()
        assert data["linked"] is True
        assert data["tenant_id"] == "tY"
        assert "api_key" not in data  # only masked

    def test_start_requires_url(self, tmp_config, client):
        resp = client.post("/api/link/start", json={})
        assert resp.status_code == 400

    def test_redeem_and_unlink(self, tmp_config, client):
        with (
            patch.object(link, "_request", return_value={"tenant_id": "t", "api_key": "k"}),
            patch.object(link, "_collect_agents", return_value=[]),
        ):
            resp = client.post("/api/link/redeem", json={"server_url": "https://riva.co", "pairing_token": "pt1"})
        assert resp.status_code == 200
        assert resp.get_json()["linked"] is True
        assert link.is_linked()

        resp = client.post("/api/link/unlink")
        assert resp.get_json()["linked"] is False
        assert not link.is_linked()
