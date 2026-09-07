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


# ---------------------------------------------------------------------------
# Multiple servers + defaults (0.3.20)
# ---------------------------------------------------------------------------


def _cfg(url, tenant="t", key="k1234567890"):
    return link.LinkConfig(server_url=url, tenant_id=tenant, api_key=key)


class TestMultiServerStore:
    def test_legacy_single_object_file_is_read_as_one_link(self, tmp_config):
        tmp_config.parent.mkdir(parents=True)
        tmp_config.write_text(
            json.dumps({"server_url": "https://old.co/", "tenant_id": "t0", "api_key": "k0", "audit_cursor": 7})
        )
        links = link.load_links()
        assert [c.server_url for c in links] == ["https://old.co"]
        assert links[0].audit_cursor == 7
        assert link.load_config().server_url == "https://old.co"

    def test_legacy_file_upgrades_to_v2_on_save(self, tmp_config):
        tmp_config.parent.mkdir(parents=True)
        tmp_config.write_text(json.dumps({"server_url": "https://old.co", "tenant_id": "t0", "api_key": "k0"}))
        link.save_config(_cfg("https://rivalabs.ai", "t1"))
        raw = json.loads(tmp_config.read_text())
        assert raw["version"] == 2
        assert [e["server_url"] for e in raw["links"]] == ["https://old.co", "https://rivalabs.ai"]

    def test_save_config_replaces_same_server_keeps_order(self, tmp_config):
        link.save_config(_cfg("https://a.co", "ta"))
        link.save_config(_cfg("https://b.co", "tb"))
        link.save_config(_cfg("https://A.co/", "ta2", "newkey12345"))  # same server, new creds
        links = link.load_links()
        assert [(c.server_url, c.tenant_id) for c in links] == [("https://A.co", "ta2"), ("https://b.co", "tb")]

    def test_load_config_by_url_and_primary(self, tmp_config):
        link.save_config(_cfg("https://a.co", "ta"))
        link.save_config(_cfg("https://b.co", "tb"))
        assert link.load_config().tenant_id == "ta"
        assert link.load_config("https://b.co/").tenant_id == "tb"
        assert link.load_config("https://nope.co") is None
        assert link.is_linked("https://b.co") and not link.is_linked("https://nope.co")

    def test_cursor_save_on_one_link_does_not_touch_the_other(self, tmp_config):
        link.save_config(_cfg("https://a.co", "ta"))
        link.save_config(_cfg("https://b.co", "tb"))
        b = link.load_config("https://b.co")
        b.audit_cursor = 42
        link.save_config(b)
        assert link.load_config("https://a.co").audit_cursor == 0
        assert link.load_config("https://b.co").audit_cursor == 42

    def test_clear_one_leaves_the_rest(self, tmp_config):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))
        assert link.clear_config("https://a.co") is True
        assert [c.server_url for c in link.load_links()] == ["https://b.co"]
        assert link.clear_config("https://a.co") is False
        assert link.clear_config("https://b.co") is True
        assert not tmp_config.exists()

    def test_unlink_one_revokes_only_that_key(self, tmp_config):
        link.save_config(_cfg("https://a.co", key="ka1234567890"))
        link.save_config(_cfg("https://b.co", key="kb1234567890"))
        with patch.object(link, "_request", return_value={}) as m:
            assert link.unlink(revoke=True, server_url="https://a.co") == 1
        assert m.call_count == 1
        assert m.call_args.args[1].startswith("https://a.co/")
        assert m.call_args.kwargs["api_key"] == "ka1234567890"
        assert [c.server_url for c in link.load_links()] == ["https://b.co"]

    def test_unlink_all(self, tmp_config):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))
        with patch.object(link, "_request", return_value={}) as m:
            assert link.unlink(revoke=True) == 2
        assert m.call_count == 2
        assert link.load_links() == []

    def test_sync_all_isolates_failures(self, tmp_config):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))

        def _sync(cfg):
            if cfg.server_url == "https://a.co":
                raise link.LinkError("down")
            return {"audit_ingested": 1, "forensic_sessions": 0}

        with patch.object(link, "sync_once", side_effect=_sync):
            out = link.sync_all()
        assert isinstance(out["https://a.co"], link.LinkError)
        assert out["https://b.co"]["audit_ingested"] == 1


class TestDefaultServer:
    def test_hosted_default(self, monkeypatch):
        monkeypatch.delenv("RIVA_SERVER_URL", raising=False)
        monkeypatch.delenv("RIVA_DEV", raising=False)
        assert link.default_server_url() == "https://rivalabs.ai"
        assert link.is_dev_mode() is False

    def test_dev_mode_points_at_localhost(self, monkeypatch):
        monkeypatch.delenv("RIVA_SERVER_URL", raising=False)
        monkeypatch.setenv("RIVA_DEV", "1")
        assert link.default_server_url() == "http://localhost:8600"
        assert link.is_dev_mode() is True

    def test_env_override_wins(self, monkeypatch):
        monkeypatch.setenv("RIVA_DEV", "1")
        monkeypatch.setenv("RIVA_SERVER_URL", "https://riva.corp.example/")
        assert link.default_server_url() == "https://riva.corp.example"


class TestMultiServerCLI:
    def test_start_without_url_uses_default(self, tmp_config, runner, monkeypatch):
        monkeypatch.delenv("RIVA_SERVER_URL", raising=False)
        monkeypatch.delenv("RIVA_DEV", raising=False)
        with (
            patch.object(link, "start_link", return_value={"pairing_token": "pt"}) as m_start,
            patch.object(link, "redeem_link", return_value=_cfg("https://rivalabs.ai", "t1")),
            patch.object(link, "register_agents", return_value=0),
        ):
            result = runner.invoke(cli, ["link", "start", "--no-wait"])
        assert result.exit_code == 0, result.output
        assert "using https://rivalabs.ai" in result.output
        m_start.assert_called_once_with("https://rivalabs.ai")

    def test_start_without_url_in_dev_mode(self, tmp_config, runner, monkeypatch):
        monkeypatch.delenv("RIVA_SERVER_URL", raising=False)
        monkeypatch.setenv("RIVA_DEV", "1")
        with (
            patch.object(link, "start_link", return_value={"pairing_token": "pt"}) as m_start,
            patch.object(link, "redeem_link", return_value=_cfg("http://localhost:8600", "t1")),
            patch.object(link, "register_agents", return_value=0),
        ):
            result = runner.invoke(cli, ["link", "start", "--no-wait"])
        assert result.exit_code == 0, result.output
        m_start.assert_called_once_with("http://localhost:8600")
        assert "RIVA_DEV" in result.output

    def test_status_lists_every_server(self, tmp_config, runner):
        link.save_config(_cfg("https://a.co", "ta"))
        link.save_config(_cfg("https://b.co", "tb"))
        result = runner.invoke(cli, ["link", "status"])
        assert result.exit_code == 0
        assert "2 server(s)" in result.output
        assert "https://a.co" in result.output and "(primary)" in result.output
        assert "https://b.co" in result.output

    def test_sync_reports_per_server(self, tmp_config, runner):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))
        with patch.object(link, "sync_once", return_value={"audit_ingested": 3, "forensic_sessions": 1}) as m:
            result = runner.invoke(cli, ["link", "sync"])
        assert result.exit_code == 0, result.output
        assert result.output.count("Synced") == 2
        assert m.call_count == 2

    def test_unlink_needs_url_when_several(self, tmp_config, runner):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))
        result = runner.invoke(cli, ["link", "unlink"])
        assert result.exit_code == 1
        assert "riva link unlink https://a.co" in result.output
        with patch.object(link, "_request", return_value={}):
            result = runner.invoke(cli, ["link", "unlink", "https://a.co"])
        assert result.exit_code == 0, result.output
        assert "1 link(s) remain" in result.output
        assert [c.server_url for c in link.load_links()] == ["https://b.co"]

    def test_unlink_all_flag(self, tmp_config, runner):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))
        with patch.object(link, "_request", return_value={}):
            result = runner.invoke(cli, ["link", "unlink", "--all"])
        assert result.exit_code == 0, result.output
        assert "from 2 server(s)" in result.output
        assert not link.is_linked()


class TestMultiServerWeb:
    @pytest.fixture
    def client(self):
        from riva.web.server import create_app

        app = create_app()
        app.config["TESTING"] = True
        return app.test_client()

    def test_status_lists_links_and_default(self, tmp_config, client, monkeypatch):
        monkeypatch.delenv("RIVA_SERVER_URL", raising=False)
        monkeypatch.delenv("RIVA_DEV", raising=False)
        link.save_config(_cfg("https://a.co", "ta"))
        link.save_config(_cfg("https://b.co", "tb"))
        data = client.get("/api/link/status").get_json()
        assert data["linked"] is True
        assert [entry["server_url"] for entry in data["links"]] == ["https://a.co", "https://b.co"]
        assert data["tenant_id"] == "ta"  # primary mirrored at top level
        assert data["default_server_url"] == "https://rivalabs.ai"
        assert data["dev_mode"] is False
        assert all("api_key" not in entry for entry in data["links"])

    def test_unlink_one_via_web(self, tmp_config, client):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))
        with patch.object(link, "_request", return_value={}):
            data = client.post("/api/link/unlink", json={"server_url": "https://a.co"}).get_json()
        assert data["linked"] is True and data["removed"] == 1
        assert [entry["server_url"] for entry in data["links"]] == ["https://b.co"]

    def test_sync_one_vs_all(self, tmp_config, client):
        link.save_config(_cfg("https://a.co"))
        link.save_config(_cfg("https://b.co"))
        with patch.object(link, "sync_once", return_value={"audit_ingested": 1, "forensic_sessions": 0}) as m:
            data = client.post("/api/link/sync", json={"server_url": "https://b.co"}).get_json()
            assert data["ok"] and list(data["servers"]) == ["https://b.co"]
            assert m.call_count == 1
            data = client.post("/api/link/sync").get_json()
            assert data["ok"] and sorted(data["servers"]) == ["https://a.co", "https://b.co"]
            assert data["audit_ingested"] == 2
        resp = client.post("/api/link/sync", json={"server_url": "https://nope.co"})
        assert resp.status_code == 404
