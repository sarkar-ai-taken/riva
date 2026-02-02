"""Tests for riva.core.audit."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from riva.core.audit import AuditResult, run_audit


class TestAuditResult:
    def test_dataclass_fields(self):
        r = AuditResult(check="Test", status="pass", detail="All good")
        assert r.check == "Test"
        assert r.status == "pass"
        assert r.detail == "All good"


class TestCheckApiKeyExposure:
    def test_no_secrets(self):
        with patch("riva.core.audit.scan_env_vars", return_value=[]):
            results = run_audit()
        api_results = [r for r in results if r.check == "API Key Exposure"]
        assert len(api_results) == 1
        assert api_results[0].status == "pass"

    def test_secrets_found(self):
        env_vars = [
            {"name": "ANTHROPIC_API_KEY", "value": "****abcd", "raw_length": "51"},
            {"name": "OPENAI_API_KEY", "value": "****efgh", "raw_length": "51"},
        ]
        with patch("riva.core.audit.scan_env_vars", return_value=env_vars), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}):
            mock_reg.return_value.detectors = []
            results = run_audit()
        api_results = [r for r in results if r.check == "API Key Exposure"]
        assert len(api_results) == 1
        assert api_results[0].status == "warn"
        assert "2 secret" in api_results[0].detail
        assert "ANTHROPIC_API_KEY" in api_results[0].detail


class TestCheckConfigDirPermissions:
    def test_no_installed_agents(self):
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}):
            det = MagicMock()
            det.is_installed.return_value = False
            mock_reg.return_value.detectors = [det]
            results = run_audit()
        config_results = [r for r in results if "Config Permissions" in r.check]
        assert len(config_results) == 1
        assert config_results[0].status == "pass"

    def test_secure_permissions(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir(mode=0o700)
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}):
            det = MagicMock()
            det.is_installed.return_value = True
            det.agent_name = "Claude Code"
            det.config_dir = config_dir
            mock_reg.return_value.detectors = [det]
            results = run_audit()
        config_results = [r for r in results if "Config Permissions" in r.check]
        assert len(config_results) == 1
        assert config_results[0].status == "pass"

    def test_insecure_permissions(self, tmp_path):
        config_dir = tmp_path / "config"
        config_dir.mkdir(mode=0o755)
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}):
            det = MagicMock()
            det.is_installed.return_value = True
            det.agent_name = "Claude Code"
            det.config_dir = config_dir
            mock_reg.return_value.detectors = [det]
            results = run_audit()
        config_results = [r for r in results if "Config Permissions" in r.check]
        assert len(config_results) == 1
        assert config_results[0].status == "fail"


class TestCheckDashboardStatus:
    def test_not_running(self):
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}):
            mock_reg.return_value.detectors = []
            results = run_audit()
        dash_results = [r for r in results if r.check == "Dashboard Status"]
        assert len(dash_results) == 1
        assert dash_results[0].status == "pass"

    def test_running(self):
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": True, "pid": 1234}):
            mock_reg.return_value.detectors = []
            results = run_audit()
        dash_results = [r for r in results if r.check == "Dashboard Status"]
        assert len(dash_results) == 1
        assert dash_results[0].status == "warn"
        assert "1234" in dash_results[0].detail


class TestCheckPluginDirectory:
    def test_no_plugin_dir(self, tmp_path):
        fake_path = tmp_path / "plugins"
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}), \
             patch("riva.core.audit.Path") as mock_path_cls:
            mock_path_cls.return_value.expanduser.return_value = fake_path
            mock_reg.return_value.detectors = []
            results = run_audit()
        plugin_results = [r for r in results if "Plugin" in r.check]
        assert len(plugin_results) == 1
        assert plugin_results[0].status == "pass"

    def test_plugin_dir_exists(self, tmp_path):
        plugin_dir = tmp_path / "plugins"
        plugin_dir.mkdir(mode=0o755)
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}), \
             patch("riva.core.audit.Path") as mock_path_cls:
            mock_path_cls.return_value.expanduser.return_value = plugin_dir
            mock_reg.return_value.detectors = []
            results = run_audit()
        plugin_results = [r for r in results if "Plugin" in r.check]
        assert len(plugin_results) >= 1
        assert plugin_results[0].status == "warn"
        assert "arbitrary code" in plugin_results[0].detail


class TestRunAuditIntegration:
    def test_returns_list_of_audit_results(self):
        with patch("riva.core.audit.scan_env_vars", return_value=[]), \
             patch("riva.core.audit.get_default_registry") as mock_reg, \
             patch("riva.core.audit.daemon_status", return_value={"running": False, "pid": None}):
            mock_reg.return_value.detectors = []
            results = run_audit()
        assert isinstance(results, list)
        assert all(isinstance(r, AuditResult) for r in results)
        assert len(results) >= 3  # At least API, config, dashboard, plugin checks
