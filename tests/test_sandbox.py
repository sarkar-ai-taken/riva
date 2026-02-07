"""Tests for riva.core.sandbox."""

from unittest.mock import MagicMock, patch

import psutil
import pytest

from riva.core.sandbox import (
    SandboxInfo,
    _check_cgroup,
    _check_env,
    _check_parent_chain,
    _extract_container_id,
    detect_sandbox,
)


class TestSandboxInfo:
    def test_host_to_dict(self):
        info = SandboxInfo(is_sandboxed=False, sandbox_type="host")
        d = info.to_dict()
        assert d == {"is_sandboxed": False, "sandbox_type": "host"}
        assert "runtime" not in d
        assert "container_id" not in d

    def test_container_to_dict(self):
        info = SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="docker",
            container_id="abc123def456",
        )
        d = info.to_dict()
        assert d["is_sandboxed"] is True
        assert d["sandbox_type"] == "container"
        assert d["runtime"] == "docker"
        assert d["container_id"] == "abc123def456"

    def test_sandbox_to_dict(self):
        info = SandboxInfo(
            is_sandboxed=True,
            sandbox_type="sandbox",
            runtime="firejail",
        )
        d = info.to_dict()
        assert d["runtime"] == "firejail"
        assert "container_id" not in d


class TestExtractContainerId:
    def test_docker_cgroup(self):
        content = "12:devices:/docker/abc123def456789abcdef0123456789\n"
        cid = _extract_container_id(content, "/docker/")
        assert cid == "abc123def456"

    def test_libpod_cgroup(self):
        content = "1:name=systemd:/libpod-fedcba987654321fedcba987654321.scope\n"
        cid = _extract_container_id(content, "/libpod-")
        assert cid == "fedcba987654"

    def test_no_match(self):
        content = "1:name=systemd:/user.slice/user-1000.slice\n"
        cid = _extract_container_id(content, "/docker/")
        assert cid is None

    def test_short_id_ignored(self):
        content = "12:devices:/docker/short\n"
        cid = _extract_container_id(content, "/docker/")
        assert cid is None


class TestCheckCgroup:
    def test_docker_detected(self, tmp_path):
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("12:devices:/docker/abc123def456789\n")
        with patch("riva.core.sandbox.Path") as MockPath:
            MockPath.return_value = cgroup
            result = _check_cgroup(1)
        assert result is not None
        assert result.runtime == "docker"
        assert result.is_sandboxed is True

    def test_podman_detected(self, tmp_path):
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("1:name=systemd:/libpod-abc123def456789.scope\n")
        with patch("riva.core.sandbox.Path") as MockPath:
            MockPath.return_value = cgroup
            result = _check_cgroup(1)
        assert result is not None
        assert result.runtime == "podman"

    def test_containerd_detected(self, tmp_path):
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("1:name=systemd:/containerd/abc123\n")
        with patch("riva.core.sandbox.Path") as MockPath:
            MockPath.return_value = cgroup
            result = _check_cgroup(1)
        assert result is not None
        assert result.runtime == "containerd"

    def test_lxc_detected(self, tmp_path):
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("1:name=systemd:/lxc/mycontainer\n")
        with patch("riva.core.sandbox.Path") as MockPath:
            MockPath.return_value = cgroup
            result = _check_cgroup(1)
        assert result is not None
        assert result.runtime == "lxc"

    def test_host_cgroup(self, tmp_path):
        cgroup = tmp_path / "cgroup"
        cgroup.write_text("1:name=systemd:/user.slice/user-1000.slice\n")
        with patch("riva.core.sandbox.Path") as MockPath:
            MockPath.return_value = cgroup
            result = _check_cgroup(1)
        assert result is None

    def test_no_proc_file(self):
        with patch("riva.core.sandbox.Path") as MockPath:
            mock_path = MagicMock()
            mock_path.exists.return_value = False
            MockPath.return_value = mock_path
            result = _check_cgroup(1)
        assert result is None


class TestCheckParentChain:
    def test_docker_parent(self):
        mock_proc = MagicMock()
        docker_parent = MagicMock()
        docker_parent.name.return_value = "dockerd"
        mock_proc.parents.return_value = [docker_parent]

        result = _check_parent_chain(mock_proc)
        assert result is not None
        assert result.runtime == "docker"
        assert result.sandbox_type == "container"

    def test_firejail_parent(self):
        mock_proc = MagicMock()
        fj_parent = MagicMock()
        fj_parent.name.return_value = "firejail"
        mock_proc.parents.return_value = [fj_parent]

        result = _check_parent_chain(mock_proc)
        assert result is not None
        assert result.runtime == "firejail"
        assert result.sandbox_type == "sandbox"

    def test_no_sandbox_parent(self):
        mock_proc = MagicMock()
        bash_parent = MagicMock()
        bash_parent.name.return_value = "bash"
        mock_proc.parents.return_value = [bash_parent]

        result = _check_parent_chain(mock_proc)
        assert result is None

    def test_access_denied(self):
        mock_proc = MagicMock()
        mock_proc.parents.side_effect = psutil.AccessDenied(pid=1)
        result = _check_parent_chain(mock_proc)
        assert result is None


class TestCheckEnv:
    def test_kubernetes(self):
        mock_proc = MagicMock()
        mock_proc.environ.return_value = {"KUBERNETES_SERVICE_HOST": "10.0.0.1"}
        result = _check_env(mock_proc)
        assert result is not None
        assert result.runtime == "kubernetes"

    def test_container_env(self):
        mock_proc = MagicMock()
        mock_proc.environ.return_value = {"container": "podman"}
        result = _check_env(mock_proc)
        assert result is not None
        assert result.runtime == "podman"

    def test_no_container_env(self):
        mock_proc = MagicMock()
        mock_proc.environ.return_value = {"HOME": "/home/user"}
        result = _check_env(mock_proc)
        assert result is None

    def test_access_denied(self):
        mock_proc = MagicMock()
        mock_proc.environ.side_effect = psutil.AccessDenied(pid=1)
        result = _check_env(mock_proc)
        assert result is None


class TestDetectSandbox:
    def test_no_such_process(self):
        with patch("riva.core.sandbox.psutil.Process", side_effect=psutil.NoSuchProcess(pid=99999)):
            result = detect_sandbox(99999)
        assert result.is_sandboxed is False
        assert result.sandbox_type == "host"

    def test_host_process(self):
        mock_proc = MagicMock()
        mock_proc.parents.return_value = [MagicMock(name=MagicMock(return_value="bash"))]
        mock_proc.environ.return_value = {"HOME": "/home/user"}

        with (
            patch("riva.core.sandbox.psutil.Process", return_value=mock_proc),
            patch("riva.core.sandbox._check_cgroup", return_value=None),
            patch("riva.core.sandbox.Path") as MockPath,
        ):
            MockPath.return_value.exists.return_value = False
            result = detect_sandbox(123)

        assert result.is_sandboxed is False
        assert result.sandbox_type == "host"

    def test_cgroup_docker(self):
        mock_proc = MagicMock()
        docker_info = SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="docker",
            container_id="abc123def456",
        )

        with (
            patch("riva.core.sandbox.psutil.Process", return_value=mock_proc),
            patch("riva.core.sandbox._check_cgroup", return_value=docker_info),
        ):
            result = detect_sandbox(123)

        assert result.is_sandboxed is True
        assert result.runtime == "docker"
        assert result.container_id == "abc123def456"

    def test_parent_chain_fallback(self):
        mock_proc = MagicMock()
        sandbox_info = SandboxInfo(
            is_sandboxed=True,
            sandbox_type="container",
            runtime="podman",
        )

        with (
            patch("riva.core.sandbox.psutil.Process", return_value=mock_proc),
            patch("riva.core.sandbox._check_cgroup", return_value=None),
            patch("riva.core.sandbox._check_parent_chain", return_value=sandbox_info),
        ):
            result = detect_sandbox(123)

        assert result.is_sandboxed is True
        assert result.runtime == "podman"

    def test_dockerenv_fallback(self):
        mock_proc = MagicMock()
        mock_proc.parents.return_value = []
        mock_proc.environ.return_value = {}

        with (
            patch("riva.core.sandbox.psutil.Process", return_value=mock_proc),
            patch("riva.core.sandbox._check_cgroup", return_value=None),
            patch("riva.core.sandbox._check_parent_chain", return_value=None),
            patch("riva.core.sandbox.Path") as MockPath,
        ):
            # /.dockerenv exists
            def path_side_effect(p):
                mock = MagicMock()
                mock.exists.return_value = str(p) == "/.dockerenv"
                return mock

            MockPath.side_effect = path_side_effect
            result = detect_sandbox(123)

        assert result.is_sandboxed is True
        assert result.runtime == "docker"
