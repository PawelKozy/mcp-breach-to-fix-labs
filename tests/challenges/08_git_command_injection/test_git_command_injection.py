"""Regression tests for Challenge 08: Git command injection."""
from __future__ import annotations

from importlib import util
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import subprocess


REPO_ROOT = Path(__file__).resolve().parents[3]


def load_module(label: str, relative: str):
    module_path = REPO_ROOT / relative
    spec = util.spec_from_file_location(label, module_path)
    module = util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)  # type: ignore[call-arg]
    return module


vulnerable = load_module(
    "challenge08_vulnerable",
    "challenges/08-git-command-injection-ghsa-3q26-f695-pp76/vulnerable/server.py",
)
secure = load_module(
    "challenge08_secure",
    "challenges/08-git-command-injection-ghsa-3q26-f695-pp76/secure/server.py",
)


def _fake_completed(stdout: str = "", stderr: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


def test_vulnerable_repo_name_leaks_secret(monkeypatch, tmp_path: Path):
    """Vulnerable build concatenates repo_name into a shell command."""
    monkeypatch.setattr(vulnerable, "REPO_ROOT", tmp_path)
    captured: dict[str, Any] = {}

    def fake_run(command: str):
        captured["command"] = command
        return _fake_completed(stdout="secret_token")

    monkeypatch.setattr(vulnerable, "_run_shell", fake_run)

    payload = (
        "mirror && python -c \"import pathlib;print(pathlib.Path('/app/secrets/deployment_token.txt').read_text())\""
    )
    response = vulnerable.init_bare_repository(payload)

    assert "secret_token" in response
    assert "python -c" in captured["command"]


def test_secure_rejects_injection_payload(monkeypatch, tmp_path: Path):
    """Secure build validates names and never executes shell metacharacters."""
    monkeypatch.setattr(secure, "REPO_ROOT", tmp_path)
    called = {"run": False}

    def fake_run(args):
        called["run"] = True
        return _fake_completed(stdout="initialized")

    monkeypatch.setattr(secure, "_run_git", fake_run)

    payload = (
        "mirror && python -c \"import pathlib;print(pathlib.Path('/app/secrets/deployment_token.txt').read_text())\""
    )
    response = secure.init_bare_repository(payload)

    assert "Invalid repository name" in response
    assert called["run"] is False


def test_secure_initializes_valid_repo(monkeypatch, tmp_path: Path):
    """Secure build still works for legitimate names."""
    monkeypatch.setattr(secure, "REPO_ROOT", tmp_path)

    def fake_run(args):
        return _fake_completed(stdout="Initialized empty Git repository")

    monkeypatch.setattr(secure, "_run_git", fake_run)
    response = secure.init_bare_repository("observability")

    assert "Initialized empty Git repository" in response
