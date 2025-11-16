"""Regression tests for Challenge 01: Predictable CRM IDs."""
from __future__ import annotations

from importlib import util
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[3]


def load_module(label: str, relative: str):
    module_path = REPO_ROOT / relative
    spec = util.spec_from_file_location(label, module_path)
    module = util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)  # type: ignore[call-arg]
    return module


vulnerable = load_module(
    "challenge01_vulnerable",
    "challenges/01-Asana-crm-confused-deputy/vulnerable/server.py",
)
secure = load_module(
    "challenge01_secure",
    "challenges/01-Asana-crm-confused-deputy/secure/server.py",
)


def write_projects(tmp_path: Path):
    data = [
        {"project_id": "CRM-1001", "tenant": "tenant_alpha", "name": "Alpha Plan"},
        {"project_id": "CRM-2001", "tenant": "tenant_bravo", "name": "Bravo Secret"},
    ]
    (tmp_path / "projects.json").write_text(
        str(data).replace("'", '"'),
        encoding="utf-8",
    )


def test_vulnerable_fetches_other_tenant(tmp_path: Path):
    vulnerable.DATA_FILE = tmp_path / "projects.json"
    write_projects(tmp_path)
    leak = vulnerable.fetch_project("CRM-1001", "bravo-api-key")
    assert "Alpha Plan" in leak


def test_secure_scopes_to_tenant(tmp_path: Path):
    secure.DATA_FILE = tmp_path / "projects.json"
    write_projects(tmp_path)
    leak_attempt = secure.fetch_project("CRM-1001", "bravo-api-key")
    assert "Alpha Plan" not in leak_attempt
