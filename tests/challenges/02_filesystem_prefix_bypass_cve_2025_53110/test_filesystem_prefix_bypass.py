"""Regression tests for Challenge 02: Filesystem Prefix Bypass."""
from __future__ import annotations

from importlib import util
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]


def load_module(label: str, relative: str):
    module_path = REPO_ROOT / relative
    spec = util.spec_from_file_location(label, module_path)
    module = util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)  # type: ignore[call-arg]
    return module


vulnerable = load_module(
    "challenge02_vulnerable",
    "challenges/02-filesystem-prefix-bypass-cve-2025-53110/vulnerable/server.py",
)
secure = load_module(
    "challenge02_secure",
    "challenges/02-filesystem-prefix-bypass-cve-2025-53110/secure/server.py",
)


def _prepare_prefix_collision(tmp_path: Path, module):
    """Create directories whose names collide but should remain isolated."""
    allowed_dir = tmp_path / "sandbox" / "safe_files"
    sensitive_dir = Path(f"{allowed_dir}_sensitive")
    allowed_dir.mkdir(parents=True)
    sensitive_dir.mkdir(parents=True)

    (allowed_dir / "manifest.txt").write_text("ok\n", encoding="utf-8")
    (sensitive_dir / "secret.txt").write_text("FLAG{unit_test_secret}\n", encoding="utf-8")

    module.ALLOWED_DIR = str(allowed_dir)
    return allowed_dir, sensitive_dir


def test_vulnerable_accepts_colliding_prefix(tmp_path: Path):
    """CVE-2025-53110 regression: naive startswith bypasses containment."""
    _, secret_dir = _prepare_prefix_collision(tmp_path, vulnerable)

    result = vulnerable.list_directory_contents(str(secret_dir))

    assert "secret.txt" in result
    assert "Access denied" not in result


def test_secure_rejects_colliding_prefix(tmp_path: Path):
    """Secure build resolves real paths and refuses access outside the base directory."""
    allowed_dir, secret_dir = _prepare_prefix_collision(tmp_path, secure)

    denied = secure.list_directory_contents(str(secret_dir))
    assert "Access denied" in denied

    allowed_listing = secure.list_directory_contents(str(allowed_dir))
    assert "manifest.txt" in allowed_listing
    assert "secret.txt" not in allowed_listing
