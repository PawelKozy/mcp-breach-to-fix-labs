"""Shared helpers for Challenge 01 (regex DoS)."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

ASSETS_DIR = Path(__file__).resolve().parent / "assets"
LOG_FILE = ASSETS_DIR / "logs" / "requests.log"


@lru_cache(maxsize=1)
def load_log_text() -> str:
    """Return the cached log text."""
    return LOG_FILE.read_text(encoding="utf-8")


def head_lines(limit: int = 5) -> list[str]:
    """Return the first few lines for preview purposes."""
    return load_log_text().splitlines()[:limit]
