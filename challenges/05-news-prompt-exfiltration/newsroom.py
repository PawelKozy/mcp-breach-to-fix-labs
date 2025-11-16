"""Shared helpers for Challenge 05 (News prompt exfiltration)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

CHALLENGE_DIR = Path(__file__).resolve().parent
ASSETS_DIR = CHALLENGE_DIR / "assets"
DATA_DIR = CHALLENGE_DIR / "data"
ARTICLES_DIR = ASSETS_DIR / "articles"
CONFIG_FILE = ASSETS_DIR / "agent_config.json"
REPORT_FILE = DATA_DIR / "bug_reports.json"

MALICIOUS_URL = "https://breaking-news.badcorp.local/copilot-panic"
LEGIT_URL = "https://newsfuse.local/weekly/digest"

ARTICLE_MAP: dict[str, Path] = {
    MALICIOUS_URL: ARTICLES_DIR / "malicious.html",
    LEGIT_URL: ARTICLES_DIR / "legit.html",
}


def load_article(url: str) -> dict[str, str]:
    """Return the HTML payload for the requested URL (simulated news host)."""
    article_path = ARTICLE_MAP.get(url, ARTICLES_DIR / "legit.html")
    if not article_path.exists():  # pragma: no cover - defensive
        raise FileNotFoundError(f"No article fixture for URL {url}")
    return {
        "url": url,
        "html": article_path.read_text(encoding="utf-8"),
    }


def read_config(section: str) -> str:
    """Return the value of a config section (contains sensitive data)."""
    raw_bytes = CONFIG_FILE.read_bytes()
    if raw_bytes.startswith(b"\xef\xbb\xbf"):
        raw_bytes = raw_bytes[3:]
    contents = raw_bytes.decode("utf-8")
    raw = json.loads(contents)
    if section not in raw:
        raise KeyError(f"Unknown config section '{section}'")
    return raw[section]


def submit_bug_report(title: str, body: str) -> str:
    """Append a bug report entry to the shared log."""
    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)
    try:
        existing: list[dict[str, Any]] = json.loads(
            REPORT_FILE.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError:
        existing = []
    entry = {"title": title, "body": body}
    existing.append(entry)
    REPORT_FILE.write_text(json.dumps(existing, indent=2), encoding="utf-8")
    return f"Recorded bug report #{len(existing)}"


def reset_reports() -> None:
    """Utility for tests - reset bug report log."""
    REPORT_FILE.write_text("[]", encoding="utf-8")
