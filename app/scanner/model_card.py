"""
Model card checker.

Looks for a model card (README / MODEL_CARD.md / model-card.md) in the
GitHub repo and scores how complete it is based on required HuggingFace-style
sections.

Max score: 20 points.
"""
from __future__ import annotations
import base64
import re
import requests
from flask import current_app

REQUIRED_SECTIONS = [
    "model description",
    "intended use",
    "limitations",
    "training data",
    "evaluation",
]

CANDIDATE_FILES = ["MODEL_CARD.md", "model_card.md", "model-card.md", "README.md"]

GITHUB_RE = re.compile(r"https?://github\.com/([^/]+)/([^/?\s]+)", re.IGNORECASE)


def _parse_owner_repo(url: str):
    if not url:
        return None
    m = GITHUB_RE.search(url)
    return (m.group(1), m.group(2).rstrip(".git")) if m else None


def _github_headers():
    token = current_app.config.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _fetch_file(owner: str, repo: str, path: str) -> str | None:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    try:
        resp = requests.get(url, headers=_github_headers(), timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            content = data.get("content", "")
            return base64.b64decode(content).decode("utf-8", errors="replace")
    except Exception:
        pass
    return None


def check_model_card(repo_url: str | None) -> dict:
    """Return {'score': 0-20, 'sections_found': list, 'sections_missing': list, 'notes': str}."""
    if not repo_url:
        return {
            "score": 5,
            "sections_found": [],
            "sections_missing": REQUIRED_SECTIONS,
            "notes": "No repository URL; unable to check model card.",
        }

    parsed = _parse_owner_repo(repo_url)
    if not parsed:
        return {
            "score": 5,
            "sections_found": [],
            "sections_missing": REQUIRED_SECTIONS,
            "notes": "Cannot parse GitHub URL.",
        }

    owner, repo = parsed
    content = None
    found_file = None

    for candidate in CANDIDATE_FILES:
        content = _fetch_file(owner, repo, candidate)
        if content:
            found_file = candidate
            break

    if not content:
        return {
            "score": 0,
            "sections_found": [],
            "sections_missing": REQUIRED_SECTIONS,
            "notes": "No model card or README found in repository root.",
        }

    lower = content.lower()
    found = [s for s in REQUIRED_SECTIONS if s in lower]
    missing = [s for s in REQUIRED_SECTIONS if s not in lower]
    ratio = len(found) / len(REQUIRED_SECTIONS)
    score = round(ratio * 20)

    return {
        "score": score,
        "file": found_file,
        "sections_found": found,
        "sections_missing": missing,
        "notes": f"Found {len(found)}/{len(REQUIRED_SECTIONS)} model card sections in '{found_file}'.",
    }
