"""
Bias & fairness disclosure checker.

Scans the README / model card for mentions of fairness, bias, and
demographic considerations. Also flags known high-risk model types.

Max score: 20 points.
"""
from __future__ import annotations
import base64
import re
import requests
from flask import current_app

BIAS_KEYWORDS = [
    "bias", "fairness", "demographic", "gender", "race", "ethnicity",
    "disparity", "equity", "protected attribute", "sensitive attribute",
    "debiasing", "mitigation", "discrimination",
]

HIGH_RISK_TYPES = {"nlp", "computer_vision", "recommendation", "generative"}

GITHUB_RE = re.compile(r"https?://github\.com/([^/]+)/([^/?\s]+)", re.IGNORECASE)


def _parse_owner_repo(url):
    if not url:
        return None
    m = GITHUB_RE.search(url)
    return (m.group(1), m.group(2).rstrip(".git")) if m else None


def _gh_headers():
    token = current_app.config.get("GITHUB_TOKEN", "")
    h = {"Accept": "application/vnd.github+json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


def _fetch_readme(owner, repo) -> str | None:
    for path in ["README.md", "README.rst", "README"]:
        try:
            resp = requests.get(
                f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
                headers=_gh_headers(), timeout=10,
            )
            if resp.status_code == 200:
                return base64.b64decode(resp.json()["content"]).decode("utf-8", errors="replace")
        except Exception:
            pass
    return None


def check_bias(repo_url: str | None, model_type: str | None = None) -> dict:
    high_risk = model_type in HIGH_RISK_TYPES

    if not repo_url:
        base = 10 if not high_risk else 5
        return {
            "score": base,
            "keywords_found": [],
            "high_risk": high_risk,
            "notes": "No repository URL provided. Partial credit.",
        }

    parsed = _parse_owner_repo(repo_url)
    if not parsed:
        return {
            "score": 5,
            "keywords_found": [],
            "high_risk": high_risk,
            "notes": "Cannot parse GitHub URL.",
        }

    owner, repo = parsed
    content = _fetch_readme(owner, repo) or ""

    lower = content.lower()
    found = [kw for kw in BIAS_KEYWORDS if kw in lower]
    ratio = min(len(found) / 4, 1.0)   # 4 keywords = full marks
    score = round(ratio * 20)

    # High-risk model with no bias discussion → penalty
    if high_risk and len(found) < 2:
        score = max(0, score - 5)

    return {
        "score": score,
        "keywords_found": found,
        "high_risk": high_risk,
        "notes": (
            f"Found {len(found)} bias-related keyword(s). "
            + ("High-risk model type requires explicit bias discussion." if high_risk and len(found) < 2 else "")
        ),
    }
