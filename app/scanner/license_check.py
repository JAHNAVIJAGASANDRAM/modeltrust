"""
License checker.

Fetches the LICENSE file from a GitHub repo via the API and determines
whether the license is OSI-approved. Falls back gracefully if no token or
no network.

Max score: 20 points.
"""
from __future__ import annotations
import re
import requests
from flask import current_app

OSI_APPROVED = {
    "mit", "apache-2.0", "gpl-2.0", "gpl-3.0", "lgpl-2.1", "lgpl-3.0",
    "bsd-2-clause", "bsd-3-clause", "mpl-2.0", "agpl-3.0", "epl-2.0",
    "cddl-1.0", "eupl-1.2", "isc", "cc0-1.0", "unlicense",
}

GITHUB_RE = re.compile(
    r"https?://github\.com/([^/]+)/([^/?\s]+)", re.IGNORECASE
)


def _parse_owner_repo(url: str) -> tuple[str, str] | None:
    if not url:
        return None
    m = GITHUB_RE.search(url)
    if m:
        return m.group(1), m.group(2).rstrip(".git")
    return None


def _github_headers() -> dict:
    token = current_app.config.get("GITHUB_TOKEN", "")
    headers = {"Accept": "application/vnd.github+json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def check_license(repo_url: str | None) -> dict:
    """Return {'score': 0-20, 'license': str, 'osi_approved': bool, 'notes': str}."""
    if not repo_url:
        return {
            "score": 5,
            "license": "Unknown",
            "osi_approved": False,
            "notes": "No repository URL provided. Partial credit for submission.",
        }

    parsed = _parse_owner_repo(repo_url)
    if not parsed:
        return {
            "score": 5,
            "license": "Unknown",
            "osi_approved": False,
            "notes": "Could not parse GitHub owner/repo from URL.",
        }

    owner, repo = parsed
    try:
        resp = requests.get(
            f"https://api.github.com/repos/{owner}/{repo}/license",
            headers=_github_headers(),
            timeout=10,
        )
        if resp.status_code == 200:
            data = resp.json()
            spdx = data.get("license", {}).get("spdx_id", "")
            name = data.get("license", {}).get("name", "Unknown")
            osi = spdx.lower() in OSI_APPROVED
            score = 20 if osi else 10
            return {
                "score": score,
                "license": name,
                "osi_approved": osi,
                "notes": f"License '{name}' {'is' if osi else 'is NOT'} OSI-approved.",
            }
        elif resp.status_code == 404:
            return {
                "score": 0,
                "license": "None found",
                "osi_approved": False,
                "notes": "No LICENSE file detected in the repository.",
            }
        else:
            raise ValueError(f"GitHub API returned {resp.status_code}")
    except Exception as exc:
        return {
            "score": 10,
            "license": "Unknown",
            "osi_approved": False,
            "notes": f"Could not fetch license info: {exc}. Partial credit awarded.",
        }
