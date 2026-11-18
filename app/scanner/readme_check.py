"""
README quality checker.

Fetches README from GitHub and scores based on length, structure
(headers, code blocks, links), and completeness.

Max score: 20 points.
"""
from __future__ import annotations
import base64
import re
import requests
from flask import current_app

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


def check_readme(repo_url: str | None) -> dict:
    if not repo_url:
        return {
            "score": 5,
            "word_count": 0,
            "headers": 0,
            "code_blocks": 0,
            "links": 0,
            "notes": "No repository URL provided.",
        }

    parsed = _parse_owner_repo(repo_url)
    if not parsed:
        return {
            "score": 5,
            "word_count": 0,
            "headers": 0,
            "code_blocks": 0,
            "links": 0,
            "notes": "Cannot parse GitHub URL.",
        }

    owner, repo = parsed
    content = _fetch_readme(owner, repo)

    if not content:
        return {
            "score": 0,
            "word_count": 0,
            "headers": 0,
            "code_blocks": 0,
            "links": 0,
            "notes": "No README found.",
        }

    word_count = len(content.split())
    headers = len(re.findall(r"^#{1,6}\s", content, re.MULTILINE))
    code_blocks = len(re.findall(r"```", content)) // 2
    links = len(re.findall(r"\[.+?\]\(.+?\)", content))

    score = 0
    score += min(8, (word_count // 100))   # up to 8 pts for length
    score += min(4, headers)               # up to 4 pts for structure
    score += min(4, code_blocks * 2)       # up to 4 pts for code examples
    score += min(4, links)                 # up to 4 pts for references
    score = min(score, 20)

    return {
        "score": score,
        "word_count": word_count,
        "headers": headers,
        "code_blocks": code_blocks,
        "links": links,
        "notes": f"README: {word_count} words, {headers} sections, {code_blocks} code blocks, {links} links.",
    }
