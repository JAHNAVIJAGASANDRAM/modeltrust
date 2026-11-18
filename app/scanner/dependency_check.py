"""
Dependency vulnerability checker.

Fetches requirements.txt / pyproject.toml / package.json from the repo and
checks for packages on a known-vulnerable list (self-contained, no external
API required so it always works offline).

Max score: 20 points.
"""
from __future__ import annotations
import base64
import re
import requests
from flask import current_app

# A representative set of known-vulnerable packages / versions for demonstration.
# In production this would be backed by OSV, PyPI Advisory DB, or Snyk.
KNOWN_VULNERABLE: dict[str, list[str]] = {
    "pillow": ["< 9.3.0"],
    "pyyaml": ["< 6.0"],
    "requests": ["< 2.20.0"],
    "numpy": ["< 1.22.0"],
    "tensorflow": ["< 2.9.0"],
    "torch": ["< 1.13.0"],
    "flask": ["< 2.3.0"],
    "django": ["< 3.2.0"],
    "cryptography": ["< 41.0.0"],
    "paramiko": ["< 3.0.0"],
}

GITHUB_RE = re.compile(r"https?://github\.com/([^/]+)/([^/?\s]+)", re.IGNORECASE)
CANDIDATE_FILES = ["requirements.txt", "pyproject.toml", "package.json", "setup.cfg"]


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


def _fetch(owner, repo, path) -> str | None:
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


def _extract_packages(content: str, filename: str) -> list[str]:
    """Return list of lowercase package names from dependency file content."""
    packages: list[str] = []
    if filename.endswith("requirements.txt") or filename.endswith("setup.cfg"):
        for line in content.splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name = re.split(r"[>=<!;\[]", line)[0].strip().lower()
                if name:
                    packages.append(name)
    elif "pyproject.toml" in filename:
        for m in re.finditer(r'"([a-zA-Z0-9_\-]+)\s*[>=<!]', content):
            packages.append(m.group(1).lower())
    elif "package.json" in filename:
        for m in re.finditer(r'"([a-zA-Z0-9_\-@/]+)"\s*:', content):
            packages.append(m.group(1).lower())
    return packages


def check_dependencies(repo_url: str | None) -> dict:
    if not repo_url:
        return {
            "score": 10,
            "vulnerable": [],
            "checked": [],
            "dep_file": None,
            "notes": "No repository URL; partial credit.",
        }

    parsed = _parse_owner_repo(repo_url)
    if not parsed:
        return {
            "score": 10,
            "vulnerable": [],
            "checked": [],
            "dep_file": None,
            "notes": "Cannot parse GitHub URL; partial credit.",
        }

    owner, repo = parsed
    content = dep_file = None

    for f in CANDIDATE_FILES:
        content = _fetch(owner, repo, f)
        if content:
            dep_file = f
            break

    if not content:
        return {
            "score": 15,
            "vulnerable": [],
            "checked": [],
            "dep_file": None,
            "notes": "No dependency file found — cannot verify. Partial credit.",
        }

    packages = _extract_packages(content, dep_file)
    vulnerable = [p for p in packages if p in KNOWN_VULNERABLE]

    score = 20 if not vulnerable else max(0, 20 - len(vulnerable) * 5)
    return {
        "score": score,
        "vulnerable": vulnerable,
        "checked": packages,
        "dep_file": dep_file,
        "notes": (
            f"Checked {len(packages)} packages in '{dep_file}'. "
            f"{'No known vulnerabilities.' if not vulnerable else f'{len(vulnerable)} potentially vulnerable package(s) found: ' + ', '.join(vulnerable)}"
        ),
    }
