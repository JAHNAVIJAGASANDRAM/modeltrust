"""GitHub repository metadata fetcher and safe archive downloader."""
from __future__ import annotations

import io
import stat
import zipfile
from pathlib import Path
from typing import Any

import requests

from config import Config
from utils.logger import get_logger
from utils.validators import ValidationError, safe_join_path

logger = get_logger("modeltrust.acquisition.github")

GITHUB_API_BASE = "https://api.github.com"


def _github_headers() -> dict[str, str]:
    headers = {
        "Accept": "application/vnd.github+json",
        "User-Agent": "ModelTrust-Security-Scanner/1.0",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if Config.GITHUB_TOKEN:
        headers["Authorization"] = f"Bearer {Config.GITHUB_TOKEN}"
    return headers


def fetch_github_metadata(owner: str, repo: str) -> dict[str, Any]:
    """Fetch repository metadata, owner profile, releases, and recent commits from GitHub API."""
    headers = _github_headers()
    timeout = Config.HTTP_TIMEOUT_SECONDS

    repo_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}"
    resp = requests.get(repo_url, headers=headers, timeout=timeout)

    if resp.status_code == 404:
        raise ValueError(f"GitHub repository '{owner}/{repo}' not found or is private.")
    if resp.status_code == 403 and "rate limit" in resp.text.lower():
        raise RuntimeError(
            "GitHub API rate limit exceeded. Configure GITHUB_TOKEN in .env for higher limits."
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"GitHub API error (HTTP {resp.status_code}): {resp.text[:200]}")

    repo_data = resp.json()
    default_branch = repo_data.get("default_branch") or "main"

    # Fetch owner/publisher profile (best-effort)
    owner_profile: dict[str, Any] = {}
    owner_info = repo_data.get("owner") or {}
    try:
        u_resp = requests.get(f"{GITHUB_API_BASE}/users/{owner}", headers=headers, timeout=timeout)
        if u_resp.status_code == 200:
            u_data = u_resp.json()
            owner_profile = {
                "login": u_data.get("login"),
                "name": u_data.get("name"),
                "type": u_data.get("type"),
                "company": u_data.get("company"),
                "blog": u_data.get("blog"),
                "is_verified": u_data.get("is_verified"),
                "created_at": u_data.get("created_at"),
                "public_repos": u_data.get("public_repos"),
            }
    except requests.RequestException as exc:
        logger.warning("Could not fetch GitHub owner profile for %s: %s", owner, exc)

    # Fetch releases (up to 10)
    releases: list[dict[str, Any]] = []
    try:
        r_resp = requests.get(
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}/releases",
            headers=headers,
            params={"per_page": 10},
            timeout=timeout,
        )
        if r_resp.status_code == 200:
            for rel in r_resp.json():
                releases.append({
                    "tag_name": rel.get("tag_name"),
                    "name": rel.get("name"),
                    "published_at": rel.get("published_at"),
                    "prerelease": bool(rel.get("prerelease")),
                    "draft": bool(rel.get("draft")),
                    "author": (rel.get("author") or {}).get("login"),
                })
    except requests.RequestException as exc:
        logger.warning("Could not fetch releases for %s/%s: %s", owner, repo, exc)

    # Fetch recent commits (up to 15) including cryptographic commit signature status
    commits: list[dict[str, Any]] = []
    try:
        c_resp = requests.get(
            f"{GITHUB_API_BASE}/repos/{owner}/{repo}/commits",
            headers=headers,
            params={"sha": default_branch, "per_page": 15},
            timeout=timeout,
        )
        if c_resp.status_code == 200:
            for item in c_resp.json():
                commit_obj = item.get("commit") or {}
                verification = commit_obj.get("verification") or {}
                author_obj = commit_obj.get("author") or {}
                commits.append({
                    "sha": (item.get("sha") or "")[:12],
                    "author_name": author_obj.get("name"),
                    "author_email": author_obj.get("email"),
                    "author_login": (item.get("author") or {}).get("login"),
                    "date": author_obj.get("date"),
                    "message": (commit_obj.get("message") or "").splitlines()[0][:120],
                    "verified_signature": bool(verification.get("verified")),
                    "verification_reason": verification.get("reason"),
                })
    except requests.RequestException as exc:
        logger.warning("Could not fetch commits for %s/%s: %s", owner, repo, exc)

    license_obj = repo_data.get("license") or {}

    return {
        "platform": "github",
        "owner": owner_info.get("login") or owner,
        "owner_type": owner_info.get("type") or owner_profile.get("type") or "Unknown",
        "owner_profile": owner_profile,
        "repo_name": repo_data.get("name") or repo,
        "full_name": repo_data.get("full_name") or f"{owner}/{repo}",
        "repository_url": repo_data.get("html_url") or f"https://github.com/{owner}/{repo}",
        "description": repo_data.get("description") or "",
        "default_branch": default_branch,
        "created_at": repo_data.get("created_at"),
        "updated_at": repo_data.get("updated_at"),
        "pushed_at": repo_data.get("pushed_at"),
        "archived": bool(repo_data.get("archived")),
        "disabled": bool(repo_data.get("disabled")),
        "is_fork": bool(repo_data.get("fork")),
        "visibility": repo_data.get("visibility") or ("private" if repo_data.get("private") else "public"),
        "license": {
            "name": license_obj.get("name"),
            "spdx_id": license_obj.get("spdx_id"),
        } if license_obj else None,
        "topics": repo_data.get("topics") or [],
        "language": repo_data.get("language"),
        "size_kb": repo_data.get("size"),
        "releases": releases,
        "commits": commits,
        "remote_files": [],
    }


def download_github_repository(
    owner: str,
    repo: str,
    branch: str,
    dest_dir: Path,
) -> dict[str, Any]:
    """
    Download GitHub zipball with strict size limits, file-count caps, and Zip Slip protection.
    Never executes any downloaded code.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    zip_url = f"{GITHUB_API_BASE}/repos/{owner}/{repo}/zipball/{branch}"
    headers = _github_headers()

    downloaded_bytes = 0
    buffer = io.BytesIO()
    truncated_archive = False

    with requests.get(zip_url, headers=headers, stream=True, timeout=Config.HTTP_TIMEOUT_SECONDS) as resp:
        if resp.status_code >= 400:
            raise RuntimeError(f"Failed to download GitHub archive (HTTP {resp.status_code}).")

        content_length = resp.headers.get("Content-Length")
        if content_length and content_length.isdigit():
            if int(content_length) > Config.MAX_DOWNLOAD_SIZE_BYTES:
                raise ValueError(
                    f"Repository archive size ({int(content_length) // (1024 * 1024)} MB) "
                    f"exceeds maximum allowed limit ({Config.MAX_DOWNLOAD_SIZE_MB} MB)."
                )

        for chunk in resp.iter_content(chunk_size=65536):
            if not chunk:
                continue
            downloaded_bytes += len(chunk)
            if downloaded_bytes > Config.MAX_DOWNLOAD_SIZE_BYTES:
                raise ValueError(
                    f"Repository download exceeded maximum allowed size of {Config.MAX_DOWNLOAD_SIZE_MB} MB."
                )
            buffer.write(chunk)

    buffer.seek(0)
    extracted_files: list[str] = []
    skipped_files: list[dict[str, str]] = []
    total_extracted_bytes = 0

    with zipfile.ZipFile(buffer) as zf:
        infos = zf.infolist()
        for info in infos:
            if info.is_dir():
                continue

            # Skip symbolic links inside zip archives
            unix_mode = info.external_attr >> 16
            if stat.S_ISLNK(unix_mode):
                skipped_files.append({"path": info.filename, "reason": "symlink skipped for security"})
                continue

            if len(extracted_files) >= Config.MAX_FILE_COUNT:
                truncated_archive = True
                skipped_files.append({"path": info.filename, "reason": "max file count limit reached"})
                continue

            if info.file_size > Config.MAX_SINGLE_FILE_BYTES:
                skipped_files.append({
                    "path": info.filename,
                    "reason": f"exceeds single file limit ({Config.MAX_SINGLE_FILE_MB} MB)",
                })
                continue

            if total_extracted_bytes + info.file_size > Config.MAX_DOWNLOAD_SIZE_BYTES * 2:
                skipped_files.append({"path": info.filename, "reason": "decompressed size limit reached"})
                truncated_archive = True
                continue

            # Strip GitHub's top-level '<owner>-<repo>-<sha>/' wrapper directory
            parts = info.filename.replace("\\", "/").split("/", 1)
            rel_path = parts[1] if len(parts) == 2 and parts[1] else parts[0]
            if not rel_path:
                continue

            try:
                target_path = safe_join_path(dest_dir, rel_path)
            except ValidationError as exc:
                logger.warning("Blocked unsafe archive entry '%s': %s", info.filename, exc)
                skipped_files.append({"path": info.filename, "reason": str(exc)})
                continue

            target_path.parent.mkdir(parents=True, exist_ok=True)
            with zf.open(info, "r") as src, open(target_path, "wb") as dst:
                while True:
                    data = src.read(65536)
                    if not data:
                        break
                    dst.write(data)
                    total_extracted_bytes += len(data)

            extracted_files.append(rel_path)

    return {
        "local_path": str(dest_dir),
        "file_count": len(extracted_files),
        "total_size_bytes": total_extracted_bytes,
        "extracted_files": extracted_files,
        "skipped_files": skipped_files,
        "truncated": truncated_archive,
    }
