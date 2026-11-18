"""Hugging Face Hub repository metadata fetcher and safe bounded file downloader."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from urllib.parse import quote

import requests

from config import Config
from utils.logger import get_logger
from utils.validators import ValidationError, safe_join_path

logger = get_logger("modeltrust.acquisition.huggingface")

HF_API_BASE = "https://huggingface.co/api"
HF_WEB_BASE = "https://huggingface.co"

# Prioritize security-relevant files first when downloading bounded snapshots from Hugging Face
_PRIORITY_EXTENSIONS = {
    ".py", ".txt", ".toml", ".yaml", ".yml", ".json", ".cfg", ".ini", ".md",
    ".pkl", ".pickle", ".p", ".joblib", ".pt", ".pth", ".bin", ".ckpt",
    ".sh", ".ipynb",
}


def _hf_headers() -> dict[str, str]:
    headers = {
        "User-Agent": "ModelTrust-Security-Scanner/1.0",
        "Accept": "application/json",
    }
    if Config.HUGGINGFACE_TOKEN:
        headers["Authorization"] = f"Bearer {Config.HUGGINGFACE_TOKEN}"
    return headers


def _api_type_segment(repo_type: str) -> str:
    return {"model": "models", "dataset": "datasets", "space": "spaces"}.get(repo_type, "models")


def _web_type_prefix(repo_type: str) -> str:
    return {"model": "", "dataset": "datasets/", "space": "spaces/"}.get(repo_type, "")


def fetch_huggingface_metadata(repo_id: str, repo_type: str = "model") -> dict[str, Any]:
    """Fetch repository metadata, siblings/tree, and commit history from Hugging Face Hub API."""
    headers = _hf_headers()
    timeout = Config.HTTP_TIMEOUT_SECONDS
    type_seg = _api_type_segment(repo_type)

    meta_url = f"{HF_API_BASE}/{type_seg}/{repo_id}"
    resp = requests.get(meta_url, headers=headers, timeout=timeout)
    if resp.status_code == 404:
        raise ValueError(f"Hugging Face {repo_type} '{repo_id}' not found or is gated/private.")
    if resp.status_code in (401, 403):
        raise RuntimeError(
            f"Access denied for Hugging Face {repo_type} '{repo_id}' (HTTP {resp.status_code}). "
            "Configure HUGGINGFACE_TOKEN if authentication is required."
        )
    if resp.status_code >= 400:
        raise RuntimeError(f"Hugging Face API error (HTTP {resp.status_code}): {resp.text[:200]}")

    data = resp.json()

    # Fetch full file tree with sizes & LFS SHA256 hashes
    remote_files: list[dict[str, Any]] = []
    try:
        tree_url = f"{HF_API_BASE}/{type_seg}/{repo_id}/tree/main"
        t_resp = requests.get(tree_url, headers=headers, params={"recursive": "true"}, timeout=timeout)
        if t_resp.status_code == 200:
            for entry in t_resp.json():
                if entry.get("type") == "file":
                    lfs = entry.get("lfs") or {}
                    remote_files.append({
                        "path": entry.get("path"),
                        "size": int(entry.get("size") or lfs.get("size") or 0),
                        "oid": entry.get("oid"),
                        "lfs_sha256": lfs.get("oid"),
                    })
    except requests.RequestException as exc:
        logger.warning("Could not fetch HF tree for %s: %s", repo_id, exc)

    if not remote_files and data.get("siblings"):
        for sib in data["siblings"]:
            fname = sib.get("rfilename")
            if fname:
                remote_files.append({
                    "path": fname,
                    "size": int(sib.get("size") or 0),
                    "oid": None,
                    "lfs_sha256": None,
                })

    # Fetch commit history (best-effort)
    commits: list[dict[str, Any]] = []
    try:
        c_url = f"{HF_API_BASE}/{type_seg}/{repo_id}/commits/main"
        c_resp = requests.get(c_url, headers=headers, timeout=timeout)
        if c_resp.status_code == 200:
            for item in c_resp.json()[:15]:
                authors = item.get("authors") or []
                first_author = authors[0].get("user") if authors and isinstance(authors[0], dict) else None
                commits.append({
                    "sha": (item.get("id") or "")[:12],
                    "author_name": first_author,
                    "author_login": first_author,
                    "date": item.get("date"),
                    "message": (item.get("title") or "")[:120],
                    "verified_signature": None,
                })
    except requests.RequestException as exc:
        logger.warning("Could not fetch HF commits for %s: %s", repo_id, exc)

    # Extract tags / license / cardData
    tags = data.get("tags") or []
    card_data = data.get("cardData") or {}
    license_name = card_data.get("license")
    if not license_name:
        for tag in tags:
            if isinstance(tag, str) and tag.startswith("license:"):
                license_name = tag.split(":", 1)[1]
                break

    author = data.get("author") or (repo_id.split("/")[0] if "/" in repo_id else "huggingface")
    repo_name = repo_id.split("/")[-1]
    web_prefix = _web_type_prefix(repo_type)

    return {
        "platform": "huggingface",
        "owner": author,
        "owner_type": "Organization/User (Hugging Face Hub)",
        "owner_profile": {"login": author, "platform": "huggingface"},
        "repo_name": repo_name,
        "full_name": repo_id,
        "repo_type": repo_type,
        "repository_url": f"{HF_WEB_BASE}/{web_prefix}{repo_id}",
        "description": card_data.get("summary") or data.get("pipeline_tag") or "",
        "default_branch": "main",
        "created_at": data.get("createdAt"),
        "updated_at": data.get("lastModified"),
        "pushed_at": data.get("lastModified"),
        "gated": bool(data.get("gated")),
        "private": bool(data.get("private")),
        "disabled": bool(data.get("disabled")),
        "sha": data.get("sha"),
        "pipeline_tag": data.get("pipeline_tag"),
        "library_name": data.get("library_name"),
        "license": {"name": license_name, "spdx_id": license_name} if license_name else None,
        "tags": tags[:25],
        "releases": [],  # HF Hub uses Git refs/revisions rather than GitHub Releases
        "commits": commits,
        "remote_files": remote_files,
    }


def download_huggingface_repository(
    repo_id: str,
    repo_type: str,
    remote_files: list[dict[str, Any]],
    dest_dir: Path,
) -> dict[str, Any]:
    """
    Download bounded files from Hugging Face Hub without executing any repository code.
    Oversized model weights are skipped cleanly while retaining their remote metadata & LFS hashes.
    """
    dest_dir.mkdir(parents=True, exist_ok=True)
    headers = _hf_headers()
    web_prefix = _web_type_prefix(repo_type)

    # Sort files: security-relevant & smaller files first
    def _sort_key(item: dict[str, Any]) -> tuple[int, int]:
        path = str(item.get("path") or "")
        ext = Path(path).suffix.lower()
        priority = 0 if ext in _PRIORITY_EXTENSIONS else 1
        return (priority, int(item.get("size") or 0))

    ordered_files = sorted(remote_files, key=_sort_key)

    downloaded_files: list[str] = []
    skipped_files: list[dict[str, str]] = []
    total_bytes = 0
    truncated = False

    for file_info in ordered_files:
        rel_path = file_info.get("path")
        if not rel_path:
            continue

        file_size = int(file_info.get("size") or 0)

        if len(downloaded_files) >= Config.MAX_FILE_COUNT:
            truncated = True
            skipped_files.append({"path": rel_path, "reason": "max file count limit reached"})
            continue

        if file_size > Config.MAX_SINGLE_FILE_BYTES:
            skipped_files.append({
                "path": rel_path,
                "reason": (
                    f"file size ({file_size / (1024 * 1024):.1f} MB) exceeds "
                    f"single-file download cap ({Config.MAX_SINGLE_FILE_MB} MB); remote metadata retained"
                ),
            })
            continue

        if total_bytes + file_size > Config.MAX_DOWNLOAD_SIZE_BYTES:
            truncated = True
            skipped_files.append({
                "path": rel_path,
                "reason": f"total download cap ({Config.MAX_DOWNLOAD_SIZE_MB} MB) reached",
            })
            continue

        try:
            target_path = safe_join_path(dest_dir, rel_path)
        except ValidationError as exc:
            skipped_files.append({"path": rel_path, "reason": str(exc)})
            continue

        encoded_path = quote(rel_path, safe="/")
        raw_url = f"{HF_WEB_BASE}/{web_prefix}{repo_id}/resolve/main/{encoded_path}"

        try:
            with requests.get(raw_url, headers=headers, stream=True, timeout=Config.HTTP_TIMEOUT_SECONDS) as resp:
                if resp.status_code >= 400:
                    skipped_files.append({"path": rel_path, "reason": f"HTTP {resp.status_code}"})
                    continue

                target_path.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                exceeded = False
                with open(target_path, "wb") as dst:
                    for chunk in resp.iter_content(chunk_size=65536):
                        if not chunk:
                            continue
                        written += len(chunk)
                        if written > Config.MAX_SINGLE_FILE_BYTES or (total_bytes + written) > Config.MAX_DOWNLOAD_SIZE_BYTES:
                            exceeded = True
                            break
                        dst.write(chunk)

                if exceeded:
                    target_path.unlink(missing_ok=True)
                    skipped_files.append({"path": rel_path, "reason": "exceeded download size cap during streaming"})
                    continue

                total_bytes += written
                downloaded_files.append(rel_path)
        except requests.RequestException as exc:
            skipped_files.append({"path": rel_path, "reason": f"network error: {exc}"})

    return {
        "local_path": str(dest_dir),
        "file_count": len(downloaded_files),
        "total_size_bytes": total_bytes,
        "extracted_files": downloaded_files,
        "skipped_files": skipped_files,
        "truncated": truncated,
    }
