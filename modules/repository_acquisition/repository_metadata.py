"""Unified repository acquisition coordinator for GitHub and Hugging Face."""
from __future__ import annotations

from pathlib import Path
from typing import Any

from config import Config
from modules.repository_acquisition.github_fetcher import (
    download_github_repository,
    fetch_github_metadata,
)
from modules.repository_acquisition.huggingface_fetcher import (
    download_huggingface_repository,
    fetch_huggingface_metadata,
)
from utils.logger import get_logger
from utils.validators import sanitize_filename, validate_repository_url

logger = get_logger("modeltrust.acquisition")


def acquire_repository(raw_url: str, assessment_id: str) -> dict[str, Any]:
    """
    Validate URL, identify platform, fetch metadata, and safely download repository
    into an isolated assessment directory under storage/downloaded_repositories/.
    """
    parsed = validate_repository_url(raw_url)
    platform = parsed["platform"]
    owner = parsed["owner"]
    repo = parsed["repo"]
    repo_id = parsed["repo_id"]
    repo_type = parsed["repo_type"]

    safe_slug = sanitize_filename(f"{assessment_id}_{platform}_{owner}_{repo}")
    dest_dir = Config.DOWNLOADS_DIR / safe_slug
    dest_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Acquiring %s repository %s into %s", platform, repo_id, dest_dir)

    if platform == "github":
        metadata = fetch_github_metadata(owner, repo)
        download_info = download_github_repository(
            owner=owner,
            repo=repo,
            branch=metadata.get("default_branch") or "main",
            dest_dir=dest_dir,
        )
    elif platform == "huggingface":
        metadata = fetch_huggingface_metadata(repo_id, repo_type=repo_type)
        download_info = download_huggingface_repository(
            repo_id=repo_id,
            repo_type=repo_type,
            remote_files=metadata.get("remote_files") or [],
            dest_dir=dest_dir,
        )
    else:
        raise ValueError(f"Unsupported platform: {platform}")

    return {
        "parsed": parsed,
        "metadata": metadata,
        "download": download_info,
        "local_path": Path(download_info["local_path"]),
    }
