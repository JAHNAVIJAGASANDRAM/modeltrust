"""Strict input validation, URL parsing, SSRF protection, and safe path utilities."""
from __future__ import annotations

import ipaddress
import os
import re
import socket
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from config import Config

# Safe identifier patterns for GitHub and Hugging Face owners/repos
_GITHUB_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$")
_HF_SEGMENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


class ValidationError(ValueError):
    """Raised when user-supplied repository input fails security validation."""


def _is_private_or_disallowed_ip(ip_str: str) -> bool:
    """Return True if an IP address is loopback, private, link-local, or reserved."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return True


def validate_outbound_host(hostname: str) -> None:
    """Ensure hostname is allowlisted and does not resolve to an internal/private IP (SSRF defense)."""
    host = (hostname or "").lower().strip()
    if not host or host not in Config.ALLOWED_REPO_HOSTS:
        raise ValidationError(
            f"Unsupported or disallowed host '{host}'. Only GitHub (github.com) and "
            "Hugging Face (huggingface.co) repositories are permitted."
        )

    # Reject raw IP literals immediately
    try:
        ipaddress.ip_address(host)
        raise ValidationError("Direct IP addresses are not permitted.")
    except ValueError:
        pass

    # Best-effort DNS resolution SSRF check (if offline, allowlisted hostname still passes DNS check gracefully)
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        for info in infos:
            ip_addr = info[4][0]
            if _is_private_or_disallowed_ip(ip_addr):
                raise ValidationError(f"Resolved IP address for {host} is disallowed (SSRF protection).")
    except socket.gaierror:
        # Network unavailable at validation time; downstream fetcher will report network error cleanly
        pass


def validate_repository_url(raw_url: str) -> dict[str, Any]:
    """
    Validate and normalize a GitHub or Hugging Face repository URL.

    Returns a dictionary containing:
        platform: 'github' | 'huggingface'
        owner: repository owner/org (or 'huggingface' for top-level official models)
        repo: repository name
        repo_id: full identifier (e.g., 'owner/repo' or 'bert-base-uncased')
        repo_type: 'model' | 'dataset' | 'space' | 'repository'
        normalized_url: canonical HTTPS repository URL
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValidationError("Repository URL is required.")

    url = raw_url.strip()
    if len(url) > 512:
        raise ValidationError("Repository URL exceeds maximum length of 512 characters.")

    if any(ch in url for ch in ("\r", "\n", "\x00", " ")):
        raise ValidationError("Repository URL contains invalid whitespace or control characters.")

    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise ValidationError("Only HTTPS repository URLs are accepted (e.g., https://github.com/owner/repo).")

    if parsed.username or parsed.password:
        raise ValidationError("Embedded credentials in URLs are not permitted.")

    if parsed.port not in (None, 443):
        raise ValidationError("Non-standard ports are not permitted.")

    hostname = (parsed.hostname or "").lower()
    validate_outbound_host(hostname)

    path_parts = [p for p in parsed.path.split("/") if p]
    if ".." in path_parts or "." in path_parts:
        raise ValidationError("Path traversal segments are not permitted in repository URLs.")

    if hostname in ("github.com", "www.github.com"):
        if len(path_parts) < 2:
            raise ValidationError(
                "Invalid GitHub repository URL. Expected format: https://github.com/<owner>/<repository>"
            )
        owner = path_parts[0]
        repo = path_parts[1]
        if repo.endswith(".git"):
            repo = repo[:-4]

        if not _GITHUB_SEGMENT_RE.match(owner) or not _GITHUB_SEGMENT_RE.match(repo):
            raise ValidationError("GitHub owner or repository name contains invalid characters.")

        repo_id = f"{owner}/{repo}"
        return {
            "platform": "github",
            "owner": owner,
            "repo": repo,
            "repo_id": repo_id,
            "repo_type": "repository",
            "normalized_url": f"https://github.com/{owner}/{repo}",
        }

    # Hugging Face URL handling
    if hostname in ("huggingface.co", "www.huggingface.co"):
        if not path_parts:
            raise ValidationError(
                "Invalid Hugging Face URL. Expected format: https://huggingface.co/<owner>/<model>"
            )

        repo_type = "model"
        idx = 0
        if path_parts[0] in ("datasets", "spaces", "models"):
            prefix = path_parts[0]
            repo_type = {"datasets": "dataset", "spaces": "space", "models": "model"}[prefix]
            idx = 1

        remaining = path_parts[idx:]
        if not remaining:
            raise ValidationError("Hugging Face URL must specify a model, dataset, or space identifier.")

        # Strip trailing web UI paths like /tree/main or /blob/main/...
        clean_segments: list[str] = []
        for seg in remaining:
            if seg in ("tree", "blob", "resolve", "commits", "discussions", "settings"):
                break
            clean_segments.append(seg)

        if len(clean_segments) == 1:
            # Official top-level Hugging Face model (e.g. https://huggingface.co/gpt2 or bert-base-uncased)
            owner = "huggingface"
            repo = clean_segments[0]
            repo_id = repo
        elif len(clean_segments) >= 2:
            owner = clean_segments[0]
            repo = clean_segments[1]
            repo_id = f"{owner}/{repo}"
        else:
            raise ValidationError("Invalid Hugging Face repository path.")

        if not _HF_SEGMENT_RE.match(owner) or not _HF_SEGMENT_RE.match(repo):
            raise ValidationError("Hugging Face owner or model name contains invalid characters.")

        type_prefix = "" if repo_type == "model" else f"{repo_type}s/"
        return {
            "platform": "huggingface",
            "owner": owner,
            "repo": repo,
            "repo_id": repo_id,
            "repo_type": repo_type,
            "normalized_url": f"https://huggingface.co/{type_prefix}{repo_id}",
        }

    raise ValidationError("Unsupported repository platform.")


def safe_join_path(base_dir: Path, relative_path: str) -> Path:
    """
    Safely join a relative path to base_dir, preventing path traversal (Zip Slip).
    Raises ValidationError if the resulting path escapes base_dir.
    """
    if not relative_path or "\x00" in relative_path:
        raise ValidationError("Invalid archive member path.")

    normalized_rel = relative_path.replace("\\", "/").lstrip("/")
    parts = [p for p in normalized_rel.split("/") if p]
    if not parts or any(p in (".", "..") for p in parts):
        raise ValidationError(f"Unsafe path traversal detected: {relative_path}")

    base_resolved = base_dir.resolve()
    target_path = (base_resolved / Path(*parts)).resolve()

    if base_resolved != target_path and base_resolved not in target_path.parents:
        raise ValidationError(f"Path escapes extraction root: {relative_path}")

    return target_path


def sanitize_filename(name: str, max_length: int = 80) -> str:
    """Return a filesystem-safe slug for storage folder/file naming."""
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "_", name or "artifact").strip("._")
    return (cleaned or "artifact")[:max_length]
