"""
Module 6: Integrity Verification using SHA-256 cryptographic hashing.

Computes per-file SHA-256 hashes and a deterministic composite repository digest,
and supports re-verifying stored artifacts to detect modification or tampering.
"""
from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from utils.logger import get_logger

logger = get_logger("modeltrust.integrity")


def compute_file_sha256(file_path: Path) -> str:
    """Compute SHA-256 hex digest of a file using streaming 64KB chunks."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as fh:
        while True:
            chunk = fh.read(65536)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


def compute_directory_hashes(repo_dir: Path) -> dict[str, Any]:
    """
    Compute SHA-256 hashes for all files in repo_dir and a deterministic
    composite SHA-256 digest over sorted '<rel_path>:<sha256>' lines.
    """
    repo_dir = Path(repo_dir)
    if not repo_dir.exists() or not repo_dir.is_dir():
        raise FileNotFoundError(f"Repository directory does not exist: {repo_dir}")

    file_hashes: dict[str, str] = {}
    file_entries: list[dict[str, Any]] = []
    total_bytes = 0

    for path in sorted(repo_dir.rglob("*")):
        if not path.is_file():
            continue
        rel = str(path.relative_to(repo_dir)).replace("\\", "/")
        digest = compute_file_sha256(path)
        size = path.stat().st_size
        total_bytes += size
        file_hashes[rel] = digest
        file_entries.append({
            "file": rel,
            "sha256": digest,
            "size_bytes": size,
        })

    manifest_hasher = hashlib.sha256()
    for rel in sorted(file_hashes.keys()):
        manifest_hasher.update(f"{rel}:{file_hashes[rel]}\n".encode("utf-8"))
    composite_hash = manifest_hasher.hexdigest()

    return {
        "composite_hash": composite_hash,
        "file_count": len(file_entries),
        "total_size_bytes": total_bytes,
        "file_hashes": file_hashes,
        "file_entries": file_entries,
    }


def generate_integrity_report(
    repo_dir: Path,
    expected_composite_hash: str | None = None,
    expected_file_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    """
    Generate SHA-256 integrity hashes for repository artifacts.
    If expected_composite_hash or expected_file_hashes are supplied, verifies against them
    and marks status FAIL upon any mismatch/tampering.
    """
    try:
        current = compute_directory_hashes(repo_dir)
    except Exception as exc:
        logger.error("Integrity hashing failed for %s: %s", repo_dir, exc)
        return {
            "module_name": "integrity",
            "status": "FAIL",
            "severity": "CRITICAL",
            "summary": f"Integrity hash computation failed: {exc}",
            "findings": [
                {
                    "title": "Artifact Integrity Computation Failed",
                    "severity": "CRITICAL",
                    "description": str(exc),
                    "recommendation": "Re-acquire repository files and verify storage accessibility.",
                }
            ],
            "raw_details": {"error": str(exc)},
            "tool_name": "SHA-256 Cryptographic Hasher",
            "tool_available": True,
        }

    if current["file_count"] == 0:
        return {
            "module_name": "integrity",
            "status": "WARNING",
            "severity": "LOW",
            "summary": "No local files were hashed (empty repository snapshot).",
            "findings": [
                {
                    "title": "Empty Repository Snapshot",
                    "severity": "LOW",
                    "description": "Zero files were downloaded locally for SHA-256 hashing.",
                    "recommendation": "Verify repository download limits or remote repository contents.",
                }
            ],
            "raw_details": current,
            "tool_name": "SHA-256 Cryptographic Hasher",
            "tool_available": True,
        }

    # Optional comparison against previously recorded hashes
    if expected_composite_hash or expected_file_hashes:
        verification = compare_hashes(
            current=current,
            expected_composite_hash=expected_composite_hash,
            expected_file_hashes=expected_file_hashes,
        )
        if not verification["verified"]:
            findings = []
            if verification["modified_files"]:
                findings.append({
                    "title": f"Modified / Tampered Files Detected ({len(verification['modified_files'])})",
                    "severity": "CRITICAL",
                    "description": "SHA-256 mismatch on: " + ", ".join(verification["modified_files"][:10]),
                    "recommendation": "Reject artifact immediately and investigate supply-chain tampering.",
                })
            if verification["missing_files"]:
                findings.append({
                    "title": f"Missing Artifact Files ({len(verification['missing_files'])})",
                    "severity": "CRITICAL",
                    "description": "Previously recorded files are missing: " + ", ".join(verification["missing_files"][:10]),
                    "recommendation": "Reject artifact and verify storage integrity.",
                })
            if verification["added_files"]:
                findings.append({
                    "title": f"Unexpected Added Files ({len(verification['added_files'])})",
                    "severity": "HIGH",
                    "description": "Unexpected new files present: " + ", ".join(verification["added_files"][:10]),
                    "recommendation": "Re-scan and re-certify before trusting.",
                })
            if not findings:
                findings.append({
                    "title": "Composite SHA-256 Hash Mismatch",
                    "severity": "CRITICAL",
                    "description": (
                        f"Expected composite hash {expected_composite_hash}, "
                        f"but computed {current['composite_hash']}."
                    ),
                    "recommendation": "Reject tampered artifact.",
                })

            return {
                "module_name": "integrity",
                "status": "FAIL",
                "severity": "CRITICAL",
                "summary": (
                    f"INTEGRITY FAILURE: Artifact hash mismatch detected! "
                    f"Modified: {len(verification['modified_files'])}, "
                    f"Missing: {len(verification['missing_files'])}, "
                    f"Added: {len(verification['added_files'])}."
                ),
                "findings": findings,
                "raw_details": {
                    **current,
                    "verification": verification,
                },
                "tool_name": "SHA-256 Cryptographic Hasher",
                "tool_available": True,
            }

    return {
        "module_name": "integrity",
        "status": "PASS",
        "severity": "NONE",
        "summary": (
            f"SHA-256 integrity manifest generated for {current['file_count']} file(s). "
            f"Composite SHA-256: {current['composite_hash']}"
        ),
        "findings": [],
        "raw_details": {
            "composite_hash": current["composite_hash"],
            "file_count": current["file_count"],
            "total_size_bytes": current["total_size_bytes"],
            "file_hashes": current["file_hashes"],
            "file_entries": current["file_entries"][:200],
            "verified": True,
        },
        "tool_name": "SHA-256 Cryptographic Hasher",
        "tool_available": True,
    }


def compare_hashes(
    current: dict[str, Any],
    expected_composite_hash: str | None = None,
    expected_file_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Compare current directory hashes against recorded baseline hashes."""
    modified: list[str] = []
    missing: list[str] = []
    added: list[str] = []

    curr_map = current.get("file_hashes") or {}
    if expected_file_hashes is not None:
        for rel, exp_hash in expected_file_hashes.items():
            if rel not in curr_map:
                missing.append(rel)
            elif curr_map[rel] != exp_hash:
                modified.append(rel)
        for rel in curr_map:
            if rel not in expected_file_hashes:
                added.append(rel)

    composite_match = (
        True
        if expected_composite_hash is None
        else (current.get("composite_hash") == expected_composite_hash)
    )
    verified = composite_match and not modified and not missing and not added

    return {
        "verified": verified,
        "composite_match": composite_match,
        "expected_composite_hash": expected_composite_hash,
        "current_composite_hash": current.get("composite_hash"),
        "modified_files": modified,
        "missing_files": missing,
        "added_files": added,
    }


def verify_artifact_integrity(
    repo_dir: Path | str,
    expected_composite_hash: str,
    expected_file_hashes: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Re-compute hashes on stored repository directory and verify against recorded baseline."""
    path = Path(repo_dir)
    if not path.exists():
        return {
            "verified": False,
            "status": "FAIL",
            "reason": f"Stored artifact directory not found: {path}",
            "modified_files": [],
            "missing_files": [],
            "added_files": [],
            "expected_composite_hash": expected_composite_hash,
            "current_composite_hash": None,
        }

    current = compute_directory_hashes(path)
    result = compare_hashes(current, expected_composite_hash, expected_file_hashes)
    if result["verified"]:
        result["status"] = "VERIFIED"
        result["reason"] = "All SHA-256 artifact hashes match the certified baseline."
    else:
        result["status"] = "TAMPERED"
        result["reason"] = (
            f"Integrity verification FAILED! Modified: {len(result['modified_files'])}, "
            f"Missing: {len(result['missing_files'])}, Added: {len(result['added_files'])}."
        )
    return result
