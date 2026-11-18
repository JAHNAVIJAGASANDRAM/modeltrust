"""
Module 10: Trusted AI Artifact Registry.

Database-backed registry admitting ONLY policy-approved, digitally certified AI artifacts.
Supports searching, viewing, and on-demand SHA-256 integrity + cryptographic signature re-verification.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from database.db import get_assessment_full, get_db_connection, utc_now_iso
from modules.certification.certificate_manager import verify_certificate_signature
from modules.integrity.hash_generator import verify_artifact_integrity
from utils.logger import get_logger

logger = get_logger("modeltrust.registry")


def admit_artifact_to_registry(
    artifact_id: int,
    decision: str,
    certificate_id: str,
    repository_name: str,
    repository_url: str,
    platform: str,
    artifact_hash: str,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """
    Admit an APPROVED and certified artifact into the trusted_registry table.
    Raises PermissionError if decision != 'APPROVE' or certificate_id is missing.
    """
    if decision != "APPROVE":
        raise PermissionError(
            f"Only APPROVED artifacts may enter the Trusted AI Artifact Registry (got '{decision}')."
        )
    if not certificate_id or not artifact_hash:
        raise PermissionError("Artifact must possess a valid SHA-256 hash and digital certificate.")

    now = utc_now_iso()
    conn = get_db_connection(db_path)
    try:
        conn.execute(
            """
            INSERT INTO trusted_registry (
                artifact_id, certificate_id, repository_name, repository_url,
                platform, artifact_hash, certification_status, integrity_status,
                admitted_at, last_verified_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                certificate_id = excluded.certificate_id,
                artifact_hash = excluded.artifact_hash,
                certification_status = excluded.certification_status,
                integrity_status = excluded.integrity_status,
                last_verified_at = excluded.last_verified_at
            """,
            (
                artifact_id,
                certificate_id,
                repository_name,
                repository_url,
                platform,
                artifact_hash,
                "CERTIFIED",
                "VERIFIED",
                now,
                now,
            ),
        )
        conn.commit()
        logger.info("Admitted artifact_id=%s (%s) into Trusted AI Artifact Registry", artifact_id, repository_name)
        return {
            "admitted": True,
            "artifact_id": artifact_id,
            "certificate_id": certificate_id,
            "admitted_at": now,
        }
    finally:
        conn.close()


def list_trusted_artifacts(
    search_query: str = "",
    db_path: Path | str | None = None,
) -> list[dict[str, Any]]:
    """List approved artifacts in the trusted registry, optionally filtered by search term."""
    conn = get_db_connection(db_path)
    try:
        q = (search_query or "").strip()
        if q:
            like = f"%{q}%"
            rows = conn.execute(
                """
                SELECT
                    tr.*,
                    a.assessment_id,
                    a.owner,
                    a.submitted_at,
                    a.completed_at,
                    c.issuer,
                    c.algorithm,
                    c.issued_at
                FROM trusted_registry tr
                JOIN artifacts a ON a.id = tr.artifact_id
                LEFT JOIN certificates c ON c.certificate_id = tr.certificate_id
                WHERE tr.repository_name LIKE ?
                   OR tr.repository_url LIKE ?
                   OR tr.artifact_hash LIKE ?
                   OR tr.platform LIKE ?
                   OR a.assessment_id LIKE ?
                ORDER BY tr.id DESC
                """,
                (like, like, like, like, like),
            ).fetchall()
        else:
            rows = conn.execute(
                """
                SELECT
                    tr.*,
                    a.assessment_id,
                    a.owner,
                    a.submitted_at,
                    a.completed_at,
                    c.issuer,
                    c.algorithm,
                    c.issued_at
                FROM trusted_registry tr
                JOIN artifacts a ON a.id = tr.artifact_id
                LEFT JOIN certificates c ON c.certificate_id = tr.certificate_id
                ORDER BY tr.id DESC
                """
            ).fetchall()

        return [dict(r) for r in rows]
    finally:
        conn.close()


def reverify_trusted_artifact(
    artifact_id: int,
    db_path: Path | str | None = None,
) -> dict[str, Any]:
    """
    Re-verify both SHA-256 artifact integrity on disk and digital certificate signature
    for an artifact in the Trusted AI Artifact Registry.
    """
    bundle = get_assessment_full(artifact_id, db_path=db_path)
    if not bundle:
        raise ValueError(f"Artifact ID {artifact_id} not found.")

    artifact = bundle["artifact"]
    certificate = bundle["certificate"]
    integrity_scan = bundle["scans"].get("integrity") or {}
    expected_file_hashes = (integrity_scan.get("raw_details") or {}).get("file_hashes")

    # 1. Re-verify SHA-256 integrity
    integrity_res = verify_artifact_integrity(
        repo_dir=artifact.get("local_path") or "",
        expected_composite_hash=artifact.get("artifact_hash") or "",
        expected_file_hashes=expected_file_hashes,
    )

    # 2. Re-verify cryptographic certificate signature
    if certificate:
        sig_res = verify_certificate_signature(
            payload=certificate["payload"],
            signature_b64=certificate["signature_b64"],
        )
        hash_matches_cert = (
            certificate["payload"].get("artifact_hash") == integrity_res.get("current_composite_hash")
        )
    else:
        sig_res = {"signature_valid": False, "reason": "No digital certificate recorded for this artifact."}
        hash_matches_cert = False

    overall_verified = bool(integrity_res["verified"] and sig_res["signature_valid"] and hash_matches_cert)
    new_integrity_status = "VERIFIED" if integrity_res["verified"] else "TAMPERED"
    new_cert_status = "CERTIFIED" if (sig_res["signature_valid"] and hash_matches_cert) else "COMPROMISED"
    now = utc_now_iso()

    # Persist updated verification status in trusted_registry if present
    conn = get_db_connection(db_path)
    try:
        conn.execute(
            """
            UPDATE trusted_registry
            SET integrity_status = ?, certification_status = ?, last_verified_at = ?
            WHERE artifact_id = ?
            """,
            (new_integrity_status, new_cert_status, now, artifact_id),
        )
        if certificate:
            conn.execute(
                "UPDATE certificates SET status = ? WHERE artifact_id = ?",
                ("VALID" if sig_res["signature_valid"] else "INVALID", artifact_id),
            )
        conn.commit()
    finally:
        conn.close()

    return {
        "artifact_id": artifact_id,
        "assessment_id": artifact["assessment_id"],
        "repository_name": f"{artifact['owner']}/{artifact['repo_name']}",
        "overall_verified": overall_verified,
        "integrity_status": new_integrity_status,
        "certification_status": new_cert_status,
        "integrity_result": integrity_res,
        "signature_result": sig_res,
        "verified_at": now,
    }
