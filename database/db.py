"""SQLite database initialization and query helpers for ModelTrust."""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import Config
from utils.logger import get_logger

logger = get_logger("modeltrust.database")


def utc_now_iso() -> str:
    """Return current UTC timestamp in ISO-8601 format."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_db_connection(db_path: Path | str | None = None) -> sqlite3.Connection:
    """Open a SQLite connection with Row factory and foreign keys enabled."""
    target = Path(db_path) if db_path else Config.DATABASE_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(target))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: Path | str | None = None) -> None:
    """Initialize SQLite tables from schema.sql and seed a default security analyst user."""
    Config.ensure_directories()
    schema_sql = Config.SCHEMA_PATH.read_text(encoding="utf-8")
    conn = get_db_connection(db_path)
    try:
        conn.executescript(schema_sql)
        # Seed default organizational analyst account for attribution
        existing = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("security_analyst",)
        ).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO users (username, email, role, created_at) VALUES (?, ?, ?, ?)",
                ("security_analyst", "analyst@modeltrust.local", "security_engineer", utc_now_iso()),
            )
        conn.commit()
        logger.info("SQLite database initialized at %s", db_path or Config.DATABASE_PATH)
    finally:
        conn.close()


def get_default_user_id(db_path: Path | str | None = None) -> int | None:
    """Return the default analyst user ID."""
    conn = get_db_connection(db_path)
    try:
        row = conn.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
        return int(row["id"]) if row else None
    finally:
        conn.close()


def create_artifact_record(
    assessment_id: str,
    repository_url: str,
    platform: str,
    owner: str,
    repo_name: str,
    repo_type: str = "repository",
    user_id: int | None = None,
    db_path: Path | str | None = None,
) -> int:
    """Insert a new artifact assessment record and return its primary key ID."""
    conn = get_db_connection(db_path)
    try:
        if user_id is None:
            row = conn.execute("SELECT id FROM users ORDER BY id ASC LIMIT 1").fetchone()
            user_id = int(row["id"]) if row else None

        cur = conn.execute(
            """
            INSERT INTO artifacts (
                assessment_id, user_id, repository_url, platform, owner, repo_name,
                repo_type, status, submitted_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                assessment_id,
                user_id,
                repository_url,
                platform,
                owner,
                repo_name,
                repo_type,
                "SCANNING",
                utc_now_iso(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def update_artifact_record(
    artifact_id: int,
    updates: dict[str, Any],
    db_path: Path | str | None = None,
) -> None:
    """Update allowed fields on an artifact row."""
    allowed_fields = {
        "description",
        "default_branch",
        "repo_created_at",
        "repo_updated_at",
        "local_path",
        "artifact_hash",
        "file_count",
        "total_size_bytes",
        "metadata_json",
        "status",
        "completed_at",
    }
    filtered = {k: v for k, v in updates.items() if k in allowed_fields}
    if not filtered:
        return

    assignments = ", ".join(f"{col} = ?" for col in filtered.keys())
    values = list(filtered.values()) + [artifact_id]
    conn = get_db_connection(db_path)
    try:
        conn.execute(f"UPDATE artifacts SET {assignments} WHERE id = ?", values)
        conn.commit()
    finally:
        conn.close()


def save_scan_result(
    artifact_id: int,
    module_name: str,
    status: str,
    severity: str,
    summary: str,
    findings: list[dict[str, Any]],
    raw_details: dict[str, Any] | None = None,
    tool_name: str | None = None,
    tool_available: bool = True,
    db_path: Path | str | None = None,
) -> int:
    """Store a security module's scan result."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO scan_results (
                artifact_id, module_name, status, severity, summary,
                findings_json, raw_details_json, tool_name, tool_available, scanned_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                artifact_id,
                module_name,
                status,
                severity,
                summary,
                json.dumps(findings, default=str),
                json.dumps(raw_details or {}, default=str),
                tool_name,
                1 if tool_available else 0,
                utc_now_iso(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def save_policy_decision(
    artifact_id: int,
    decision: str,
    risk_classification: str,
    violations: list[dict[str, Any]],
    reason: str,
    policy_snapshot: dict[str, Any] | None = None,
    db_path: Path | str | None = None,
) -> int:
    """Store or replace the final policy decision for an artifact."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO policy_decisions (
                artifact_id, decision, risk_classification, violations_json,
                reason, policy_snapshot_json, decided_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                decision = excluded.decision,
                risk_classification = excluded.risk_classification,
                violations_json = excluded.violations_json,
                reason = excluded.reason,
                policy_snapshot_json = excluded.policy_snapshot_json,
                decided_at = excluded.decided_at
            """,
            (
                artifact_id,
                decision,
                risk_classification,
                json.dumps(violations, default=str),
                reason,
                json.dumps(policy_snapshot or {}, default=str),
                utc_now_iso(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def save_certificate_record(
    artifact_id: int,
    certificate_id: str,
    assessment_id: str,
    repository_url: str,
    artifact_hash: str,
    issuer: str,
    algorithm: str,
    payload: dict[str, Any],
    signature_b64: str,
    certificate_path: str,
    status: str = "VALID",
    db_path: Path | str | None = None,
) -> int:
    """Persist digital certificate record for an approved artifact."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO certificates (
                artifact_id, certificate_id, assessment_id, repository_url,
                artifact_hash, issuer, algorithm, payload_json,
                signature_b64, certificate_path, status, issued_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                certificate_id = excluded.certificate_id,
                artifact_hash = excluded.artifact_hash,
                payload_json = excluded.payload_json,
                signature_b64 = excluded.signature_b64,
                certificate_path = excluded.certificate_path,
                status = excluded.status,
                issued_at = excluded.issued_at
            """,
            (
                artifact_id,
                certificate_id,
                assessment_id,
                repository_url,
                artifact_hash,
                issuer,
                algorithm,
                json.dumps(payload, sort_keys=True),
                signature_b64,
                certificate_path,
                status,
                utc_now_iso(),
            ),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def save_report_record(
    artifact_id: int,
    assessment_id: str,
    report_filename: str,
    report_path: str,
    db_path: Path | str | None = None,
) -> int:
    """Persist PDF report metadata."""
    conn = get_db_connection(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO reports (
                artifact_id, assessment_id, report_filename, report_path, generated_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(artifact_id) DO UPDATE SET
                report_filename = excluded.report_filename,
                report_path = excluded.report_path,
                generated_at = excluded.generated_at
            """,
            (artifact_id, assessment_id, report_filename, report_path, utc_now_iso()),
        )
        conn.commit()
        return int(cur.lastrowid)
    finally:
        conn.close()


def get_assessment_full(artifact_id: int, db_path: Path | str | None = None) -> dict[str, Any] | None:
    """Fetch complete assessment bundle: artifact, scan_results, policy_decision, certificate, registry, report."""
    conn = get_db_connection(db_path)
    try:
        art = conn.execute("SELECT * FROM artifacts WHERE id = ?", (artifact_id,)).fetchone()
        if not art:
            return None

        artifact_dict = dict(art)
        artifact_dict["metadata"] = _safe_json_loads(artifact_dict.get("metadata_json"), {})

        scan_rows = conn.execute(
            "SELECT * FROM scan_results WHERE artifact_id = ? ORDER BY id ASC",
            (artifact_id,),
        ).fetchall()
        scans: dict[str, dict[str, Any]] = {}
        scans_list: list[dict[str, Any]] = []
        for row in scan_rows:
            item = dict(row)
            item["findings"] = _safe_json_loads(item.get("findings_json"), [])
            item["raw_details"] = _safe_json_loads(item.get("raw_details_json"), {})
            item["tool_available"] = bool(item["tool_available"])
            scans[item["module_name"]] = item
            scans_list.append(item)

        pd_row = conn.execute(
            "SELECT * FROM policy_decisions WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        policy_decision = None
        if pd_row:
            policy_decision = dict(pd_row)
            policy_decision["violations"] = _safe_json_loads(
                policy_decision.get("violations_json"), []
            )
            policy_decision["policy_snapshot"] = _safe_json_loads(
                policy_decision.get("policy_snapshot_json"), {}
            )

        cert_row = conn.execute(
            "SELECT * FROM certificates WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        certificate = None
        if cert_row:
            certificate = dict(cert_row)
            certificate["payload"] = _safe_json_loads(certificate.get("payload_json"), {})

        reg_row = conn.execute(
            "SELECT * FROM trusted_registry WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        registry_entry = dict(reg_row) if reg_row else None

        rep_row = conn.execute(
            "SELECT * FROM reports WHERE artifact_id = ?", (artifact_id,)
        ).fetchone()
        report = dict(rep_row) if rep_row else None

        return {
            "artifact": artifact_dict,
            "scans": scans,
            "scans_list": scans_list,
            "policy_decision": policy_decision,
            "certificate": certificate,
            "registry_entry": registry_entry,
            "report": report,
        }
    finally:
        conn.close()


def get_dashboard_summary(db_path: Path | str | None = None) -> dict[str, Any]:
    """Return aggregate counts and recent security assessments for the Dashboard."""
    conn = get_db_connection(db_path)
    try:
        total = conn.execute("SELECT COUNT(*) AS c FROM artifacts").fetchone()["c"]
        approved = conn.execute(
            "SELECT COUNT(*) AS c FROM policy_decisions WHERE decision = 'APPROVE'"
        ).fetchone()["c"]
        review = conn.execute(
            "SELECT COUNT(*) AS c FROM policy_decisions WHERE decision = 'REVIEW'"
        ).fetchone()["c"]
        rejected = conn.execute(
            "SELECT COUNT(*) AS c FROM policy_decisions WHERE decision = 'REJECT'"
        ).fetchone()["c"]
        registry_count = conn.execute(
            "SELECT COUNT(*) AS c FROM trusted_registry"
        ).fetchone()["c"]

        recent_rows = conn.execute(
            """
            SELECT
                a.id,
                a.assessment_id,
                a.repository_url,
                a.platform,
                a.owner,
                a.repo_name,
                a.artifact_hash,
                a.status,
                a.submitted_at,
                a.completed_at,
                pd.decision,
                pd.risk_classification,
                pd.reason,
                c.certificate_id,
                tr.id AS registry_id
            FROM artifacts a
            LEFT JOIN policy_decisions pd ON pd.artifact_id = a.id
            LEFT JOIN certificates c ON c.artifact_id = a.id
            LEFT JOIN trusted_registry tr ON tr.artifact_id = a.id
            ORDER BY a.id DESC
            LIMIT 50
            """
        ).fetchall()

        module_stats_rows = conn.execute(
            """
            SELECT module_name, status, COUNT(*) AS cnt
            FROM scan_results
            GROUP BY module_name, status
            """
        ).fetchall()
        module_stats: dict[str, dict[str, int]] = {}
        for row in module_stats_rows:
            mod = row["module_name"]
            module_stats.setdefault(mod, {"PASS": 0, "WARNING": 0, "FAIL": 0, "NOT SCANNED": 0})
            module_stats[mod][row["status"]] = int(row["cnt"])

        return {
            "stats": {
                "total": int(total),
                "approved": int(approved),
                "review": int(review),
                "rejected": int(rejected),
                "registry_count": int(registry_count),
            },
            "recent_assessments": [dict(r) for r in recent_rows],
            "module_stats": module_stats,
        }
    finally:
        conn.close()


def _safe_json_loads(raw: str | None, default: Any) -> Any:
    if not raw:
        return default
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default
