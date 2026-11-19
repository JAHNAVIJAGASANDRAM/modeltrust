"""Server-side authorization, permission management, and auditing for reports."""
from datetime import datetime, timezone

from flask import request
from flask_login import current_user

from app.extensions import db
from app.models.report_access import ReportAuditLog, ReportPermission
from database.db import artifact_exists, get_artifact_auth_user_id, get_db_connection, list_artifact_ids


def visible_artifact_ids() -> list[int]:
    """Return assessment IDs the current account is permitted to see."""
    if current_user.has_role("administrator"):
        return list_artifact_ids()

    conn = get_db_connection()
    try:
        owned = conn.execute(
            "SELECT id FROM artifacts WHERE auth_user_id = ?", (current_user.id,)
        ).fetchall()
    finally:
        conn.close()
    granted = ReportPermission.query.filter_by(user_id=current_user.id).with_entities(
        ReportPermission.artifact_id
    ).all()
    return sorted({int(row["id"]) for row in owned} | {int(row[0]) for row in granted})


def can_access_artifact(artifact_id: int) -> bool:
    """Check existence and owner, grant, or administrator access without returning data."""
    if not artifact_exists(artifact_id):
        return False
    owner_id = get_artifact_auth_user_id(artifact_id)
    if current_user.has_role("administrator") or owner_id == current_user.id:
        return True
    return ReportPermission.query.filter_by(
        artifact_id=artifact_id, user_id=current_user.id
    ).first() is not None


def require_artifact_access(artifact_id: int, action: str | None = None) -> bool:
    """Apply uniform 404 behavior to missing and unauthorized artifact IDs."""
    if not can_access_artifact(artifact_id):
        return False
    if action:
        write_report_audit(action, artifact_id)
    return True


def write_report_audit(action: str, artifact_id: int, target_user_id: int | None = None) -> None:
    """Persist a non-sensitive audit event for a report action."""
    db.session.add(
        ReportAuditLog(
            artifact_id=artifact_id,
            actor_user_id=current_user.id,
            target_user_id=target_user_id,
            action=action,
            ip_address=request.remote_addr,
            created_at=datetime.now(timezone.utc),
        )
    )
    db.session.commit()


def grant_report_access(artifact_id: int, target_user_id: int) -> bool:
    """Grant access if absent; return whether a new permission was created."""
    existing = ReportPermission.query.filter_by(
        artifact_id=artifact_id, user_id=target_user_id
    ).first()
    if existing:
        return False
    db.session.add(
        ReportPermission(
            artifact_id=artifact_id,
            user_id=target_user_id,
            granted_by_user_id=current_user.id,
        )
    )
    write_report_audit("permission_granted", artifact_id, target_user_id)
    return True


def revoke_report_access(artifact_id: int, target_user_id: int) -> bool:
    """Revoke an existing permission; return whether a permission was removed."""
    permission = ReportPermission.query.filter_by(
        artifact_id=artifact_id, user_id=target_user_id
    ).first()
    if permission is None:
        return False
    db.session.delete(permission)
    write_report_audit("permission_revoked", artifact_id, target_user_id)
    return True
