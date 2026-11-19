"""Report-level grants and access audit records."""
from datetime import datetime, timezone

from app.extensions import db


class ReportPermission(db.Model):
    __tablename__ = "report_permissions"
    __table_args__ = (
        db.UniqueConstraint("artifact_id", "user_id", name="uq_report_permission_artifact_user"),
        db.Index("ix_report_permissions_user_id", "user_id"),
    )

    id = db.Column(db.Integer, primary_key=True)
    artifact_id = db.Column(db.Integer, nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    granted_by_user_id = db.Column(
        db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    user = db.relationship("User", foreign_keys=[user_id])
    granted_by = db.relationship("User", foreign_keys=[granted_by_user_id])


class ReportAuditLog(db.Model):
    __tablename__ = "report_audit_logs"
    __table_args__ = (
        db.CheckConstraint(
            "action IN ('analysis_view', 'report_view', 'pdf_download', 'sbom_download', "
            "'permission_granted', 'permission_revoked')",
            name="ck_report_audit_action",
        ),
        db.Index("ix_report_audit_artifact_created", "artifact_id", "created_at"),
    )

    id = db.Column(db.Integer, primary_key=True)
    artifact_id = db.Column(db.Integer, nullable=False, index=True)
    actor_user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    target_user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    action = db.Column(db.String(32), nullable=False)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    actor = db.relationship("User", foreign_keys=[actor_user_id])
    target_user = db.relationship("User", foreign_keys=[target_user_id])
