"""add report permissions and access audit records

Revision ID: 1cbdfbc7a211
Revises: bb83d50706ad
Create Date: 2026-11-19
"""
from alembic import op
import sqlalchemy as sa


revision = "1cbdfbc7a211"
down_revision = "bb83d50706ad"
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        "report_permissions",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("artifact_id", sa.Integer(), nullable=False),
        sa.Column("user_id", sa.Integer(), nullable=False),
        sa.Column("granted_by_user_id", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.ForeignKeyConstraint(["granted_by_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.UniqueConstraint("artifact_id", "user_id", name="uq_report_permission_artifact_user"),
    )
    op.create_index("ix_report_permissions_artifact_id", "report_permissions", ["artifact_id"])
    op.create_index("ix_report_permissions_user_id", "report_permissions", ["user_id"])

    op.create_table(
        "report_audit_logs",
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column("artifact_id", sa.Integer(), nullable=False),
        sa.Column("actor_user_id", sa.Integer(), nullable=False),
        sa.Column("target_user_id", sa.Integer(), nullable=True),
        sa.Column("action", sa.String(length=32), nullable=False),
        sa.Column("ip_address", sa.String(length=45), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "action IN ('analysis_view', 'report_view', 'pdf_download', 'sbom_download', "
            "'permission_granted', 'permission_revoked')",
            name="ck_report_audit_action",
        ),
        sa.ForeignKeyConstraint(["actor_user_id"], ["users.id"], ondelete="RESTRICT"),
        sa.ForeignKeyConstraint(["target_user_id"], ["users.id"], ondelete="SET NULL"),
    )
    op.create_index("ix_report_audit_logs_artifact_id", "report_audit_logs", ["artifact_id"])
    op.create_index("ix_report_audit_artifact_created", "report_audit_logs", ["artifact_id", "created_at"])


def downgrade():
    op.drop_index("ix_report_audit_artifact_created", table_name="report_audit_logs")
    op.drop_index("ix_report_audit_logs_artifact_id", table_name="report_audit_logs")
    op.drop_table("report_audit_logs")
    op.drop_index("ix_report_permissions_user_id", table_name="report_permissions")
    op.drop_index("ix_report_permissions_artifact_id", table_name="report_permissions")
    op.drop_table("report_permissions")
