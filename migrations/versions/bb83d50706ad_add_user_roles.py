"""add server enforced user roles

Revision ID: bb83d50706ad
Revises: 5076a89d9075
Create Date: 2026-11-19
"""
from alembic import op
import sqlalchemy as sa


revision = "bb83d50706ad"
down_revision = "5076a89d9075"
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.add_column(
            sa.Column("role", sa.String(length=24), nullable=False, server_default="developer")
        )
        batch_op.create_check_constraint(
            "ck_users_role",
            "role IN ('developer', 'authorized_user', 'administrator')",
        )

    # Preserve administrator status for accounts created by the old is_admin flag.
    op.execute("UPDATE users SET role = 'administrator' WHERE is_admin = 1")


def downgrade():
    with op.batch_alter_table("users") as batch_op:
        batch_op.drop_constraint("ck_users_role", type_="check")
        batch_op.drop_column("role")
