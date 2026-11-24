"""Cloud sign-in: Supabase account ID, e-mail and daily usage reporting on users.

Revision ID: 0003_cloud
Revises: 0002_workspaces
Create Date: 2026-11-24 22:12:06.288389
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

import filevow.db.base  # noqa: F401 - custom column types used by autogenerate

revision: str = "0003_cloud"
down_revision: str | None = "0002_workspaces"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


# Plain ADD COLUMN (no table rebuild): SQLite can't drop and recreate ``users`` while other
# tables reference it, and adding nullable columns or ones with a default is safe everywhere.


def upgrade() -> None:
    op.add_column("users", sa.Column("cloud_id", sa.String(length=64), nullable=True))
    op.add_column("users", sa.Column("email", sa.String(length=320), nullable=True))
    op.add_column("users", sa.Column("cloud_refresh_enc", sa.LargeBinary(), nullable=True))
    op.add_column("users", sa.Column("cloud_reported_on", sa.Date(), nullable=True))
    op.add_column(
        "users", sa.Column("usage_reporting", sa.Boolean(), server_default=sa.true(), nullable=False)
    )
    op.create_index(op.f("ix_users_cloud_id"), "users", ["cloud_id"], unique=True)


def downgrade() -> None:
    op.drop_index(op.f("ix_users_cloud_id"), table_name="users")
    with op.batch_alter_table("users", schema=None) as batch_op:
        batch_op.drop_column("usage_reporting")
        batch_op.drop_column("cloud_reported_on")
        batch_op.drop_column("cloud_refresh_enc")
        batch_op.drop_column("email")
        batch_op.drop_column("cloud_id")
