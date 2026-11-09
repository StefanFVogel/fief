"""Add expiration to AdminSessionToken

Revision ID: f0462e660029
Revises: a736fe95ec4f
Create Date: 2026-11-09 22:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

import fief

# revision identifiers, used by Alembic.
revision = "f0462e660029"
down_revision = "a736fe95ec4f"
branch_labels = None
depends_on = None


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    # Existing admin sessions have no expiration: end them.
    op.execute(f"DELETE FROM {table_prefix}admin_session_tokens")

    columns = [
        sa.Column(
            "expires_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=False,
        ),
        sa.Column(
            "last_activity_at",
            fief.models.generics.TIMESTAMPAware(timezone=True),
            nullable=False,
        ),
    ]

    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(
            f"{table_prefix}admin_session_tokens", recreate="always"
        ) as batch_op:
            for column in columns:
                batch_op.add_column(column)
    else:
        for column in columns:
            op.add_column(f"{table_prefix}admin_session_tokens", column)

    op.create_index(
        op.f(f"ix_{table_prefix}admin_session_tokens_expires_at"),
        f"{table_prefix}admin_session_tokens",
        ["expires_at"],
        unique=False,
    )
    op.create_index(
        op.f(f"ix_{table_prefix}admin_session_tokens_last_activity_at"),
        f"{table_prefix}admin_session_tokens",
        ["last_activity_at"],
        unique=False,
    )


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.drop_index(
        op.f(f"ix_{table_prefix}admin_session_tokens_last_activity_at"),
        table_name=f"{table_prefix}admin_session_tokens",
    )
    op.drop_index(
        op.f(f"ix_{table_prefix}admin_session_tokens_expires_at"),
        table_name=f"{table_prefix}admin_session_tokens",
    )

    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(f"{table_prefix}admin_session_tokens") as batch_op:
            batch_op.drop_column("last_activity_at")
            batch_op.drop_column("expires_at")
    else:
        op.drop_column(f"{table_prefix}admin_session_tokens", "last_activity_at")
        op.drop_column(f"{table_prefix}admin_session_tokens", "expires_at")
