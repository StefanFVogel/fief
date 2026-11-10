"""Encrypt secrets at rest

Revision ID: c3d1e9a4b7f2
Revises: f0462e660029
Create Date: 2026-11-10 00:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

import fief
from fief.settings import settings

# revision identifiers, used by Alembic.
revision = "c3d1e9a4b7f2"
down_revision = "f0462e660029"
branch_labels = None
depends_on = None

SECRET_COLUMNS = [
    ("tenants", "sign_jwk"),
    ("clients", "client_secret"),
    ("webhooks", "secret"),
]

# Columns widened to TEXT to fit the ciphertext.
# On SQLite, VARCHAR and TEXT share the same affinity, so we don't alter them:
# recreating the referenced `clients` table would cascade deletions.
STRING_COLUMNS = [
    ("clients", "client_secret"),
    ("webhooks", "secret"),
]


def _convert_secrets(*, encrypt: bool) -> None:
    table_prefix = op.get_context().opts["table_prefix"]
    connection = op.get_bind()
    for table_name, column_name in SECRET_COLUMNS:
        plaintext_table = sa.table(
            f"{table_prefix}{table_name}",
            sa.column("id", fief.models.generics.GUID()),
            sa.column(column_name, sa.Text()),
        )
        encrypted_table = sa.table(
            f"{table_prefix}{table_name}",
            sa.column("id", fief.models.generics.GUID()),
            sa.column(
                column_name,
                fief.crypto.encryption.StringEncryptedType(
                    sa.Text,
                    settings.encryption_key,
                    fief.crypto.encryption.FernetEngine,
                ),
            ),
        )
        read_table, write_table = (
            (plaintext_table, encrypted_table)
            if encrypt
            else (encrypted_table, plaintext_table)
        )
        rows = connection.execute(
            sa.select(read_table.c.id, read_table.c[column_name])
        ).all()
        for id, value in rows:
            connection.execute(
                sa.update(write_table)
                .where(write_table.c.id == id)
                .values({column_name: value})
            )


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    op.drop_index(
        op.f(f"ix_{table_prefix}clients_client_secret"),
        table_name=f"{table_prefix}clients",
    )

    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        for table_name, column_name in STRING_COLUMNS:
            op.alter_column(
                f"{table_prefix}{table_name}",
                column_name,
                existing_type=sa.String(length=255),
                type_=sa.Text(),
                existing_nullable=False,
            )

    _convert_secrets(encrypt=True)


def downgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    _convert_secrets(encrypt=False)

    connection = op.get_bind()
    if connection.dialect.name != "sqlite":
        for table_name, column_name in STRING_COLUMNS:
            op.alter_column(
                f"{table_prefix}{table_name}",
                column_name,
                existing_type=sa.Text(),
                type_=sa.String(length=255),
                existing_nullable=False,
            )

    op.create_index(
        op.f(f"ix_{table_prefix}clients_client_secret"),
        f"{table_prefix}clients",
        ["client_secret"],
        unique=False,
    )
