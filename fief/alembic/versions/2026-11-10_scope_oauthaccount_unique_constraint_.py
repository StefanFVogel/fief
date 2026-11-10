"""Scope OAuthAccount unique constraint on provider_id and account_id by tenant

Revision ID: 4eef465ce7bd
Revises: c3d1e9a4b7f2
Create Date: 2026-11-10 12:00:00.000000

"""

from alembic import op

# revision identifiers, used by Alembic.
revision = "4eef465ce7bd"
down_revision = "c3d1e9a4b7f2"
branch_labels = None
depends_on = None

OLD_COLUMNS = ["oauth_provider_id", "account_id"]
NEW_COLUMNS = ["oauth_provider_id", "account_id", "tenant_id"]


def _constraint_name(table_prefix: str, columns: list[str]) -> str:
    return op.f(f"{table_prefix}oauth_accounts_{'_'.join(columns)}_key")


def _swap_unique_constraint(drop_columns: list[str], create_columns: list[str]) -> None:
    table_prefix = op.get_context().opts["table_prefix"]
    table_name = f"{table_prefix}oauth_accounts"
    drop_name = _constraint_name(table_prefix, drop_columns)
    create_name = _constraint_name(table_prefix, create_columns)

    # Create the new constraint before dropping the old one,
    # so MySQL always has an index for the oauth_provider_id foreign key.
    connection = op.get_bind()
    if connection.dialect.name == "sqlite":
        with op.batch_alter_table(table_name) as batch_op:
            batch_op.create_unique_constraint(create_name, create_columns)
            batch_op.drop_constraint(drop_name, type_="unique")
    else:
        op.create_unique_constraint(create_name, table_name, create_columns)
        op.drop_constraint(drop_name, table_name, type_="unique")


def upgrade():
    _swap_unique_constraint(OLD_COLUMNS, NEW_COLUMNS)


def downgrade():
    _swap_unique_constraint(NEW_COLUMNS, OLD_COLUMNS)
