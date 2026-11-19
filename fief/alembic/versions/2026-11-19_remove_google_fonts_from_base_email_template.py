"""Remove Google Fonts import from base email template

Revision ID: 0ca0ffa65291
Revises: 4eef465ce7bd
Create Date: 2026-11-19 12:00:00.000000

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "0ca0ffa65291"
down_revision = "4eef465ce7bd"
branch_labels = None
depends_on = None

GOOGLE_FONTS_IMPORT = '@import url("https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap");'


def upgrade():
    table_prefix = op.get_context().opts["table_prefix"]
    email_templates = sa.table(
        f"{table_prefix}email_templates",
        sa.column("type", sa.String()),
        sa.column("content", sa.Text()),
    )
    # The base template is copied into the database on first start,
    # so existing installations still load Inter from Google when a mail is opened.
    # Remove the whole line as shipped, then any remaining occurrence of the statement.
    for statement in (f"    {GOOGLE_FONTS_IMPORT}\n\n", GOOGLE_FONTS_IMPORT):
        op.execute(
            email_templates.update()
            .where(email_templates.c.type == "BASE")
            .values(content=sa.func.replace(email_templates.c.content, statement, ""))
        )


def downgrade():
    # Don't reintroduce the request to Google Fonts.
    pass
