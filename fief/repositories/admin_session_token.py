from datetime import UTC, datetime, timedelta

from sqlalchemy import delete, or_, select

from fief.models import AdminSessionToken
from fief.repositories.base import BaseRepository, ExpiresAtMixin, UUIDRepositoryMixin
from fief.settings import settings


class AdminSessionTokenRepository(
    BaseRepository[AdminSessionToken],
    UUIDRepositoryMixin[AdminSessionToken],
    ExpiresAtMixin[AdminSessionToken],
):
    model = AdminSessionToken

    async def get_by_token(self, token: str) -> AdminSessionToken | None:
        statement = select(AdminSessionToken).where(AdminSessionToken.token == token)
        return await self.get_one_or_none(statement)

    async def delete_expired(self):
        last_activity_limit = datetime.now(UTC) - timedelta(
            seconds=settings.fief_admin_session_idle_timeout_seconds
        )
        statement = delete(AdminSessionToken).where(
            or_(
                AdminSessionToken.is_expired.is_(True),
                AdminSessionToken.last_activity_at < last_activity_limit,
            )
        )
        await self._execute_statement(statement)
