from pydantic import UUID4
from sqlalchemy import delete, select

from fief.models import SessionToken
from fief.repositories.base import BaseRepository, ExpiresAtMixin, UUIDRepositoryMixin


class SessionTokenRepository(
    BaseRepository[SessionToken],
    UUIDRepositoryMixin[SessionToken],
    ExpiresAtMixin[SessionToken],
):
    model = SessionToken

    async def get_by_token(
        self, token: str, *, fresh: bool = True
    ) -> SessionToken | None:
        statement = select(SessionToken).where(SessionToken.token == token)
        if fresh:
            statement = statement.where(SessionToken.is_expired.is_(False))

        return await self.get_one_or_none(statement)

    async def delete_by_user(
        self, user: UUID4, *, exclude: UUID4 | None = None
    ) -> None:
        statement = delete(SessionToken).where(SessionToken.user_id == user)
        if exclude is not None:
            statement = statement.where(SessionToken.id != exclude)
        await self._execute_statement(statement)
