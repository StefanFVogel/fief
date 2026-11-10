from typing import cast

from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult

from fief.models import RefreshToken
from fief.repositories.base import BaseRepository, ExpiresAtMixin, UUIDRepositoryMixin


class RefreshTokenRepository(
    BaseRepository[RefreshToken],
    UUIDRepositoryMixin[RefreshToken],
    ExpiresAtMixin[RefreshToken],
):
    model = RefreshToken

    async def get_by_token(
        self, token: str, *, fresh: bool = True
    ) -> RefreshToken | None:
        statement = select(RefreshToken).where(RefreshToken.token == token)
        if fresh:
            statement = statement.where(RefreshToken.is_expired.is_(False))

        return await self.get_one_or_none(statement)

    async def consume(self, refresh_token: RefreshToken) -> bool:
        statement = delete(RefreshToken).where(RefreshToken.id == refresh_token.id)
        result = cast(CursorResult, await self._execute_statement(statement))
        return result.rowcount == 1
