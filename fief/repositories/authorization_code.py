from datetime import UTC, datetime
from typing import cast

from sqlalchemy import delete, select
from sqlalchemy.engine import CursorResult

from fief.models import AuthorizationCode
from fief.repositories.base import BaseRepository, ExpiresAtMixin, UUIDRepositoryMixin


class AuthorizationCodeRepository(
    BaseRepository[AuthorizationCode],
    UUIDRepositoryMixin[AuthorizationCode],
    ExpiresAtMixin[AuthorizationCode],
):
    model = AuthorizationCode

    async def get_valid_by_code(self, code: str) -> AuthorizationCode | None:
        statement = select(AuthorizationCode).where(
            AuthorizationCode.code == code,
            AuthorizationCode.expires_at > datetime.now(UTC),
        )
        return await self.get_one_or_none(statement)

    async def get_by_code(self, code: str) -> AuthorizationCode | None:
        statement = select(AuthorizationCode).where(AuthorizationCode.code == code)
        return await self.get_one_or_none(statement)

    async def consume(self, authorization_code: AuthorizationCode) -> bool:
        statement = delete(AuthorizationCode).where(
            AuthorizationCode.id == authorization_code.id
        )
        result = cast(CursorResult, await self._execute_statement(statement))
        return result.rowcount == 1
