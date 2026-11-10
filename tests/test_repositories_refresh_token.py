import pytest

from fief.db import AsyncSession
from fief.repositories import RefreshTokenRepository
from tests.data import TestData


@pytest.mark.asyncio
async def test_consume(main_session: AsyncSession, test_data: TestData):
    refresh_token_repository = RefreshTokenRepository(main_session)
    refresh_token = await refresh_token_repository.get_by_id(
        test_data["refresh_tokens"]["default_regular"].id
    )
    assert refresh_token is not None

    assert await refresh_token_repository.consume(refresh_token) is True
    assert await refresh_token_repository.consume(refresh_token) is False
    assert (
        await refresh_token_repository.get_by_token(refresh_token.token, fresh=False)
        is None
    )
