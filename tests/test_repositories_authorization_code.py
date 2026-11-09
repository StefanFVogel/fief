import pytest

from fief.db import AsyncSession
from fief.repositories import AuthorizationCodeRepository
from tests.data import TestData


@pytest.mark.asyncio
async def test_consume(main_session: AsyncSession, test_data: TestData):
    authorization_code_repository = AuthorizationCodeRepository(main_session)
    authorization_code = await authorization_code_repository.get_by_id(
        test_data["authorization_codes"]["default_regular"].id
    )
    assert authorization_code is not None

    assert await authorization_code_repository.consume(authorization_code) is True
    assert await authorization_code_repository.consume(authorization_code) is False
    assert (
        await authorization_code_repository.get_by_code(authorization_code.code) is None
    )
