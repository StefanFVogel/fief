import pytest
from sqlalchemy import select, text

from fief.db import AsyncSession
from fief.models import Client
from fief.repositories import ClientRepository
from tests.data import TestData


@pytest.mark.asyncio
async def test_client_secret_encrypted_at_rest(
    main_session: AsyncSession, test_data: TestData
):
    client = test_data["clients"]["default_tenant"]
    result = await main_session.execute(
        select(text("client_secret"))
        .select_from(Client.__table__)
        .where(Client.id == client.id)
    )
    stored_value = result.scalar_one()

    assert client.client_secret not in stored_value


@pytest.mark.asyncio
class TestGetByClientIdAndSecret:
    async def test_valid(self, main_session: AsyncSession, test_data: TestData):
        client = test_data["clients"]["default_tenant"]
        client_repository = ClientRepository(main_session)

        result = await client_repository.get_by_client_id_and_secret(
            client.client_id, client.client_secret
        )

        assert result is not None
        assert result.id == client.id

    async def test_invalid_secret(
        self, main_session: AsyncSession, test_data: TestData
    ):
        client = test_data["clients"]["default_tenant"]
        client_repository = ClientRepository(main_session)

        result = await client_repository.get_by_client_id_and_secret(
            client.client_id, "INVALID_CLIENT_SECRET"
        )

        assert result is None

    async def test_non_ascii_secret(
        self, main_session: AsyncSession, test_data: TestData
    ):
        client = test_data["clients"]["default_tenant"]
        client_repository = ClientRepository(main_session)

        result = await client_repository.get_by_client_id_and_secret(
            client.client_id, "Ä-INVALID_CLIENT_SECRET"
        )

        assert result is None

    async def test_unknown_client_id(
        self, main_session: AsyncSession, test_data: TestData
    ):
        client = test_data["clients"]["default_tenant"]
        client_repository = ClientRepository(main_session)

        result = await client_repository.get_by_client_id_and_secret(
            "UNKNOWN_CLIENT_ID", client.client_secret
        )

        assert result is None
