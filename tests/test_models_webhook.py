import pytest
from sqlalchemy import select, text

from fief.db import AsyncSession
from fief.models import Webhook
from tests.data import TestData


@pytest.mark.asyncio
async def test_secret_encrypted_at_rest(
    main_session: AsyncSession, test_data: TestData
):
    webhook = test_data["webhooks"]["all"]
    result = await main_session.execute(
        select(text("secret"))
        .select_from(Webhook.__table__)
        .where(Webhook.id == webhook.id)
    )
    stored_value = result.scalar_one()

    assert webhook.secret not in stored_value
