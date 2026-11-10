from unittest.mock import MagicMock, patch

import pytest

from fief.db import AsyncEngine
from fief.services.initializer import Initializer
from fief.settings import settings
from tests.data import TestData


@pytest.mark.asyncio
class TestCreateAdmin:
    async def test_valid(
        self, main_engine: AsyncEngine, main_session_manager, test_data: TestData
    ):
        initializer = Initializer(main_engine, settings)
        initializer.sessionmaker = main_session_manager

        with patch("fief.services.initializer.send_task", MagicMock()):
            user = await initializer.create_admin(
                "new-admin@bretagne.duchy", "herminetincture"
            )

        assert user.email == "new-admin@bretagne.duchy"
