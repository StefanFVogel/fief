from datetime import UTC, datetime, timedelta
from unittest.mock import MagicMock

import pytest

from fief.crypto.token import get_token_hash
from fief.db import AsyncSession
from fief.repositories import AdminSessionTokenRepository
from fief.settings import settings
from fief.tasks.cleanup import CleanupTask
from tests.conftest import create_admin_session_token
from tests.data import TestData


@pytest.mark.asyncio
class TestTasksCleanup:
    async def test_cleanup(self, main_session_manager, send_task_mock: MagicMock):
        cleanup = CleanupTask(main_session_manager, send_task=send_task_mock)
        await cleanup.run()

    async def test_cleanup_admin_session_tokens(
        self,
        main_session_manager,
        main_session: AsyncSession,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        user = test_data["users"]["admin"]
        now = datetime.now(UTC)

        valid_session_token, valid_token = await create_admin_session_token(
            user, main_session
        )

        expired_session_token, expired_token = await create_admin_session_token(
            user, main_session
        )
        expired_session_token.expires_at = now - timedelta(seconds=1)

        idle_session_token, idle_token = await create_admin_session_token(
            user, main_session
        )
        idle_session_token.last_activity_at = now - timedelta(
            seconds=settings.fief_admin_session_idle_timeout_seconds + 1
        )
        await main_session.commit()

        cleanup = CleanupTask(main_session_manager, send_task=send_task_mock)
        await cleanup.run()

        main_session.expunge_all()
        repository = AdminSessionTokenRepository(main_session)
        assert await repository.get_by_token(get_token_hash(valid_token)) is not None
        assert await repository.get_by_token(get_token_hash(expired_token)) is None
        assert await repository.get_by_token(get_token_hash(idle_token)) is None
