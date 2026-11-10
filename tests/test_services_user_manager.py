from unittest.mock import MagicMock

import pytest

from fief.crypto.password import password_helper
from fief.db import AsyncSession
from fief.repositories import (
    EmailVerificationRepository,
    RefreshTokenRepository,
    SessionTokenRepository,
    UserRepository,
)
from fief.schemas.user import UserFields, UserUpdateAdmin
from fief.services.user_manager import UserManager
from tests.data import TestData
from tests.helpers import get_user_tokens


class UserUpdateIsActive(UserUpdateAdmin[UserFields]):
    is_active: bool | None = None


@pytest.fixture
def user_manager(main_session: AsyncSession) -> UserManager:
    return UserManager(
        password_helper=password_helper,
        user_repository=UserRepository(main_session),
        email_verification_repository=EmailVerificationRepository(main_session),
        session_token_repository=SessionTokenRepository(main_session),
        refresh_token_repository=RefreshTokenRepository(main_session),
        user_fields=[],
        send_task=MagicMock(),
        audit_logger=MagicMock(),
        trigger_webhooks=MagicMock(),
        user_roles=MagicMock(),
    )


@pytest.mark.asyncio
class TestUpdate:
    async def test_deactivate_revokes_tokens(
        self,
        user_manager: UserManager,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = await UserRepository(main_session).get_by_id(
            test_data["users"]["regular"].id
        )
        assert user is not None

        await user_manager.update(UserUpdateIsActive(is_active=False), user)

        session_tokens, refresh_tokens = await get_user_tokens(main_session, user)
        assert session_tokens == []
        assert refresh_tokens == []

    async def test_without_deactivation_keeps_tokens(
        self,
        user_manager: UserManager,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        user = await UserRepository(main_session).get_by_id(
            test_data["users"]["regular"].id
        )
        assert user is not None

        await user_manager.update(UserUpdateIsActive(is_active=True), user)

        session_tokens, refresh_tokens = await get_user_tokens(main_session, user)
        assert len(session_tokens) > 0
        assert len(refresh_tokens) > 0
