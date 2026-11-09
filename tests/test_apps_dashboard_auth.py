from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest
from fastapi import status
from fief_client import FiefAccessTokenMissingPermission

from fief.crypto.token import get_token_hash
from fief.db import AsyncSession
from fief.repositories import AdminSessionTokenRepository
from fief.settings import settings
from fief.settings_class import Settings
from tests.conftest import create_admin_session_token
from tests.data import TestData
from tests.helpers import HTTPXResponseAssertion


@pytest.mark.asyncio
class TestAuthLogin:
    async def test_success(
        self,
        test_client_dashboard: httpx.AsyncClient,
        fief_client_mock: MagicMock,
    ):
        fief_client_mock.auth_url.side_effect = AsyncMock(
            return_value="http://localhost/authorize"
        )

        response = await test_client_dashboard.get("/auth/login")

        assert response.status_code == status.HTTP_302_FOUND

        location = response.headers["Location"]
        assert location == "http://localhost/authorize"

        state = response.cookies[settings.fief_admin_state_cookie_name]
        assert state != ""
        set_cookie_header = response.headers["Set-Cookie"].lower()
        assert "httponly" in set_cookie_header
        assert "samesite=lax" in set_cookie_header

        fief_client_mock.auth_url.assert_called_once_with(
            redirect_uri="http://api.fief.dev/auth/callback",
            state=state,
            scope=["openid"],
            extras_params={"screen": "login"},
        )


@pytest.mark.asyncio
class TestAuthCallback:
    async def test_missing_code(self, test_client_dashboard: httpx.AsyncClient):
        response = await test_client_dashboard.get("/auth/callback")

        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    @pytest.mark.parametrize(
        "state,state_cookie",
        [
            pytest.param(None, None, id="Missing state and cookie"),
            pytest.param("STATE", None, id="Missing cookie"),
            pytest.param(None, "STATE", id="Missing state"),
            pytest.param("STATE", "OTHER_STATE", id="State mismatch"),
            pytest.param("ÉTAT", "STATE", id="Non-ASCII state"),
        ],
    )
    async def test_invalid_state(
        self,
        state: str | None,
        state_cookie: str | None,
        test_client_dashboard: httpx.AsyncClient,
        fief_client_mock: MagicMock,
    ):
        params = {"code": "CODE"}
        if state is not None:
            params["state"] = state
        if state_cookie is not None:
            test_client_dashboard.cookies.set(
                settings.fief_admin_state_cookie_name, state_cookie
            )

        response = await test_client_dashboard.get("/auth/callback", params=params)

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        session_cookie = response.cookies.get(settings.fief_admin_session_cookie_name)
        assert session_cookie is None
        fief_client_mock.auth_callback.assert_not_called()

    async def test_missing_permission(
        self, test_client_dashboard: httpx.AsyncClient, fief_client_mock: MagicMock
    ):
        fief_client_mock.auth_callback.side_effect = AsyncMock(
            return_value=(
                {"access_token": "ACCESS_TOKEN", "id_token": "ID_TOKEN"},
                {"email": "anne@bretagne.duchy"},
            )
        )
        fief_client_mock.validate_access_token.side_effect = (
            FiefAccessTokenMissingPermission()
        )

        test_client_dashboard.cookies.set(
            settings.fief_admin_state_cookie_name, "STATE"
        )
        response = await test_client_dashboard.get(
            "/auth/callback", params={"code": "CODE", "state": "STATE"}
        )

        assert response.status_code == status.HTTP_403_FORBIDDEN

        session_cookie = response.cookies.get(settings.fief_admin_session_cookie_name)
        assert session_cookie is None

    async def test_success(
        self,
        test_client_dashboard: httpx.AsyncClient,
        fief_client_mock: MagicMock,
        main_session: AsyncSession,
    ):
        fief_client_mock.auth_callback.side_effect = AsyncMock(
            return_value=(
                {"access_token": "ACCESS_TOKEN", "id_token": "ID_TOKEN"},
                {"email": "anne@bretagne.duchy"},
            )
        )

        test_client_dashboard.cookies.set(
            settings.fief_admin_state_cookie_name, "STATE"
        )
        response = await test_client_dashboard.get(
            "/auth/callback", params={"code": "CODE", "state": "STATE"}
        )

        assert response.status_code == status.HTTP_302_FOUND

        session_cookie = response.cookies.get(settings.fief_admin_session_cookie_name)
        assert session_cookie is not None

        admin_session_token_repository = AdminSessionTokenRepository(main_session)
        session_token_hash = get_token_hash(session_cookie)
        session_token = await admin_session_token_repository.get_by_token(
            session_token_hash
        )
        assert session_token is not None
        assert session_token.userinfo == {"email": "anne@bretagne.duchy"}

        expected_expires_at = datetime.now(UTC) + timedelta(
            seconds=settings.fief_admin_session_lifetime_seconds
        )
        assert (
            expected_expires_at - timedelta(seconds=5)
            <= session_token.expires_at
            <= expected_expires_at
        )

        assert any(
            header.startswith(f"{settings.fief_admin_session_cookie_name}=")
            and f"max-age={settings.fief_admin_session_lifetime_seconds}"
            in header.lower()
            for header in response.headers.get_list("Set-Cookie")
        )

        assert any(
            header.startswith(f"{settings.fief_admin_state_cookie_name}=")
            and "max-age=0" in header.lower()
            for header in response.headers.get_list("Set-Cookie")
        )


def test_admin_session_settings_defaults():
    assert Settings.model_fields["fief_admin_session_lifetime_seconds"].default == 7200
    assert (
        Settings.model_fields["fief_admin_session_idle_timeout_seconds"].default == 1800
    )


def test_admin_session_settings_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("FIEF_ADMIN_SESSION_LIFETIME_SECONDS", "600")
    monkeypatch.setenv("FIEF_ADMIN_SESSION_IDLE_TIMEOUT_SECONDS", "60")

    overridden_settings = Settings()  # pyright: ignore

    assert overridden_settings.fief_admin_session_lifetime_seconds == 600
    assert overridden_settings.fief_admin_session_idle_timeout_seconds == 60


@pytest.mark.asyncio
class TestAdminSessionExpiration:
    async def _get_profile(
        self,
        test_client_dashboard: httpx.AsyncClient,
        main_session: AsyncSession,
        test_data: TestData,
        *,
        created_ago: timedelta = timedelta(0),
        last_activity_ago: timedelta = timedelta(0),
    ):
        session_token, token = await create_admin_session_token(
            test_data["users"]["admin"], main_session
        )
        now = datetime.now(UTC)
        session_token.created_at = now - created_ago
        session_token.expires_at = (
            now
            - created_ago
            + timedelta(seconds=settings.fief_admin_session_lifetime_seconds)
        )
        session_token.last_activity_at = now - last_activity_ago
        main_session.add(session_token)
        await main_session.commit()
        expires_at = session_token.expires_at

        test_client_dashboard.cookies.set(
            settings.fief_admin_session_cookie_name, token
        )
        response = await test_client_dashboard.get("/auth/profile")

        main_session.expunge_all()
        repository = AdminSessionTokenRepository(main_session)
        stored_session_token = await repository.get_by_token(get_token_hash(token))

        return response, expires_at, stored_session_token

    async def test_absolute_lifetime_exceeded(
        self,
        test_client_dashboard: httpx.AsyncClient,
        main_session: AsyncSession,
        test_data: TestData,
    ):
        response, _, stored_session_token = await self._get_profile(
            test_client_dashboard,
            main_session,
            test_data,
            created_ago=timedelta(
                seconds=settings.fief_admin_session_lifetime_seconds + 1
            ),
        )

        assert response.status_code == status.HTTP_307_TEMPORARY_REDIRECT
        assert response.headers["Location"].endswith("/auth/login")
        assert stored_session_token is None

    async def test_idle_timeout_exceeded(
        self,
        test_client_dashboard: httpx.AsyncClient,
        main_session: AsyncSession,
        test_data: TestData,
    ):
        response, _, stored_session_token = await self._get_profile(
            test_client_dashboard,
            main_session,
            test_data,
            created_ago=timedelta(
                seconds=settings.fief_admin_session_idle_timeout_seconds + 60
            ),
            last_activity_ago=timedelta(
                seconds=settings.fief_admin_session_idle_timeout_seconds + 1
            ),
        )

        assert response.status_code == status.HTTP_307_TEMPORARY_REDIRECT
        assert response.headers["Location"].endswith("/auth/login")
        assert stored_session_token is None

    async def test_idle_timeout_setting_override(
        self,
        test_client_dashboard: httpx.AsyncClient,
        main_session: AsyncSession,
        test_data: TestData,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(settings, "fief_admin_session_idle_timeout_seconds", 10)

        response, _, stored_session_token = await self._get_profile(
            test_client_dashboard,
            main_session,
            test_data,
            created_ago=timedelta(seconds=60),
            last_activity_ago=timedelta(seconds=11),
        )

        assert response.status_code == status.HTTP_307_TEMPORARY_REDIRECT
        assert stored_session_token is None

    async def test_activity_extends_idle_window_only(
        self,
        test_client_dashboard: httpx.AsyncClient,
        main_session: AsyncSession,
        test_data: TestData,
    ):
        response, expires_at, stored_session_token = await self._get_profile(
            test_client_dashboard,
            main_session,
            test_data,
            created_ago=timedelta(
                seconds=settings.fief_admin_session_idle_timeout_seconds + 60
            ),
            last_activity_ago=timedelta(
                seconds=settings.fief_admin_session_idle_timeout_seconds - 60
            ),
        )

        assert response.status_code == status.HTTP_302_FOUND
        assert stored_session_token is not None
        assert stored_session_token.last_activity_at >= datetime.now(UTC) - timedelta(
            seconds=5
        )
        assert stored_session_token.expires_at == expires_at


@pytest.mark.asyncio
class TestAuthProfile:
    async def test_unauthorized(
        self,
        unauthorized_dashboard_assertions: HTTPXResponseAssertion,
        test_client_dashboard: httpx.AsyncClient,
    ):
        response = await test_client_dashboard.get("/auth/profile")

        unauthorized_dashboard_assertions(response)

    @pytest.mark.authenticated_admin(mode="session")
    async def test_valid(self, test_client_dashboard: httpx.AsyncClient):
        response = await test_client_dashboard.get("/auth/profile")

        assert response.status_code == status.HTTP_302_FOUND

        location = response.headers["Location"]
        assert location == f"//{settings.fief_domain}"


@pytest.mark.asyncio
class TestAuthLogout:
    async def test_unauthorized(self, test_client_dashboard: httpx.AsyncClient):
        response = await test_client_dashboard.get("/auth/logout")

        assert response.status_code == status.HTTP_307_TEMPORARY_REDIRECT

    @pytest.mark.authenticated_admin(mode="session")
    async def test_valid(
        self,
        test_client_dashboard: httpx.AsyncClient,
        main_session: AsyncSession,
        fief_client_mock: MagicMock,
    ):
        token = test_client_dashboard.cookies.get(
            settings.fief_admin_session_cookie_name
        )
        assert token is not None
        token_hash = get_token_hash(token)

        fief_client_mock.base_url = "https://bretagne.fief.dev"
        response = await test_client_dashboard.get("/auth/logout")

        assert response.status_code == status.HTTP_302_FOUND

        location = response.headers["Location"]
        assert (
            location
            == f"//{settings.fief_domain}/logout?redirect_uri=http://api.fief.dev/admin/"
        )

        assert "Set-Cookie" in response.headers

        admin_session_token_repository = AdminSessionTokenRepository(main_session)
        deleted_admin_session_token = await admin_session_token_repository.get_by_token(
            token_hash
        )
        assert deleted_admin_session_token is None

    @pytest.mark.authenticated_admin(mode="session")
    async def test_logout_chain_reaches_admin(
        self,
        test_client_dashboard: httpx.AsyncClient,
        test_client_auth: httpx.AsyncClient,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(settings, "fief_domain", "api.fief.dev")

        response = await test_client_dashboard.get("/auth/logout")
        assert response.status_code == status.HTTP_302_FOUND

        location = response.headers["Location"]
        assert location.startswith("//api.fief.dev/logout?")

        response = await test_client_auth.get(f"http:{location}")

        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"] == "http://api.fief.dev/admin/"
