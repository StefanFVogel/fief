import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import status
from furl import furl
from jwcrypto import jwt

from fief.crypto.password import password_helper
from fief.models import User
from fief.services.user_manager import RESET_PASSWORD_TOKEN_AUDIENCE
from fief.settings import settings
from fief.tasks import on_after_forgot_password
from tests.data import TestData
from tests.helpers import str_match
from tests.types import TenantParams


def generate_jwt(user: User, *, exp: int | None = None, with_exp: bool = True) -> str:
    claims = {
        "sub": str(user.id),
        "password_fgpt": password_helper.hash(user.hashed_password),
        "aud": RESET_PASSWORD_TOKEN_AUDIENCE,
    }
    if with_exp:
        claims["exp"] = (
            exp
            if exp is not None
            else int(datetime.now(UTC).timestamp())
            + settings.reset_password_token_lifetime_seconds
        )
    signing_key = user.tenant.get_sign_jwk()
    token = jwt.JWT(header={"alg": "RS256", "kid": signing_key["kid"]}, claims=claims)
    token.make_signed_token(signing_key)

    return token.serialize()


def get_forgot_password_calls(send_task_mock: MagicMock) -> int:
    return len(
        [
            call
            for call in send_task_mock.call_args_list
            if call.args[0] == on_after_forgot_password
        ]
    )


@pytest.mark.asyncio
class TestGetForgotPassword:
    async def test_valid(
        self, tenant_params: TenantParams, test_client_auth: httpx.AsyncClient
    ):
        response = await test_client_auth.get(f"{tenant_params.path_prefix}/forgot")

        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
class TestPostForgotPassword:
    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="Missing email"),
            pytest.param({"email": "anne"}, id="Invalid email"),
        ],
    )
    async def test_invalid_form(
        self,
        data: dict[str, str],
        tenant_params: TenantParams,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
    ):
        response = await test_client_auth_csrf.post(
            f"{tenant_params.path_prefix}/forgot",
            data={**data, "csrf_token": csrf_token},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_not_existing_user(
        self,
        tenant_params: TenantParams,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        send_task_mock: MagicMock,
    ):
        response = await test_client_auth_csrf.post(
            f"{tenant_params.path_prefix}/forgot",
            data={"email": "louis@bretagne.duchy", "csrf_token": csrf_token},
        )

        assert response.status_code == status.HTTP_200_OK

        send_task_mock.assert_not_called()

    async def test_existing_user(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        user = test_data["users"]["regular"]

        response = await test_client_auth_csrf.post(
            "/forgot", data={"email": "anne@bretagne.duchy", "csrf_token": csrf_token}
        )

        assert response.status_code == status.HTTP_200_OK

        send_task_mock.assert_called_with(
            on_after_forgot_password,
            str(user.id),
            str_match(r"/reset.*token="),
        )

    async def test_too_many_requests(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        send_task_mock: MagicMock,
        rate_limiter_clock: MagicMock,
    ):
        responses = []
        for _ in range(3):
            response = await test_client_auth_csrf.post(
                "/forgot",
                data={"email": "anne@bretagne.duchy", "csrf_token": csrf_token},
            )
            assert response.status_code == status.HTTP_200_OK
            responses.append(response)

        assert get_forgot_password_calls(send_task_mock) == 2
        assert responses[2].text == responses[1].text

        rate_limiter_clock.return_value += 60

        response = await test_client_auth_csrf.post(
            "/forgot", data={"email": "anne@bretagne.duchy", "csrf_token": csrf_token}
        )
        assert response.status_code == status.HTTP_200_OK
        assert get_forgot_password_calls(send_task_mock) == 3

    async def test_existing_user_token_expires(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        user = test_data["users"]["regular"]

        now = int(datetime.now(UTC).timestamp())
        response = await test_client_auth_csrf.post(
            "/forgot", data={"email": "anne@bretagne.duchy", "csrf_token": csrf_token}
        )

        assert response.status_code == status.HTTP_200_OK

        reset_url = send_task_mock.call_args.args[2]
        token = furl(reset_url).args["token"]
        decoded_token = jwt.JWT(
            jwt=token, algs=["RS256"], key=user.tenant.get_sign_jwk()
        )
        claims = json.loads(decoded_token.claims)
        expected_exp = now + settings.reset_password_token_lifetime_seconds
        assert expected_exp <= claims["exp"] <= expected_exp + 5

    async def test_reset_url_uses_fief_domain(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(settings, "fief_domain", "auth.example.com")
        user = test_data["users"]["regular"]

        response = await test_client_auth_csrf.post(
            "/forgot",
            data={"email": "anne@bretagne.duchy", "csrf_token": csrf_token},
            headers={"Host": "evil.example"},
        )

        assert response.status_code == status.HTTP_200_OK

        send_task_mock.assert_called_with(
            on_after_forgot_password,
            str(user.id),
            str_match(r"^http://auth\.example\.com/reset\?token="),
        )


@pytest.mark.asyncio
class TestGetResetPassword:
    async def test_missing_token(
        self, tenant_params: TenantParams, test_client_auth: httpx.AsyncClient
    ):
        response = await test_client_auth.get(f"{tenant_params.path_prefix}/reset")

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        headers = response.headers
        assert headers["X-Fief-Error"] == "missing_token"

    async def test_valid(
        self, tenant_params: TenantParams, test_client_auth: httpx.AsyncClient
    ):
        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/reset", params={"token": "TOKEN"}
        )

        assert response.status_code == status.HTTP_200_OK


@pytest.mark.asyncio
class TestPostResetPassword:
    @pytest.mark.parametrize(
        "data",
        [
            pytest.param({}, id="Missing password and token"),
            pytest.param({"password": "newherminetincture"}, id="Missing token"),
            pytest.param({"token": "TOKEN"}, id="Missing password"),
            pytest.param(
                {"token": "TOKEN", "password": "newherminetincture"}, id="Invalid token"
            ),
        ],
    )
    async def test_invalid_form(
        self,
        data: dict[str, str],
        tenant_params: TenantParams,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
    ):
        response = await test_client_auth_csrf.post(
            f"{tenant_params.path_prefix}/reset",
            data={**data, "csrf_token": csrf_token},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_invalid_password(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
    ):
        user = test_data["users"]["regular"]
        token = generate_jwt(user)

        response = await test_client_auth_csrf.post(
            "/reset", data={"password": "h", "token": token, "csrf_token": csrf_token}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    @pytest.mark.parametrize(
        "token_kwargs",
        [
            pytest.param(
                {"exp": int(datetime.now(UTC).timestamp()) - 3600}, id="Expired token"
            ),
            pytest.param({"with_exp": False}, id="Token without expiration"),
        ],
    )
    async def test_expired_or_not_expiring_token(
        self,
        token_kwargs: dict,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
    ):
        user = test_data["users"]["regular"]
        token = generate_jwt(user, **token_kwargs)

        response = await test_client_auth_csrf.post(
            "/reset",
            data={
                "password": "newherminetincture",
                "token": token,
                "csrf_token": csrf_token,
            },
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        headers = response.headers
        assert headers["X-Fief-Error"] == "invalid_token"

    async def test_valid(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
    ):
        user = test_data["users"]["regular"]
        token = generate_jwt(user)

        response = await test_client_auth_csrf.post(
            "/reset",
            data={
                "password": "newherminetincture",
                "token": token,
                "csrf_token": csrf_token,
            },
        )

        assert response.status_code == status.HTTP_302_FOUND

        redirect_uri = response.headers["Location"]
        assert redirect_uri.endswith("/")

    async def test_valid_resets_forgot_password_rate_limit(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        user = test_data["users"]["regular"]
        for _ in range(2):
            await test_client_auth_csrf.post(
                "/forgot", data={"email": user.email, "csrf_token": csrf_token}
            )

        response = await test_client_auth_csrf.post(
            "/reset",
            data={
                "password": "newherminetincture",
                "token": generate_jwt(user),
                "csrf_token": csrf_token,
            },
        )
        assert response.status_code == status.HTTP_302_FOUND

        await test_client_auth_csrf.post(
            "/forgot", data={"email": user.email, "csrf_token": csrf_token}
        )
        assert get_forgot_password_calls(send_task_mock) == 3

    async def test_valid_with_login_session(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
    ):
        user = test_data["users"]["regular"]
        token = generate_jwt(user)
        login_session = test_data["login_sessions"]["default"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token

        response = await test_client_auth_csrf.post(
            "/reset",
            data={
                "password": "newherminetincture",
                "token": token,
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_302_FOUND

        redirect_uri = response.headers["Location"]
        assert redirect_uri.endswith("/login")
