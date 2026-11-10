import urllib.parse
from typing import Any
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import status
from furl import furl

from fief.crypto.password import password_helper
from fief.crypto.token import get_token_hash
from fief.db import AsyncSession
from fief.models import RegistrationSessionFlow, UserField, UserFieldType
from fief.repositories import (
    OAuthAccountRepository,
    RegistrationSessionRepository,
    SessionTokenRepository,
    UserRepository,
)
from fief.settings import settings
from fief.tasks import (
    on_after_register,
    on_existing_account_registration,
    on_registration_confirmation_requested,
)
from tests.data import TestData
from tests.helpers import str_match
from tests.types import TenantParams


@pytest.mark.asyncio
class TestGetRegister:
    async def test_invalid_login_session(
        self, tenant_params: TenantParams, test_client_auth: httpx.AsyncClient
    ):
        cookies = {}
        cookies[settings.login_session_cookie_name] = "INVALID_LOGIN_SESSION"

        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/register", cookies=cookies
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        headers = response.headers
        assert headers["X-Fief-Error"] == "invalid_session"

    async def test_disabled_registration_tenant(
        self, test_client_auth: httpx.AsyncClient, test_data: TestData
    ):
        login_session = test_data["login_sessions"]["registration_disabled"]
        client = login_session.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token

        response = await test_client_auth.get(
            f"{path_prefix}/register", cookies=cookies
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        headers = response.headers
        assert headers["X-Fief-Error"] == "registration_disabled"

    async def test_valid_no_login_session(
        self,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        tenant = test_data["tenants"]["default"]
        path_prefix = tenant.slug if not tenant.default else ""

        response = await test_client_auth.get(f"{path_prefix}/register")

        assert response.status_code == status.HTTP_200_OK

        html = response.text
        assert 'name="password"' not in html

        registration_session_cookie = response.cookies[
            settings.registration_session_cookie_name
        ]
        set_cookie_header = next(
            header
            for header in response.headers.get_list("Set-Cookie")
            if header.startswith(f"{settings.registration_session_cookie_name}=")
        )
        assert "httponly" in set_cookie_header.lower()

        registration_session_repository = RegistrationSessionRepository(main_session)
        registration_session = await registration_session_repository.get_by_token(
            registration_session_cookie
        )
        assert registration_session is not None
        assert registration_session.flow == RegistrationSessionFlow.PASSWORD
        assert registration_session.tenant_id == tenant.id

    async def test_valid_no_registration_session(
        self,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        login_session = test_data["login_sessions"]["default"]
        client = login_session.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token

        response = await test_client_auth.get(
            f"{path_prefix}/register", cookies=cookies
        )

        assert response.status_code == status.HTTP_200_OK

        html = response.text
        assert 'name="password"' not in html

        registration_session_cookie = response.cookies[
            settings.registration_session_cookie_name
        ]
        registration_session_repository = RegistrationSessionRepository(main_session)
        registration_session = await registration_session_repository.get_by_token(
            registration_session_cookie
        )
        assert registration_session is not None
        assert registration_session.flow == RegistrationSessionFlow.PASSWORD
        assert registration_session.tenant_id == tenant.id

    async def test_registration_session_from_another_tenant(
        self,
        test_client_auth: httpx.AsyncClient,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["secondary_password"]
        client = login_session.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth.get(
            f"{path_prefix}/register", cookies=cookies
        )

        assert response.status_code == status.HTTP_200_OK

        html = response.text
        assert 'name="password"' not in html

        registration_session_cookie = response.cookies[
            settings.registration_session_cookie_name
        ]
        registration_session_repository = RegistrationSessionRepository(main_session)
        new_registration_session = await registration_session_repository.get_by_token(
            registration_session_cookie
        )
        assert new_registration_session is not None
        assert new_registration_session.id != registration_session.id
        assert new_registration_session.flow == RegistrationSessionFlow.PASSWORD
        assert new_registration_session.tenant_id == tenant.id

    async def test_valid_registration_session_oauth(
        self, test_client_auth: httpx.AsyncClient, tenant_params: TenantParams
    ):
        login_session = tenant_params.login_session
        registration_session = tenant_params.registration_session_oauth

        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/register", cookies=cookies
        )

        assert response.status_code == status.HTTP_200_OK

        html = response.text
        assert 'name="password"' not in html

        assert registration_session.oauth_account is not None
        assert f'value="{registration_session.email}"' in html


@pytest.mark.asyncio
class TestPostRegister:
    async def test_invalid_login_session(
        self,
        tenant_params: TenantParams,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
    ):
        cookies = {}
        cookies[settings.login_session_cookie_name] = "INVALID_LOGIN_SESSION"

        response = await test_client_auth_csrf.post(
            f"{tenant_params.path_prefix}/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        headers = response.headers
        assert headers["X-Fief-Error"] == "invalid_session"

    async def test_disabled_registration_tenant(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
    ):
        login_session = test_data["login_sessions"]["registration_disabled"]
        client = login_session.client
        tenant = client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token

        response = await test_client_auth_csrf.post(
            f"{path_prefix}/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

        headers = response.headers
        assert headers["X-Fief-Error"] == "registration_disabled"

    @pytest.mark.parametrize("cookie", [None, "INVALID_REGISTRATION_SESSION"])
    async def test_invalid_registration_session(
        self,
        cookie: str | None,
        tenant_params: TenantParams,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
    ):
        login_session = tenant_params.login_session
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        if cookie is not None:
            cookies[settings.registration_session_cookie_name] = cookie

        response = await test_client_auth_csrf.post(
            f"{tenant_params.path_prefix}/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK

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
        login_session = tenant_params.login_session
        registration_session = tenant_params.registration_session_password
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            f"{tenant_params.path_prefix}/register",
            data={**data, "csrf_token": csrf_token},
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST

    async def test_existing_user(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        user = test_data["users"]["regular"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "newherminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK
        assert "X-Fief-Error" not in response.headers
        assert settings.session_cookie_name not in response.cookies

        send_task_mock.assert_called_once_with(
            on_existing_account_registration,
            str(user.id),
            str_match(r"/login$"),
            str_match(r"/forgot$"),
        )

        user_repository = UserRepository(main_session)
        existing_user = await user_repository.get_by_id(user.id)
        assert existing_user is not None
        assert existing_user.hashed_password == user.hashed_password

    async def test_existing_and_new_user_same_response(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
    ):
        login_session = test_data["login_sessions"]["default"]
        texts = []
        for email, registration_session in (
            ("anne@bretagne.duchy", "default_password"),
            ("louis@bretagne.duchy", "default_password_2"),
        ):
            cookies = {}
            cookies[settings.login_session_cookie_name] = login_session.token
            cookies[settings.registration_session_cookie_name] = test_data[
                "registration_sessions"
            ][registration_session].token

            response = await test_client_auth_csrf.post(
                "/register",
                data={
                    "email": email,
                    "password": "herminetincture",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )

            assert response.status_code == status.HTTP_200_OK
            assert settings.session_cookie_name not in response.cookies
            texts.append(response.text.replace(email, ""))

        assert texts[0] == texts[1]

    async def test_new_user(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_password"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "louis@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK
        assert settings.session_cookie_name not in response.cookies

        user_repository = UserRepository(main_session)
        tenant = test_data["tenants"]["default"]
        assert (
            await user_repository.get_by_email_and_tenant(
                "louis@bretagne.duchy", tenant.id
            )
            is None
        )

        registration_session_repository = RegistrationSessionRepository(main_session)
        deleted_registration_session = await registration_session_repository.get_by_id(
            registration_session.id
        )
        assert deleted_registration_session is None

        send_task_mock.assert_called_once_with(
            on_registration_confirmation_requested,
            str(tenant.id),
            "louis@bretagne.duchy",
            str_match(r"/register/confirm\?token="),
        )

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token, cookies=cookies
        )

        assert response.status_code == status.HTTP_302_FOUND
        redirect_uri = response.headers["Location"]
        assert redirect_uri.endswith("/verify-request")

        session_cookie = response.cookies[settings.session_cookie_name]
        session_token_repository = SessionTokenRepository(main_session)
        session_token = await session_token_repository.get_by_token(
            get_token_hash(session_cookie)
        )
        assert session_token is not None

        user = await user_repository.get_by_id(session_token.user_id)
        assert user is not None
        assert user.email == "louis@bretagne.duchy"
        assert user.email_verified is True
        assert password_helper.verify_and_update(
            "herminetincture", user.hashed_password
        )[0]

        login_hint_cookie = response.cookies[settings.login_hint_cookie_name]
        assert urllib.parse.unquote(login_hint_cookie) == "louis@bretagne.duchy"

        send_task_mock.assert_any_call(on_after_register, str(session_token.user_id))

    async def test_too_many_requests(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["default"]
        for registration_session in (
            "default_password",
            "default_password_2",
            "default_password_3",
        ):
            cookies = {}
            cookies[settings.login_session_cookie_name] = login_session.token
            cookies[settings.registration_session_cookie_name] = test_data[
                "registration_sessions"
            ][registration_session].token

            response = await test_client_auth_csrf.post(
                "/register",
                data={
                    "email": "louis@bretagne.duchy",
                    "password": "herminetincture",
                    "csrf_token": csrf_token,
                },
                cookies=cookies,
            )
            assert response.status_code == status.HTTP_200_OK

        assert send_task_mock.call_count == 2


@pytest.mark.asyncio
class TestGetRegisterConfirm:
    async def test_invalid_token(
        self, tenant_params: TenantParams, test_client_auth: httpx.AsyncClient
    ):
        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/register/confirm",
            params={"token": "INVALID_TOKEN"},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers["X-Fief-Error"] == "invalid_token"

    async def test_expired_token(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ):
        await request_registration(
            test_client_auth_csrf, csrf_token, test_data, "louis@bretagne.duchy"
        )
        monkeypatch.setattr(settings, "registration_confirmation_lifetime_seconds", -1)
        confirm_url = send_task_mock.call_args.args[-1]

        response = await test_client_auth_csrf.get(_get_path(confirm_url))

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers["X-Fief-Error"] == "invalid_token"

    async def test_other_tenant(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        await request_registration(
            test_client_auth_csrf, csrf_token, test_data, "louis@bretagne.duchy"
        )
        confirm_url = furl(send_task_mock.call_args.args[-1])
        token = confirm_url.args["token"]

        response = await test_client_auth_csrf.get(
            f"/{test_data['tenants']['secondary'].slug}/register/confirm",
            params={"token": token},
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers["X-Fief-Error"] == "invalid_token"

    async def test_already_used(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        await request_registration(
            test_client_auth_csrf, csrf_token, test_data, "louis@bretagne.duchy"
        )
        confirm_url = send_task_mock.call_args.args[-1]

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token
        )
        assert response.status_code == status.HTTP_302_FOUND

        response = await test_client_auth_csrf.post(
            str(furl(confirm_url).path),
            data={
                "token": furl(confirm_url).args["token"],
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
        )
        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers["X-Fief-Error"] == "invalid_token"

    async def test_disabled_registration_tenant(
        self, test_client_auth: httpx.AsyncClient, test_data: TestData
    ):
        login_session = test_data["login_sessions"]["registration_disabled"]
        tenant = login_session.client.tenant
        path_prefix = tenant.slug if not tenant.default else ""

        response = await test_client_auth.get(
            f"{path_prefix}/register/confirm", params={"token": "TOKEN"}
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert response.headers["X-Fief-Error"] == "registration_disabled"

    @pytest.mark.parametrize(
        "password",
        [
            pytest.param("", id="Missing password"),
            pytest.param("h", id="Too short password"),
            pytest.param("h" * 512, id="Too long password"),
        ],
    )
    async def test_invalid_password(
        self,
        password: str,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        await request_registration(
            test_client_auth_csrf, csrf_token, test_data, "louis@bretagne.duchy"
        )

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token, password=password
        )

        assert response.status_code == status.HTTP_400_BAD_REQUEST
        assert settings.session_cookie_name not in response.cookies

    async def test_open_link_creates_nothing(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        await request_registration(
            test_client_auth_csrf, csrf_token, test_data, "louis@bretagne.duchy"
        )
        confirm_url = send_task_mock.call_args.args[-1]

        response = await test_client_auth_csrf.get(_get_path(confirm_url))

        assert response.status_code == status.HTTP_200_OK
        assert settings.session_cookie_name not in response.cookies
        user_repository = UserRepository(main_session)
        assert (
            await user_repository.get_by_email_and_tenant(
                "louis@bretagne.duchy", test_data["tenants"]["default"].id
            )
            is None
        )

    async def test_password_chosen_on_confirmation(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        await request_registration(
            test_client_auth_csrf, csrf_token, test_data, "louis@bretagne.duchy"
        )

        response = await confirm_registration(
            test_client_auth_csrf,
            send_task_mock,
            csrf_token,
            password="mynewherminetincture",
        )
        assert response.status_code == status.HTTP_302_FOUND

        user_repository = UserRepository(main_session)
        user = await user_repository.get_by_email_and_tenant(
            "louis@bretagne.duchy", test_data["tenants"]["default"].id
        )
        assert user is not None
        assert password_helper.verify_and_update(
            "mynewherminetincture", user.hashed_password
        )[0]

    @pytest.mark.parametrize(
        "has_login_session,redirect_path",
        [
            (True, "/verify-request"),
            (False, "/verify-request"),
        ],
    )
    async def test_without_registration_cookies(
        self,
        has_login_session: bool,
        redirect_path: str,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        await request_registration(
            test_client_auth_csrf, csrf_token, test_data, "louis@bretagne.duchy"
        )

        cookies = {}
        if has_login_session:
            login_session = test_data["login_sessions"]["default"]
            cookies[settings.login_session_cookie_name] = login_session.token
        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token, cookies=cookies
        )

        assert response.status_code == status.HTTP_302_FOUND
        assert response.headers["Location"].endswith(redirect_path)
        assert settings.session_cookie_name in response.cookies


@pytest.mark.asyncio
class TestPostRegisterFields:
    async def test_no_email_conflict_on_another_tenant(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["secondary"]
        registration_session = test_data["registration_sessions"]["secondary_password"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            f"/{test_data['tenants']['secondary'].slug}/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token
        )
        assert response.status_code == status.HTTP_302_FOUND

    async def test_registration_fields_set(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["secondary"]
        registration_session = test_data["registration_sessions"]["secondary_password"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            f"/{test_data['tenants']['secondary'].slug}/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "fields.given_name": "Anne",
                "fields.address.line1": "4 place Marc Elder",
                "fields.address.postal_code": "44000",
                "fields.address.city": "Nantes",
                "fields.address.country": "FR",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token
        )
        assert response.status_code == status.HTTP_302_FOUND

        session_cookie = response.cookies[settings.session_cookie_name]
        session_token_repository = SessionTokenRepository(main_session)
        session_token = await session_token_repository.get_by_token(
            get_token_hash(session_cookie)
        )
        assert session_token is not None

        user_repository = UserRepository(main_session)
        user = await user_repository.get_by_id(session_token.user_id)
        assert user is not None
        assert user.fields == {
            "given_name": "Anne",
            "address": {
                "line1": "4 place Marc Elder",
                "line2": None,
                "postal_code": "44000",
                "city": "Nantes",
                "state": None,
                "country": "FR",
            },
            "onboarding_done": False,  # Default value
        }

    @pytest.mark.parametrize(
        "data,status_code",
        [
            ({}, status.HTTP_400_BAD_REQUEST),
            ({"fields.terms": ""}, status.HTTP_400_BAD_REQUEST),
            ({"fields.terms": "on"}, status.HTTP_200_OK),
        ],
    )
    async def test_required_boolean_field(
        self,
        data: dict[str, Any],
        status_code: int,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        field = UserField(
            name="Accept terms",
            slug="terms",
            type=UserFieldType.BOOLEAN,
            configuration={
                "choices": None,
                "default": False,
                "at_registration": True,
                "at_update": False,
                "required": True,
            },
        )
        main_session.add(field)
        await main_session.commit()

        login_session = test_data["login_sessions"]["secondary"]
        registration_session = test_data["registration_sessions"]["secondary_password"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            f"/{test_data['tenants']['secondary'].slug}/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "csrf_token": csrf_token,
                **data,
            },
            cookies=cookies,
        )

        assert response.status_code == status_code

    async def test_registration_fields_empty_string(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["secondary"]
        registration_session = test_data["registration_sessions"]["secondary_password"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            f"/{test_data['tenants']['secondary'].slug}/register",
            data={
                "email": "anne@bretagne.duchy",
                "password": "herminetincture",
                "fields.given_name": "",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token
        )
        assert response.status_code == status.HTTP_302_FOUND

        session_cookie = response.cookies[settings.session_cookie_name]
        session_token_repository = SessionTokenRepository(main_session)
        session_token = await session_token_repository.get_by_token(
            get_token_hash(session_cookie)
        )
        assert session_token is not None

        user_repository = UserRepository(main_session)
        user = await user_repository.get_by_id(session_token.user_id)
        assert user is not None
        assert user.fields == {
            "onboarding_done": False,  # Default value
        }


@pytest.mark.asyncio
class TestPostRegisterOAuth:
    async def test_new_user_oauth(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_oauth"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "louis@bretagne.duchy",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_302_FOUND

        redirect_uri = response.headers["Location"]
        assert redirect_uri.endswith("/verify-request")

        session_cookie = response.cookies[settings.session_cookie_name]
        session_token_repository = SessionTokenRepository(main_session)
        session_token = await session_token_repository.get_by_token(
            get_token_hash(session_cookie)
        )
        assert session_token is not None

        oauth_account_repository = OAuthAccountRepository(main_session)
        assert registration_session.oauth_account_id is not None
        oauth_account = await oauth_account_repository.get_by_id(
            registration_session.oauth_account_id
        )
        assert oauth_account is not None
        assert oauth_account.user_id == session_token.user_id

        login_hint_cookie = response.cookies[settings.login_hint_cookie_name]
        assert login_hint_cookie == str(oauth_account.oauth_provider_id)

        registration_session_repository = RegistrationSessionRepository(main_session)
        deleted_registration_session = await registration_session_repository.get_by_id(
            registration_session.id
        )
        assert deleted_registration_session is None

        send_task_mock.assert_called_with(on_after_register, str(session_token.user_id))

    async def test_new_user_oauth_override_default_email(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_oauth"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "louis+fief@bretagne.duchy",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK
        assert settings.session_cookie_name not in response.cookies

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token, cookies=cookies
        )
        assert response.status_code == status.HTTP_302_FOUND

        session_cookie = response.cookies[settings.session_cookie_name]
        session_token_repository = SessionTokenRepository(main_session)
        session_token = await session_token_repository.get_by_token(
            get_token_hash(session_cookie)
        )
        assert session_token is not None

        user_repository = UserRepository(main_session)
        user = await user_repository.get_by_id(session_token.user_id)
        assert user is not None
        assert user.email == "louis+fief@bretagne.duchy"
        assert user.email_verified is True

        oauth_account_repository = OAuthAccountRepository(main_session)
        assert registration_session.oauth_account_id is not None
        oauth_account = await oauth_account_repository.get_by_id(
            registration_session.oauth_account_id
        )
        assert oauth_account is not None
        assert oauth_account.user_id == user.id

    async def test_new_user_oauth_override_default_email_other_browser(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        main_session: AsyncSession,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_oauth"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "louis+fief@bretagne.duchy",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )
        assert response.status_code == status.HTTP_200_OK

        response = await confirm_registration(
            test_client_auth_csrf, send_task_mock, csrf_token
        )
        assert response.status_code == status.HTTP_302_FOUND

        oauth_account_repository = OAuthAccountRepository(main_session)
        assert registration_session.oauth_account_id is not None
        oauth_account = await oauth_account_repository.get_by_id(
            registration_session.oauth_account_id
        )
        assert oauth_account is not None
        assert oauth_account.user_id is None

    async def test_existing_user_oauth_override_default_email(
        self,
        test_client_auth_csrf: httpx.AsyncClient,
        csrf_token: str,
        test_data: TestData,
        send_task_mock: MagicMock,
    ):
        login_session = test_data["login_sessions"]["default"]
        registration_session = test_data["registration_sessions"]["default_oauth"]
        cookies = {}
        cookies[settings.login_session_cookie_name] = login_session.token
        cookies[settings.registration_session_cookie_name] = registration_session.token

        response = await test_client_auth_csrf.post(
            "/register",
            data={
                "email": "anne@bretagne.duchy",
                "csrf_token": csrf_token,
            },
            cookies=cookies,
        )

        assert response.status_code == status.HTTP_200_OK
        assert "X-Fief-Error" not in response.headers
        assert send_task_mock.call_args.args[0] == on_existing_account_registration


def _get_path(url: str) -> str:
    parsed_url = furl(url)
    return f"{parsed_url.path}?{parsed_url.query}"


async def request_registration(
    test_client: httpx.AsyncClient, csrf_token: str, test_data: TestData, email: str
) -> httpx.Response:
    login_session = test_data["login_sessions"]["default"]
    registration_session = test_data["registration_sessions"]["default_password"]
    cookies = {}
    cookies[settings.login_session_cookie_name] = login_session.token
    cookies[settings.registration_session_cookie_name] = registration_session.token

    response = await test_client.post(
        "/register",
        data={"email": email, "password": "herminetincture", "csrf_token": csrf_token},
        cookies=cookies,
    )
    assert response.status_code == status.HTTP_200_OK
    return response


async def confirm_registration(
    test_client: httpx.AsyncClient,
    send_task_mock: MagicMock,
    csrf_token: str,
    *,
    cookies: dict[str, str] | None = None,
    password: str = "herminetincture",
) -> httpx.Response:
    assert send_task_mock.call_args.args[0] == on_registration_confirmation_requested
    confirm_url = send_task_mock.call_args.args[-1]

    response = await test_client.get(_get_path(confirm_url), cookies=cookies)
    assert response.status_code == status.HTTP_200_OK

    return await test_client.post(
        str(furl(confirm_url).path),
        data={
            "token": furl(confirm_url).args["token"],
            "password": password,
            "csrf_token": csrf_token,
        },
        cookies=cookies,
    )
