import json
from collections.abc import Callable

import httpx
import pytest
from bs4 import BeautifulSoup
from fastapi import status

from fief.settings import settings
from tests.data import TestData

UNSAFE_REQUESTS: list[tuple[str, Callable[[TestData], str]]] = [
    (
        "POST",
        lambda d: f"/clients/{d['clients']['default_tenant'].id}/encryption-key",
    ),
    ("POST", lambda d: f"/webhooks/{d['webhooks']['all'].id}/secret"),
    (
        "POST",
        lambda d: f"/customization/themes/{d['themes']['custom'].id}/default",
    ),
    ("POST", lambda d: f"/tenants/{d['tenants']['default'].id}/email/verify"),
    ("POST", lambda d: f"/users/{d['users']['regular'].id}/verify-request"),
    (
        "DELETE",
        lambda d: (
            f"/users/{d['users']['regular'].id}"
            f"/roles/{d['roles']['castles_visitor'].id}"
        ),
    ),
    (
        "DELETE",
        lambda d: (
            f"/users/{d['users']['regular'].id}"
            f"/permissions/{d['permissions']['castles:delete'].id}"
        ),
    ),
    ("DELETE", lambda d: f"/webhooks/{d['webhooks']['all'].id}/delete"),
    ("DELETE", lambda d: f"/clients/{d['clients']['default_tenant'].id}/delete"),
    ("POST", lambda d: "/access-control/permissions/"),
]

UNSAFE_REQUESTS_IDS = [
    "clients:encryption_key",
    "webhooks:secret",
    "themes:default",
    "tenants:email_domain_verify",
    "users:verify_email_request",
    "users:delete_role",
    "users:delete_permission",
    "webhooks:delete",
    "clients:delete",
    "permissions:list",
]


@pytest.mark.asyncio
@pytest.mark.authenticated_admin(mode="session")
class TestDashboardCSRF:
    @pytest.mark.parametrize("method,path", UNSAFE_REQUESTS, ids=UNSAFE_REQUESTS_IDS)
    async def test_missing_header(
        self,
        method: str,
        path: Callable[[TestData], str],
        test_client_dashboard: httpx.AsyncClient,
        test_data: TestData,
    ):
        del test_client_dashboard.headers["X-CSRFToken"]
        response = await test_client_dashboard.request(method, path(test_data))

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.parametrize("method,path", UNSAFE_REQUESTS, ids=UNSAFE_REQUESTS_IDS)
    async def test_invalid_header(
        self,
        method: str,
        path: Callable[[TestData], str],
        test_client_dashboard: httpx.AsyncClient,
        test_data: TestData,
    ):
        test_client_dashboard.headers["X-CSRFToken"] = "INVALID_TOKEN"
        response = await test_client_dashboard.request(method, path(test_data))

        assert response.status_code == status.HTTP_403_FORBIDDEN

    @pytest.mark.parametrize("method,path", UNSAFE_REQUESTS, ids=UNSAFE_REQUESTS_IDS)
    async def test_missing_cookie(
        self,
        method: str,
        path: Callable[[TestData], str],
        test_client_dashboard: httpx.AsyncClient,
        test_data: TestData,
    ):
        test_client_dashboard.cookies.delete(settings.csrf_cookie_name)
        response = await test_client_dashboard.request(method, path(test_data))

        assert response.status_code == status.HTTP_403_FORBIDDEN

    async def test_valid_header(
        self, test_client_dashboard: httpx.AsyncClient, test_data: TestData
    ):
        webhook = test_data["webhooks"]["all"]
        response = await test_client_dashboard.post(f"/webhooks/{webhook.id}/secret")

        assert response.status_code == status.HTTP_200_OK

    @pytest.mark.htmx(target="modal")
    async def test_valid_form_field(
        self, test_client_dashboard: httpx.AsyncClient, csrf_token: str
    ):
        del test_client_dashboard.headers["X-CSRFToken"]
        response = await test_client_dashboard.post(
            "/access-control/permissions/",
            data={
                "name": "New permission",
                "codename": "new_permission",
                "csrf_token": csrf_token,
            },
        )

        assert response.status_code == status.HTTP_201_CREATED

    async def test_check_disabled(
        self,
        test_client_dashboard: httpx.AsyncClient,
        test_data: TestData,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(settings, "csrf_check_enabled", False)
        del test_client_dashboard.headers["X-CSRFToken"]
        webhook = test_data["webhooks"]["all"]
        response = await test_client_dashboard.post(f"/webhooks/{webhook.id}/secret")

        assert response.status_code == status.HTTP_200_OK

    async def test_token_in_htmx_headers(
        self, test_client_dashboard: httpx.AsyncClient, csrf_token: str
    ):
        test_client_dashboard.headers.pop("HX-Request", None)
        response = await test_client_dashboard.get("/")

        assert response.status_code == status.HTTP_200_OK

        html = BeautifulSoup(response.text, features="html.parser")
        hx_headers = json.loads(html.find("body")["hx-headers"])
        assert hx_headers["X-CSRFToken"] == csrf_token

    async def test_token_generated_in_htmx_headers(
        self, test_client_dashboard: httpx.AsyncClient
    ):
        test_client_dashboard.headers.pop("HX-Request", None)
        test_client_dashboard.cookies.delete(settings.csrf_cookie_name)
        response = await test_client_dashboard.get("/")

        assert response.status_code == status.HTTP_200_OK

        html = BeautifulSoup(response.text, features="html.parser")
        hx_headers = json.loads(html.find("body")["hx-headers"])
        assert hx_headers["X-CSRFToken"] == response.cookies[settings.csrf_cookie_name]
