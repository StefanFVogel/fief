import httpx
import pytest
from fastapi import status
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from fief.apps import auth_app
from fief.middlewares.x_forwarded_host import XForwardedHostMiddleware
from fief.settings import settings
from fief.settings_class import Settings
from tests.types import TenantParams

PROXY_NETWORK = "10.244.0.0/16"
PROXY_ADDRESS = "10.244.0.5"


async def host(request: Request) -> PlainTextResponse:
    return PlainTextResponse(request.headers["host"])


host_app = Starlette(routes=[Route("/", host)])


async def get_host(trusted_hosts: str, client_host: str) -> str:
    app = XForwardedHostMiddleware(host_app, trusted_hosts=trusted_hosts)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(client_host, 123)),
        base_url="http://auth.example.com",
    ) as client:
        response = await client.get("/", headers={"X-Forwarded-Host": "evil.example"})
    return response.text


def test_disabled_by_default():
    assert Settings.model_fields["x_forwarded_host_enabled"].default is False


@pytest.mark.asyncio
class TestXForwardedHostMiddleware:
    @pytest.mark.parametrize(
        "trusted_hosts,client_host",
        [
            ("*", "198.51.100.9"),
            (PROXY_NETWORK, PROXY_ADDRESS),
            (PROXY_ADDRESS, PROXY_ADDRESS),
        ],
    )
    async def test_ignored_when_disabled(self, trusted_hosts: str, client_host: str):
        assert await get_host(trusted_hosts, client_host) == "auth.example.com"

    @pytest.mark.parametrize(
        "trusted_hosts,client_host",
        [
            ("*", "198.51.100.9"),
            (PROXY_NETWORK, PROXY_ADDRESS),
            (PROXY_ADDRESS, PROXY_ADDRESS),
            ("127.0.0.1, 10.244.0.5", PROXY_ADDRESS),
            ("::1, fd00::/8", "fd00::5"),
        ],
    )
    async def test_trusted_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch, trusted_hosts: str, client_host: str
    ):
        monkeypatch.setattr(settings, "x_forwarded_host_enabled", True)

        assert await get_host(trusted_hosts, client_host) == "evil.example"

    @pytest.mark.parametrize(
        "trusted_hosts,client_host",
        [
            (PROXY_NETWORK, "198.51.100.9"),
            (PROXY_ADDRESS, "10.244.0.6"),
            ("127.0.0.1", PROXY_ADDRESS),
            ("not-an-ip/16", PROXY_ADDRESS),
        ],
    )
    async def test_untrusted_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch, trusted_hosts: str, client_host: str
    ):
        monkeypatch.setattr(settings, "x_forwarded_host_enabled", True)

        assert await get_host(trusted_hosts, client_host) == "auth.example.com"


async def get_login_redirect(
    trusted_hosts: str, headers: dict[str, str], tenant_params: TenantParams
) -> httpx.Response:
    app = ProxyHeadersMiddleware(
        XForwardedHostMiddleware(auth_app, trusted_hosts=trusted_hosts),
        trusted_hosts=trusted_hosts,
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app, client=(PROXY_ADDRESS, 123)),
        base_url="http://auth.example.com",
    ) as client:
        response = await client.get(
            f"{tenant_params.path_prefix}/",
            headers={**headers, "X-Forwarded-Host": "evil.example"},
        )
    assert response.status_code == status.HTTP_307_TEMPORARY_REDIRECT
    return response


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "trusted_hosts,headers",
    [
        ("*", {"X-Forwarded-For": "203.0.113.7, 198.51.100.9"}),
        (PROXY_NETWORK, {"X-Forwarded-For": "203.0.113.7, 198.51.100.9"}),
        (PROXY_NETWORK, {}),
    ],
)
async def test_foreign_host_not_in_links(
    trusted_hosts: str,
    headers: dict[str, str],
    tenant_params: TenantParams,
    test_client_auth: httpx.AsyncClient,
):
    response = await get_login_redirect(trusted_hosts, headers, tenant_params)

    assert response.headers["location"].startswith("http://auth.example.com/")
    assert "evil.example" not in response.text


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "headers,host",
    [
        ({"X-Forwarded-For": "203.0.113.7, 198.51.100.9"}, "auth.example.com"),
        ({"X-Forwarded-For": "10.244.3.3"}, "evil.example"),
        ({}, "evil.example"),
    ],
)
async def test_enabled_trusts_client_address_resolved_by_uvicorn(
    headers: dict[str, str],
    host: str,
    monkeypatch: pytest.MonkeyPatch,
    tenant_params: TenantParams,
    test_client_auth: httpx.AsyncClient,
):
    monkeypatch.setattr(settings, "x_forwarded_host_enabled", True)

    response = await get_login_redirect(PROXY_NETWORK, headers, tenant_params)

    assert response.headers["location"].startswith(f"http://{host}/")
