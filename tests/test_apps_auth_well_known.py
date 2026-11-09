import httpx
import pytest
from fastapi import status
from jwcrypto import jwk
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from fief.apps import auth_app
from fief.middlewares.x_forwarded_host import XForwardedHostMiddleware
from fief.services.response_type import ALLOWED_RESPONSE_TYPES
from fief.settings import settings
from tests.types import TenantParams

FIEF_DOMAIN = "auth.example.com"
ENDPOINT_PATHS = {
    "authorization_endpoint": "/authorize",
    "token_endpoint": "/api/token",
    "userinfo_endpoint": "/api/userinfo",
    "jwks_uri": "/.well-known/jwks.json",
    "registration_endpoint": "/register",
}


def assert_endpoints(configuration: dict[str, str], base_url: str) -> None:
    for key, path in ENDPOINT_PATHS.items():
        assert configuration[key] == f"{base_url}{path}"


@pytest.fixture(autouse=True)
def fief_domain(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(settings, "fief_domain", FIEF_DOMAIN)


@pytest.mark.asyncio
class TestWellKnownOpenIDConfiguration:
    @pytest.mark.parametrize("x_forwarded_host", [None, "evil.example"])
    async def test_return_configuration(
        self,
        x_forwarded_host: str | None,
        tenant_params: TenantParams,
        test_client_auth: httpx.AsyncClient,
    ):
        headers = {}
        if x_forwarded_host is not None:
            headers["X-Forwarded-Host"] = x_forwarded_host

        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/.well-known/openid-configuration",
            headers=headers,
        )

        assert response.status_code == status.HTTP_200_OK

        json = response.json()

        assert json["issuer"] == tenant_params.tenant.get_host()
        for key in json:
            assert json[key] is not None

        assert json["response_types_supported"] == ALLOWED_RESPONSE_TYPES
        assert json["token_endpoint_auth_methods_supported"] == [
            "client_secret_basic",
            "client_secret_post",
        ]
        assert json["code_challenge_methods_supported"] == ["plain", "S256"]

        assert_endpoints(json, f"http://{FIEF_DOMAIN}{tenant_params.path_prefix}")

    @pytest.mark.parametrize(
        "headers",
        [
            {"Host": "evil.example"},
            {"Host": "evil.example:8443"},
            {"Host": "evil.example/path?"},
            {"X-Forwarded-Host": "evil.example", "Host": "evil.example"},
        ],
    )
    async def test_host_comes_from_settings(
        self,
        headers: dict[str, str],
        tenant_params: TenantParams,
        test_client_auth: httpx.AsyncClient,
    ):
        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/.well-known/openid-configuration",
            headers=headers,
        )

        assert response.status_code == status.HTTP_200_OK
        assert_endpoints(
            response.json(), f"http://{FIEF_DOMAIN}{tenant_params.path_prefix}"
        )

    async def test_domain_with_port(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tenant_params: TenantParams,
        test_client_auth: httpx.AsyncClient,
    ):
        monkeypatch.setattr(settings, "fief_domain", "localhost:8000")

        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/.well-known/openid-configuration"
        )

        assert response.status_code == status.HTTP_200_OK
        assert_endpoints(
            response.json(), f"http://localhost:8000{tenant_params.path_prefix}"
        )

    async def test_scheme_comes_from_request(
        self,
        tenant_params: TenantParams,
        test_client_auth: httpx.AsyncClient,
    ):
        response = await test_client_auth.get(
            f"https://api.fief.dev{tenant_params.path_prefix}/.well-known/openid-configuration"
        )

        assert response.status_code == status.HTTP_200_OK
        assert_endpoints(
            response.json(), f"https://{FIEF_DOMAIN}{tenant_params.path_prefix}"
        )

    async def test_root_path_is_kept(
        self,
        tenant_params: TenantParams,
        test_client_auth: httpx.AsyncClient,
    ):
        transport = httpx.ASGITransport(app=auth_app, root_path="/auth")
        async with httpx.AsyncClient(
            transport=transport, base_url="http://api.fief.dev"
        ) as client:
            response = await client.get(
                f"/auth{tenant_params.path_prefix}/.well-known/openid-configuration"
            )

        assert response.status_code == status.HTTP_200_OK
        assert_endpoints(
            response.json(), f"http://{FIEF_DOMAIN}/auth{tenant_params.path_prefix}"
        )

    @pytest.mark.parametrize(
        "headers,scheme",
        [
            ({"X-Forwarded-Host": "evil.example"}, "http"),
            ({"Host": "evil.example"}, "http"),
            ({"X-Forwarded-Proto": "https"}, "https"),
            (
                {"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "https"},
                "https",
            ),
            ({"X-Forwarded-Proto": "javascript"}, "http"),
            ({"X-Forwarded-Proto": "https://evil.example/"}, "http"),
            ({"X-Forwarded-Proto": "ws"}, "http"),
        ],
    )
    async def test_all_clients_trusted(
        self,
        headers: dict[str, str],
        scheme: str,
        tenant_params: TenantParams,
        test_client_auth: httpx.AsyncClient,
    ):
        app = ProxyHeadersMiddleware(
            XForwardedHostMiddleware(auth_app, trusted_hosts="*"), trusted_hosts="*"
        )
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://api.fief.dev"
        ) as client:
            response = await client.get(
                f"{tenant_params.path_prefix}/.well-known/openid-configuration",
                headers=headers,
            )

        assert response.status_code == status.HTTP_200_OK
        assert_endpoints(
            response.json(), f"{scheme}://{FIEF_DOMAIN}{tenant_params.path_prefix}"
        )


@pytest.mark.asyncio
class TestWellKnownJWKS:
    async def test_return_public_keys(
        self,
        tenant_params: TenantParams,
        test_client_auth: httpx.AsyncClient,
    ):
        response = await test_client_auth.get(
            f"{tenant_params.path_prefix}/.well-known/jwks.json"
        )

        assert response.status_code == status.HTTP_200_OK

        keyset = jwk.JWKSet.from_json(response.text)

        key: jwk.JWK | None = keyset.get_key(tenant_params.tenant.get_sign_jwk()["kid"])
        assert key is not None
        assert key.has_private is False
