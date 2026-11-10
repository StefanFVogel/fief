import pytest

from fief.db import AsyncEngine, AsyncSession
from fief.services.initializer import Initializer
from fief.settings import settings
from fief.settings_class import Environment
from tests.data import TestData


def get_initializer(
    main_engine: AsyncEngine, environment: Environment, domain: str, client_id: str
) -> Initializer:
    return Initializer(
        main_engine,
        settings.model_copy(
            update={
                "environment": environment,
                "fief_domain": domain,
                "fief_client_id": client_id,
            }
        ),
    )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "environment,domain,expected_schemes",
    [
        (Environment.DEVELOPMENT, "fief.bretagne.duchy", {"http", "https"}),
        (Environment.STAGING, "fief.bretagne.duchy", {"http", "https"}),
        (Environment.PRODUCTION, "fief.bretagne.duchy", {"https"}),
        (Environment.PRODUCTION, "localhost:8000", {"http", "https"}),
    ],
)
async def test_init_default_client_new(
    environment: Environment,
    domain: str,
    expected_schemes: set[str],
    main_engine: AsyncEngine,
    main_session: AsyncSession,
    test_data: TestData,
):
    initializer = get_initializer(
        main_engine, environment, domain, "INITIALIZER_CLIENT_ID"
    )

    client = await initializer._init_default_client(
        main_session, test_data["tenants"]["default"]
    )

    assert {uri.split(":")[0] for uri in client.redirect_uris} == expected_schemes
    assert f"https://{domain}/admin/auth/callback" in client.redirect_uris


@pytest.mark.asyncio
async def test_init_default_client_existing_production(
    main_engine: AsyncEngine,
    main_session: AsyncSession,
    test_data: TestData,
):
    existing_client = test_data["clients"]["default_tenant"]
    existing_redirect_uris = set(existing_client.redirect_uris)
    initializer = get_initializer(
        main_engine,
        Environment.PRODUCTION,
        "fief.bretagne.duchy",
        existing_client.client_id,
    )

    client = await initializer._init_default_client(
        main_session, test_data["tenants"]["default"]
    )

    assert set(client.redirect_uris) == existing_redirect_uris | {
        "https://fief.bretagne.duchy/admin/auth/callback",
        "https://fief.bretagne.duchy/docs/oauth2-redirect",
    }
