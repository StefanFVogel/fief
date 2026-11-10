import json
import uuid

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.config import Config
from cryptography.fernet import Fernet
from jwcrypto import jwk

from fief.db.engine import create_engine
from fief.db.types import get_driver
from fief.models.base import TABLE_PREFIX
from fief.models.generics import GUID
from fief.paths import ALEMBIC_CONFIG_FILE
from fief.settings import settings
from tests.types import GetTestDatabase

PREVIOUS_REVISION = "f0462e660029"
ENCRYPT_SECRETS_REVISION = "c3d1e9a4b7f2"
OAUTH_ACCOUNT_TENANT_REVISION = "4eef465ce7bd"

SIGN_JWK = jwk.JWK.generate(kty="RSA", size=1024).export()
CLIENT_SECRET = "PLAINTEXT_CLIENT_SECRET"
WEBHOOK_SECRET = "PLAINTEXT_WEBHOOK_SECRET"

tenants_table = sa.table(
    f"{TABLE_PREFIX}tenants",
    sa.column("id", GUID),
    sa.column("name", sa.String),
    sa.column("slug", sa.String),
    sa.column("default", sa.Boolean),
    sa.column("sign_jwk", sa.Text),
    sa.column("registration_allowed", sa.Boolean),
)
clients_table = sa.table(
    f"{TABLE_PREFIX}clients",
    sa.column("id", GUID),
    sa.column("name", sa.String),
    sa.column("first_party", sa.Boolean),
    sa.column("client_id", sa.String),
    sa.column("client_secret", sa.Text),
    sa.column("redirect_uris", sa.JSON),
    sa.column("authorization_code_lifetime_seconds", sa.Integer),
    sa.column("access_id_token_lifetime_seconds", sa.Integer),
    sa.column("refresh_token_lifetime_seconds", sa.Integer),
    sa.column("tenant_id", GUID),
)
webhooks_table = sa.table(
    f"{TABLE_PREFIX}webhooks",
    sa.column("id", GUID),
    sa.column("url", sa.String),
    sa.column("secret", sa.Text),
    sa.column("events", sa.JSON),
)

oauth_providers_table = sa.table(
    f"{TABLE_PREFIX}oauth_providers",
    sa.column("id", GUID),
    sa.column("provider", sa.String),
    sa.column("client_id", sa.Text),
    sa.column("client_secret", sa.Text),
    sa.column("scopes", sa.JSON),
)
oauth_accounts_table = sa.table(
    f"{TABLE_PREFIX}oauth_accounts",
    sa.column("id", GUID),
    sa.column("access_token", sa.Text),
    sa.column("account_id", sa.String),
    sa.column("oauth_provider_id", GUID),
    sa.column("tenant_id", GUID),
)


def _run_alembic(connection: sa.Connection, func, revision: str) -> None:
    config = Config(ALEMBIC_CONFIG_FILE)
    config.attributes["connection"] = connection
    config.attributes["configure_logger"] = False
    func(config, revision)


def _get_stored_values(connection: sa.Connection) -> tuple[str, str, str]:
    return (
        connection.execute(sa.select(tenants_table.c.sign_jwk)).scalar_one(),
        connection.execute(sa.select(clients_table.c.client_secret)).scalar_one(),
        connection.execute(sa.select(webhooks_table.c.secret)).scalar_one(),
    )


@pytest.mark.asyncio
async def test_encrypt_secrets_migration(get_test_database: GetTestDatabase):
    async with get_test_database(name="fief-test-migration") as (
        (url, connect_args),
        database_type,
    ):
        url = url.set(drivername=get_driver(database_type, asyncio=True))
        engine = create_engine((url, connect_args))

        def _insert_plaintext_rows(connection: sa.Connection) -> None:
            _run_alembic(connection, command.upgrade, PREVIOUS_REVISION)
            tenant_id = uuid.uuid4()
            connection.execute(
                tenants_table.insert().values(
                    id=tenant_id,
                    name="Default",
                    slug="default",
                    default=True,
                    sign_jwk=SIGN_JWK,
                    registration_allowed=True,
                )
            )
            connection.execute(
                clients_table.insert().values(
                    id=uuid.uuid4(),
                    name="Default",
                    first_party=True,
                    client_id="CLIENT_ID",
                    client_secret=CLIENT_SECRET,
                    redirect_uris=[],
                    authorization_code_lifetime_seconds=600,
                    access_id_token_lifetime_seconds=3600,
                    refresh_token_lifetime_seconds=3600,
                    tenant_id=tenant_id,
                )
            )
            connection.execute(
                webhooks_table.insert().values(
                    id=uuid.uuid4(),
                    url="https://internal.bretagne.duchy/webhook",
                    secret=WEBHOOK_SECRET,
                    events=[],
                )
            )

        def _upgrade(connection: sa.Connection) -> tuple[str, str, str]:
            _run_alembic(connection, command.upgrade, ENCRYPT_SECRETS_REVISION)
            return _get_stored_values(connection)

        def _downgrade(connection: sa.Connection) -> tuple[str, str, str]:
            _run_alembic(connection, command.downgrade, PREVIOUS_REVISION)
            return _get_stored_values(connection)

        try:
            async with engine.begin() as connection:
                await connection.run_sync(_insert_plaintext_rows)
            async with engine.begin() as connection:
                encrypted_values = await connection.run_sync(_upgrade)
            async with engine.begin() as connection:
                decrypted_values = await connection.run_sync(_downgrade)
        finally:
            await engine.dispose()

        fernet = Fernet(settings.encryption_key)
        sign_jwk, client_secret, webhook_secret = encrypted_values
        assert SIGN_JWK not in sign_jwk
        assert fernet.decrypt(sign_jwk.encode()).decode() == SIGN_JWK
        assert CLIENT_SECRET not in client_secret
        assert fernet.decrypt(client_secret.encode()).decode() == CLIENT_SECRET
        assert WEBHOOK_SECRET not in webhook_secret
        assert fernet.decrypt(webhook_secret.encode()).decode() == WEBHOOK_SECRET

        assert decrypted_values == (SIGN_JWK, CLIENT_SECRET, WEBHOOK_SECRET)
        assert json.loads(decrypted_values[0])["kty"] == "RSA"


@pytest.mark.asyncio
async def test_oauth_account_tenant_unique_constraint_migration(
    get_test_database: GetTestDatabase,
):
    async with get_test_database(name="fief-test-migration-oauth-account") as (
        (url, connect_args),
        database_type,
    ):
        url = url.set(drivername=get_driver(database_type, asyncio=True))
        engine = create_engine((url, connect_args))

        oauth_provider_id = uuid.uuid4()
        tenant_ids = [uuid.uuid4(), uuid.uuid4()]

        def _insert_oauth_account(connection: sa.Connection, tenant_id: uuid.UUID):
            connection.execute(
                oauth_accounts_table.insert().values(
                    id=uuid.uuid4(),
                    access_token="ACCESS_TOKEN",
                    account_id="ACCOUNT_ID",
                    oauth_provider_id=oauth_provider_id,
                    tenant_id=tenant_id,
                )
            )

        def _upgrade(connection: sa.Connection) -> None:
            _run_alembic(connection, command.upgrade, ENCRYPT_SECRETS_REVISION)
            for index, tenant_id in enumerate(tenant_ids):
                connection.execute(
                    tenants_table.insert().values(
                        id=tenant_id,
                        name=f"Tenant {index}",
                        slug=f"tenant-{index}",
                        default=index == 0,
                        sign_jwk="SIGN_JWK",
                        registration_allowed=True,
                    )
                )
            connection.execute(
                oauth_providers_table.insert().values(
                    id=oauth_provider_id,
                    provider="google",
                    client_id="CLIENT_ID",
                    client_secret="CLIENT_SECRET",
                    scopes=[],
                )
            )
            _insert_oauth_account(connection, tenant_ids[0])
            _run_alembic(connection, command.upgrade, OAUTH_ACCOUNT_TENANT_REVISION)

        def _insert_in_other_tenant(connection: sa.Connection) -> None:
            _insert_oauth_account(connection, tenant_ids[1])

        def _downgrade(connection: sa.Connection) -> None:
            connection.execute(
                oauth_accounts_table.delete().where(
                    oauth_accounts_table.c.tenant_id == tenant_ids[1]
                )
            )
            _run_alembic(connection, command.downgrade, ENCRYPT_SECRETS_REVISION)

        try:
            async with engine.begin() as connection:
                await connection.run_sync(_upgrade)
            async with engine.begin() as connection:
                await connection.run_sync(_insert_in_other_tenant)
            async with engine.begin() as connection:
                await connection.run_sync(_downgrade)
            with pytest.raises(sa.exc.IntegrityError):
                async with engine.begin() as connection:
                    await connection.run_sync(_insert_in_other_tenant)
        finally:
            await engine.dispose()
