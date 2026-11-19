import uuid
from unittest.mock import MagicMock

import httpx
import pytest
from fakeredis import FakeAsyncRedis
from fastapi import Request, status
from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware

from fief.apps import auth_app
from fief.middlewares.x_forwarded_host import XForwardedHostMiddleware
from fief.services.rate_limit import (
    RateLimiter,
    RateLimitExceededError,
    RateLimitKey,
    get_email_rate_limit_keys,
    get_login_rate_limit_keys,
    get_verify_code_rate_limit_keys,
)
from fief.settings import settings
from fief.settings_class import Settings

UNCAPPED_KEY = RateLimitKey("uncapped", capped=False)
CAPPED_KEY = RateLimitKey("capped", capped=True)


async def hit_until_blocked(rate_limiter: RateLimiter, key: RateLimitKey) -> int:
    while True:
        try:
            await rate_limiter.hit([key])
        except RateLimitExceededError as e:
            return e.wait_seconds


@pytest.mark.asyncio
class TestRateLimiterHit:
    async def test_first_attempts_free(self, rate_limiter: RateLimiter):
        await rate_limiter.hit([UNCAPPED_KEY])
        await rate_limiter.hit([UNCAPPED_KEY])

        with pytest.raises(RateLimitExceededError) as e:
            await rate_limiter.hit([UNCAPPED_KEY])
        assert e.value.wait_seconds == 60

    async def test_exponential_backoff(
        self, rate_limiter: RateLimiter, rate_limiter_clock: MagicMock
    ):
        await rate_limiter.hit([UNCAPPED_KEY])
        await rate_limiter.hit([UNCAPPED_KEY])

        for expected_wait in (60, 120, 240, 480):
            with pytest.raises(RateLimitExceededError) as e:
                await rate_limiter.hit([UNCAPPED_KEY])
            assert e.value.wait_seconds == expected_wait

            rate_limiter_clock.return_value += expected_wait - 1
            with pytest.raises(RateLimitExceededError) as e:
                await rate_limiter.hit([UNCAPPED_KEY])
            assert e.value.wait_seconds == 1

            rate_limiter_clock.return_value += 1
            await rate_limiter.hit([UNCAPPED_KEY])

    async def test_blocked_attempts_not_counted(
        self, rate_limiter: RateLimiter, rate_limiter_clock: MagicMock
    ):
        await rate_limiter.hit([UNCAPPED_KEY])
        await rate_limiter.hit([UNCAPPED_KEY])
        for _ in range(10):
            with pytest.raises(RateLimitExceededError):
                await rate_limiter.hit([UNCAPPED_KEY])

        rate_limiter_clock.return_value += 60
        await rate_limiter.hit([UNCAPPED_KEY])
        with pytest.raises(RateLimitExceededError) as e:
            await rate_limiter.hit([UNCAPPED_KEY])
        assert e.value.wait_seconds == 120

    async def test_capped(
        self, rate_limiter: RateLimiter, rate_limiter_clock: MagicMock
    ):
        for _ in range(20):
            rate_limiter_clock.return_value += await hit_until_blocked(
                rate_limiter, CAPPED_KEY
            )

        assert await hit_until_blocked(rate_limiter, CAPPED_KEY) == 900

    async def test_uncapped_bounded_by_lifetime(
        self, rate_limiter: RateLimiter, rate_limiter_clock: MagicMock
    ):
        for _ in range(20):
            rate_limiter_clock.return_value += await hit_until_blocked(
                rate_limiter, UNCAPPED_KEY
            )

        assert await hit_until_blocked(rate_limiter, UNCAPPED_KEY) == 86400

    async def test_any_key_blocks_and_nothing_recorded(
        self, rate_limiter: RateLimiter, rate_limiter_redis: FakeAsyncRedis
    ):
        await rate_limiter.hit([UNCAPPED_KEY])
        await rate_limiter.hit([UNCAPPED_KEY])

        with pytest.raises(RateLimitExceededError):
            await rate_limiter.hit([CAPPED_KEY, UNCAPPED_KEY])
        assert await rate_limiter_redis.exists(CAPPED_KEY.key) == 0

    async def test_counter_lifetime(
        self, rate_limiter: RateLimiter, rate_limiter_redis: FakeAsyncRedis
    ):
        await rate_limiter.hit([UNCAPPED_KEY])

        assert await rate_limiter_redis.ttl(UNCAPPED_KEY.key) == 86400

    async def test_settings(
        self,
        rate_limiter: RateLimiter,
        rate_limiter_clock: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ):
        monkeypatch.setattr(settings, "rate_limit_free_attempts", 3)
        monkeypatch.setattr(settings, "rate_limit_base_wait_seconds", 10)
        monkeypatch.setattr(settings, "rate_limit_max_wait_seconds", 30)

        for _ in range(4):
            await rate_limiter.hit([CAPPED_KEY])
        for expected_wait in (10, 20, 30, 30):
            with pytest.raises(RateLimitExceededError) as e:
                await rate_limiter.hit([CAPPED_KEY])
            assert e.value.wait_seconds == expected_wait
            rate_limiter_clock.return_value += expected_wait
            await rate_limiter.hit([CAPPED_KEY])

    async def test_disabled(
        self, rate_limiter: RateLimiter, monkeypatch: pytest.MonkeyPatch
    ):
        monkeypatch.setattr(settings, "rate_limit_enabled", False)

        for _ in range(10):
            await rate_limiter.hit([UNCAPPED_KEY])


@pytest.mark.asyncio
class TestRateLimiterReset:
    async def test_reset(self, rate_limiter: RateLimiter):
        await rate_limiter.hit([UNCAPPED_KEY, CAPPED_KEY])
        await rate_limiter.hit([UNCAPPED_KEY, CAPPED_KEY])
        with pytest.raises(RateLimitExceededError):
            await rate_limiter.hit([UNCAPPED_KEY])

        await rate_limiter.reset([UNCAPPED_KEY, CAPPED_KEY])

        await rate_limiter.hit([UNCAPPED_KEY, CAPPED_KEY])
        await rate_limiter.hit([UNCAPPED_KEY, CAPPED_KEY])


def get_request(ip: str) -> Request:
    return Request({"type": "http", "client": (ip, 0)})


@pytest.mark.asyncio
class TestLoginRateLimitKeys:
    async def test_account_blocked_from_other_ips(
        self, rate_limiter: RateLimiter, rate_limiter_clock: MagicMock
    ):
        tenant = uuid.uuid4()
        for ip in ("10.0.0.1", "10.0.0.2"):
            await rate_limiter.hit(
                get_login_rate_limit_keys(
                    get_request(ip), tenant, "anne@bretagne.duchy"
                )
            )

        with pytest.raises(RateLimitExceededError):
            await rate_limiter.hit(
                get_login_rate_limit_keys(
                    get_request("10.0.0.3"), tenant, "Anne@Bretagne.Duchy"
                )
            )
        await rate_limiter.hit(
            get_login_rate_limit_keys(
                get_request("10.0.0.3"), tenant, "louis@bretagne.duchy"
            )
        )

    async def test_ip_blocked_for_other_accounts(self, rate_limiter: RateLimiter):
        tenant = uuid.uuid4()
        request = get_request("10.0.0.1")
        for email in ("anne@bretagne.duchy", "louis@bretagne.duchy"):
            await rate_limiter.hit(get_login_rate_limit_keys(request, tenant, email))

        with pytest.raises(RateLimitExceededError):
            await rate_limiter.hit(
                get_login_rate_limit_keys(request, tenant, "isabeau@bretagne.duchy")
            )


class TestNoClient:
    def test_login(self):
        tenant = uuid.uuid4()
        keys = get_login_rate_limit_keys(
            Request({"type": "http"}), tenant, "Anne@Bretagne.Duchy"
        )

        assert keys == [
            RateLimitKey(
                f"fief:rate_limit:login:account:{tenant}:anne@bretagne.duchy",
                capped=True,
            )
        ]

    def test_verify_code(self):
        user = uuid.uuid4()
        keys = get_verify_code_rate_limit_keys(Request({"type": "http"}), user)

        assert keys == [
            RateLimitKey(f"fief:rate_limit:verify_code:account:{user}", capped=False)
        ]

    def test_email(self):
        tenant = uuid.uuid4()
        keys = get_email_rate_limit_keys(
            Request({"type": "http"}), "forgot_password", tenant, "anne@bretagne.duchy"
        )

        assert keys == [
            RateLimitKey(
                f"fief:rate_limit:forgot_password:email:{tenant}:anne@bretagne.duchy",
                capped=True,
            )
        ]


PROXY_NETWORK = "10.244.0.0/16"
PROXY_ADDRESS = "10.244.0.5"


@pytest.mark.asyncio
class TestClientAddressBehindProxy:
    """
    The rate limiter relies on `request.client.host` being the address reported
    by trusted proxies, as resolved by uvicorn from `FORWARDED_ALLOW_IPS`.
    """

    async def forgot(
        self,
        csrf_token: str,
        client_host: str,
        email: str,
        x_forwarded_for: str | None = None,
        trusted_hosts: str = PROXY_NETWORK,
    ) -> None:
        app = ProxyHeadersMiddleware(
            XForwardedHostMiddleware(auth_app, trusted_hosts=trusted_hosts),
            trusted_hosts=trusted_hosts,
        )
        headers = {}
        if x_forwarded_for is not None:
            headers["X-Forwarded-For"] = x_forwarded_for
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, client=(client_host, 123)),
            base_url="http://api.fief.dev",
            cookies={settings.csrf_cookie_name: csrf_token},
        ) as client:
            response = await client.post(
                "/forgot",
                data={"email": email, "csrf_token": csrf_token},
                headers=headers,
            )
        assert response.status_code == status.HTTP_200_OK

    async def get_ip_keys(self, rate_limiter_redis: FakeAsyncRedis) -> list[str]:
        return sorted(
            key.decode()
            for key in await rate_limiter_redis.keys("fief:rate_limit:*:ip:*")
        )

    @pytest.mark.parametrize(
        "client_host,x_forwarded_for",
        [
            (PROXY_ADDRESS, "203.0.113.7, 198.51.100.9"),
            (PROXY_ADDRESS, "198.51.100.9"),
            ("198.51.100.9", "203.0.113.7"),
            ("198.51.100.9", None),
        ],
    )
    async def test_key_uses_client_address(
        self,
        client_host: str,
        x_forwarded_for: str | None,
        csrf_token: str,
        rate_limiter_redis: FakeAsyncRedis,
        test_client_auth: httpx.AsyncClient,
    ):
        await self.forgot(
            csrf_token, client_host, "anne@bretagne.duchy", x_forwarded_for
        )

        assert await self.get_ip_keys(rate_limiter_redis) == [
            "fief:rate_limit:forgot_password:ip:198.51.100.9"
        ]

    async def test_all_trusted_takes_client_chosen_address(
        self,
        csrf_token: str,
        rate_limiter_redis: FakeAsyncRedis,
        test_client_auth: httpx.AsyncClient,
    ):
        await self.forgot(
            csrf_token,
            PROXY_ADDRESS,
            "anne@bretagne.duchy",
            "203.0.113.7, 198.51.100.9",
            trusted_hosts="*",
        )

        assert await self.get_ip_keys(rate_limiter_redis) == [
            "fief:rate_limit:forgot_password:ip:203.0.113.7"
        ]

    async def test_other_client_not_blocked(
        self,
        csrf_token: str,
        rate_limiter_redis: FakeAsyncRedis,
        test_client_auth: httpx.AsyncClient,
    ):
        for email in (
            "anne@bretagne.duchy",
            "isabeau@bretagne.duchy",
            "marguerite@bretagne.duchy",
        ):
            await self.forgot(
                csrf_token, PROXY_ADDRESS, email, "203.0.113.7, 198.51.100.9"
            )
        assert (
            await rate_limiter_redis.hget(
                "fief:rate_limit:forgot_password:ip:198.51.100.9", "count"
            )
            == b"2"
        )

        await self.forgot(
            csrf_token, PROXY_ADDRESS, "louis@bretagne.duchy", "198.51.100.10"
        )

        assert (
            await rate_limiter_redis.hget(
                "fief:rate_limit:forgot_password:ip:198.51.100.10", "count"
            )
            == b"1"
        )


def test_settings_defaults():
    assert settings.rate_limit_enabled is True
    assert settings.rate_limit_free_attempts == 1
    assert settings.rate_limit_base_wait_seconds == 60
    assert settings.rate_limit_max_wait_seconds == 900
    assert settings.rate_limit_counter_lifetime_seconds == 86400


def test_settings_from_env(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("RATE_LIMIT_ENABLED", "false")
    monkeypatch.setenv("RATE_LIMIT_FREE_ATTEMPTS", "3")
    monkeypatch.setenv("RATE_LIMIT_BASE_WAIT_SECONDS", "10")
    monkeypatch.setenv("RATE_LIMIT_MAX_WAIT_SECONDS", "300")
    monkeypatch.setenv("RATE_LIMIT_COUNTER_LIFETIME_SECONDS", "3600")

    env_settings = Settings()  # type: ignore[call-arg]

    assert env_settings.rate_limit_enabled is False
    assert env_settings.rate_limit_free_attempts == 3
    assert env_settings.rate_limit_base_wait_seconds == 10
    assert env_settings.rate_limit_max_wait_seconds == 300
    assert env_settings.rate_limit_counter_lifetime_seconds == 3600
