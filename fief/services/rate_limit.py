import math
import time
from collections.abc import Callable
from typing import NamedTuple

from fastapi import Request
from pydantic import UUID4
from redis.asyncio import Redis

from fief.settings import settings

# Checks every key and, only if none of them is blocked, records the attempt
# on all of them. Doing both atomically prevents parallel requests from
# slipping through before the previous failures are recorded.
HIT_SCRIPT = """
local now = tonumber(ARGV[1])
local free_attempts = tonumber(ARGV[2])
local base_wait = tonumber(ARGV[3])
local max_wait = tonumber(ARGV[4])
local lifetime = tonumber(ARGV[5])

local remaining = 0
for i, key in ipairs(KEYS) do
    local state = redis.call("HMGET", key, "count", "last")
    local count = tonumber(state[1]) or 0
    local last = tonumber(state[2]) or 0
    if count > free_attempts then
        local wait = math.min(base_wait * 2 ^ (count - free_attempts - 1), lifetime)
        if ARGV[5 + i] == "1" then
            wait = math.min(wait, max_wait)
        end
        remaining = math.max(remaining, last + wait - now)
    end
end

if remaining > 0 then
    return tostring(remaining)
end

for _, key in ipairs(KEYS) do
    redis.call("HINCRBY", key, "count", 1)
    redis.call("HSET", key, "last", ARGV[1])
    redis.call("EXPIRE", key, lifetime)
end
return "0"
"""


class RateLimitExceededError(Exception):
    def __init__(self, wait_seconds: int) -> None:
        super().__init__(wait_seconds)
        self.wait_seconds = wait_seconds

    @property
    def wait_minutes(self) -> int:
        return math.ceil(self.wait_seconds / 60)


class RateLimitKey(NamedTuple):
    key: str
    capped: bool


class RateLimiter:
    def __init__(self, redis: Redis, *, clock: Callable[[], float] = time.time):
        self.redis = redis
        self.clock = clock

    async def hit(self, keys: list[RateLimitKey]) -> None:
        """
        Record an attempt on every key.

        Raises `RateLimitExceededError` without recording anything
        if one of the keys is still in its backoff period.
        """
        if not settings.rate_limit_enabled:
            return

        remaining = await self.redis.eval(  # type: ignore[misc]
            HIT_SCRIPT,
            len(keys),
            *(key.key for key in keys),
            repr(self.clock()),
            str(settings.rate_limit_free_attempts),
            str(settings.rate_limit_base_wait_seconds),
            str(settings.rate_limit_max_wait_seconds),
            str(settings.rate_limit_counter_lifetime_seconds),
            *("1" if key.capped else "0" for key in keys),
        )
        wait_seconds = math.ceil(float(remaining))
        if wait_seconds > 0:
            raise RateLimitExceededError(wait_seconds)

    async def reset(self, keys: list[RateLimitKey]) -> None:
        if not settings.rate_limit_enabled:
            return

        await self.redis.delete(*(key.key for key in keys))


def _get_client_ip(request: Request) -> str:
    return request.client.host if request.client is not None else ""


def get_login_rate_limit_keys(
    request: Request, tenant: UUID4, email: str
) -> list[RateLimitKey]:
    email = email.strip().lower()
    ip = _get_client_ip(request)
    return [
        RateLimitKey(f"fief:rate_limit:login:ip:{ip}", capped=True),
        RateLimitKey(
            f"fief:rate_limit:login:account_ip:{tenant}:{email}:{ip}", capped=False
        ),
        RateLimitKey(f"fief:rate_limit:login:account:{tenant}:{email}", capped=True),
    ]


def get_verify_code_rate_limit_keys(
    request: Request, user: UUID4
) -> list[RateLimitKey]:
    ip = _get_client_ip(request)
    return [
        RateLimitKey(f"fief:rate_limit:verify_code:ip:{ip}", capped=True),
        RateLimitKey(
            f"fief:rate_limit:verify_code:account_ip:{user}:{ip}", capped=False
        ),
    ]


def get_email_rate_limit_keys(
    request: Request, action: str, tenant: UUID4, email: str
) -> list[RateLimitKey]:
    email = email.strip().lower()
    ip = _get_client_ip(request)
    return [
        RateLimitKey(f"fief:rate_limit:{action}:ip:{ip}", capped=True),
        RateLimitKey(f"fief:rate_limit:{action}:email:{tenant}:{email}", capped=True),
    ]
