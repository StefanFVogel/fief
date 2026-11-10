from urllib.parse import urlparse

from redis.asyncio import Redis

from fief.services.rate_limit import RateLimiter
from fief.settings import settings


def create_redis(redis_url: str, ssl_cert_reqs: str) -> Redis:
    if urlparse(redis_url).scheme == "rediss":
        # Same as the Dramatiq broker: certificates are verified by default
        return Redis.from_url(redis_url, ssl_cert_reqs=ssl_cert_reqs)
    return Redis.from_url(redis_url)


redis = create_redis(settings.redis_url, settings.redis_ssl_cert_reqs)


async def get_rate_limiter() -> RateLimiter:
    return RateLimiter(redis)
