from urllib.parse import urlparse

from redis.asyncio import Redis

from fief.services.rate_limit import RateLimiter
from fief.settings import settings

if urlparse(settings.redis_url).scheme == "rediss":
    # Same as the Dramatiq broker: Heroku Redis with TLS use self-signed certs
    redis = Redis.from_url(settings.redis_url, ssl_cert_reqs=None)
else:
    redis = Redis.from_url(settings.redis_url)


async def get_rate_limiter() -> RateLimiter:
    return RateLimiter(redis)
