import ssl

import pytest
from redis.asyncio.connection import Connection, SSLConnection

from fief.dependencies.rate_limit import create_redis


class TestCreateRedis:
    def test_redis_scheme_no_ssl(self):
        redis = create_redis("redis://localhost:6379", "required")

        assert redis.connection_pool.connection_class is Connection

    @pytest.mark.parametrize(
        "ssl_cert_reqs,expected",
        [
            ("required", ssl.CERT_REQUIRED),
            ("optional", ssl.CERT_OPTIONAL),
            ("none", ssl.CERT_NONE),
        ],
    )
    def test_rediss_scheme_cert_reqs(self, ssl_cert_reqs: str, expected: int):
        redis = create_redis("rediss://localhost:6379", ssl_cert_reqs)

        connection_pool = redis.connection_pool
        assert connection_pool.connection_class is SSLConnection
        connection = connection_pool.make_connection()
        assert connection.ssl_context.cert_reqs == expected
