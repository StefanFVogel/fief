import ssl

import pytest
from redis.connection import Connection, SSLConnection

from fief.settings_class import Settings
from fief.tasks.base import create_redis_broker


def test_redis_ssl_cert_reqs_default_required():
    assert Settings.model_fields["redis_ssl_cert_reqs"].default == "required"


class TestCreateRedisBroker:
    def test_redis_scheme_no_ssl(self):
        broker = create_redis_broker("redis://localhost:6379", "required")

        connection_pool = broker.client.connection_pool
        assert connection_pool.connection_class is Connection
        assert connection_pool.connection_kwargs["host"] == "localhost"
        assert connection_pool.connection_kwargs["port"] == 6379

    @pytest.mark.parametrize(
        "ssl_cert_reqs,expected",
        [
            ("required", ssl.CERT_REQUIRED),
            ("optional", ssl.CERT_OPTIONAL),
            ("none", ssl.CERT_NONE),
        ],
    )
    def test_rediss_scheme_cert_reqs(self, ssl_cert_reqs: str, expected: int):
        broker = create_redis_broker("rediss://localhost:6379", ssl_cert_reqs)

        connection_pool = broker.client.connection_pool
        assert connection_pool.connection_class is SSLConnection
        connection = connection_pool.make_connection()
        assert connection.cert_reqs == expected
