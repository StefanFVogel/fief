import pytest

from fief.services.localhost import is_localhost


@pytest.mark.parametrize(
    "host,result",
    [
        ("127.0.0.1", True),
        ("127.0.1.1", True),
        ("::1", True),
        ("[::1]", True),
        ("localhost", True),
        ("LOCALHOST", True),
        ("localhost:8000", True),
        ("app.localhost", True),
        ("app.localhost:8000", True),
        ("192.168.0.42", False),
        ("192.168.1.1", False),
        ("10.0.0.5", False),
        ("172.16.0.1", False),
        ("localhost.attacker.example", False),
        ("app.localhost.attacker.example", False),
        ("localhost8000.attacker.example", False),
        ("notlocalhost", False),
        ("www.bretagne.duchy", False),
        ("www.fief.dev", False),
    ],
)
def test_is_localhost(host: str, result: bool):
    assert is_localhost(host) == result
