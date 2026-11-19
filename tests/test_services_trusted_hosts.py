import pytest

from fief.services.trusted_hosts import TrustedHosts


@pytest.mark.parametrize(
    "trusted_hosts,host,expected",
    [
        ("*", "198.51.100.9", True),
        ("*", None, True),
        (["*"], "198.51.100.9", True),
        ("10.244.0.0/16", "10.244.0.5", True),
        ("10.244.0.0/16", "10.245.0.5", False),
        ("10.244.0.0/16", None, False),
        ("10.244.0.0/16", "", False),
        (["127.0.0.1", "10.244.0.5"], "10.244.0.5", True),
        ("::1", "0:0:0:0:0:0:0:1", True),
        ("unix:/run/fief.sock", "unix:/run/fief.sock", True),
        ("unix:/run/fief.sock", "unix:/run/other.sock", False),
        ("10.244.0.0/16, *", "198.51.100.9", False),
    ],
)
def test_contains(trusted_hosts: str | list[str], host: str | None, expected: bool):
    assert (host in TrustedHosts(trusted_hosts)) is expected


@pytest.mark.parametrize(
    "trusted_hosts,expected",
    [
        ("*", True),
        (["*"], True),
        (" * ", False),
        ("127.0.0.1", False),
        ("127.0.0.1,*", False),
    ],
)
def test_always_trust(trusted_hosts: str, expected: bool):
    assert TrustedHosts(trusted_hosts).always_trust is expected
