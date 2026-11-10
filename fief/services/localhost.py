import ipaddress
import re

LOCALHOST_HOST_PATTERN = re.compile(r"([^\.]+\.)?localhost(:\d+)?", flags=re.IGNORECASE)


def is_localhost(host: str) -> bool:
    try:
        return ipaddress.ip_address(host.strip("[]")).is_loopback
    except ValueError:
        return LOCALHOST_HOST_PATTERN.fullmatch(host) is not None


__all__ = ["is_localhost"]
