import asyncio
import ipaddress
import socket

from fief.settings import settings

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address


class WebhookTargetBlockedError(Exception):
    def __init__(self, host: str) -> None:
        super().__init__(f"Webhook target {host} resolves to an internal address")


def is_allowed_address(address: IPAddress) -> bool:
    if any(address in network for network in settings.webhooks_allowed_networks):
        return True
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        return is_allowed_address(address.ipv4_mapped)
    return address.is_global and not address.is_multicast


def is_allowed_host(host: str) -> bool:
    """
    Check a host before any DNS resolution, for early validation of webhook URLs.

    Hostnames are resolved and checked again at delivery time.
    """
    host = host.strip("[]").rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return True
    return is_allowed_address(address)


async def resolve_host(host: str) -> list[IPAddress]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    return [ipaddress.ip_address(info[4][0]) for info in infos]


async def resolve_allowed_address(host: str) -> IPAddress:
    """
    Resolve the host and return the address to connect to.

    Raises `WebhookTargetBlockedError` if any resolved address is internal.
    """
    try:
        addresses: list[IPAddress] = [ipaddress.ip_address(host.strip("[]"))]
    except ValueError:
        addresses = await resolve_host(host)
    if len(addresses) == 0 or not all(is_allowed_address(a) for a in addresses):
        raise WebhookTargetBlockedError(host)
    return addresses[0]
