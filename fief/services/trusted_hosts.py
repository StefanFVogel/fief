import ipaddress


class TrustedHosts:
    """
    Trusted proxies, written like uvicorn's `FORWARDED_ALLOW_IPS`:
    a comma-separated list of IP addresses, IP networks or literals, or `*`.
    """

    def __init__(self, trusted_hosts: str | list[str]) -> None:
        self.always_trust = trusted_hosts in ("*", ["*"])
        if isinstance(trusted_hosts, str):
            trusted_hosts = [item.strip() for item in trusted_hosts.split(",")]

        self.literals: set[str] = set()
        self.addresses: set[ipaddress.IPv4Address | ipaddress.IPv6Address] = set()
        self.networks: set[ipaddress.IPv4Network | ipaddress.IPv6Network] = set()

        for host in trusted_hosts:
            try:
                if "/" in host:
                    self.networks.add(ipaddress.ip_network(host))
                else:
                    self.addresses.add(ipaddress.ip_address(host))
            except ValueError:
                self.literals.add(host)

    def __contains__(self, host: str | None) -> bool:
        if self.always_trust:
            return True

        if not host:
            return False

        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            return host in self.literals

        return ip in self.addresses or any(ip in network for network in self.networks)
