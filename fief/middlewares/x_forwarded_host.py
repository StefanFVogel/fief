from starlette.datastructures import MutableHeaders
from starlette.types import ASGIApp, Receive, Scope, Send

from fief.services.trusted_hosts import TrustedHosts
from fief.settings import settings


class XForwardedHostMiddleware:
    def __init__(self, app: ASGIApp, trusted_hosts: str | list[str] = "127.0.0.1"):
        self.app = app
        self.trusted_hosts = TrustedHosts(trusted_hosts)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if settings.x_forwarded_host_enabled and scope["type"] in ("http", "websocket"):
            client_addr: tuple[str, int] | None = scope.get("client")
            client_host = client_addr[0] if client_addr else None

            if client_host in self.trusted_hosts:
                headers = MutableHeaders(scope=scope)

                if "x-forwarded-host" in headers:
                    headers.update({"host": headers["x-forwarded-host"]})
                    scope["headers"] = headers.raw

        return await self.app(scope, receive, send)
