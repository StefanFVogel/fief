import hmac
import socket
import time
from hashlib import sha256

import httpx

from fief import __version__
from fief.models import Webhook, WebhookLog
from fief.repositories import WebhookLogRepository
from fief.services.webhooks.models import WebhookEvent
from fief.services.webhooks.target import (
    WebhookTargetBlockedError,
    resolve_allowed_address,
)
from fief.settings import settings


class WebhookDeliveryError(Exception):
    def __init__(self, message: str) -> None:
        super().__init__(message)


class WebhookDelivery:
    def __init__(self, webhook_log_repository: WebhookLogRepository) -> None:
        self.webhook_log_repository = webhook_log_repository

    async def deliver(self, webhook: Webhook, event: WebhookEvent, attempt: int = 1):
        async with httpx.AsyncClient() as client:
            payload = event.model_dump_json()
            signature, ts = self._get_signature(payload, webhook.secret)

            webhook_log = WebhookLog(
                webhook_id=webhook.id,
                event=event.type,
                attempt=attempt,
                payload=payload,
                success=False,
            )

            try:
                url = httpx.URL(webhook.url)
                host = url.raw_host.decode("ascii")
                address = await resolve_allowed_address(host)
                async with client.stream(
                    "POST",
                    url.copy_with(host=str(address)),
                    content=payload,
                    headers={
                        "Host": url.netloc.decode("ascii"),
                        "User-Agent": f"fief-server-webhooks/{__version__}",
                        "Content-Type": "application/json",
                        "X-Fief-Webhook-Signature": signature,
                        "X-Fief-Webhook-Timestamp": str(ts),
                    },
                    extensions={"sni_hostname": host},
                    follow_redirects=False,
                ) as response:
                    webhook_log.response = await self._read_response(response)
                    response.raise_for_status()
                webhook_log.success = True
            except (
                httpx.HTTPError,
                socket.gaierror,
                UnicodeError,
                WebhookTargetBlockedError,
            ) as e:
                webhook_log.error_type = type(e).__name__
                webhook_log.error_message = str(e)
                raise WebhookDeliveryError(str(e)) from e
            finally:
                await self.webhook_log_repository.create(webhook_log)

    async def _read_response(self, response: httpx.Response) -> str:
        max_size = settings.webhooks_max_response_log_size
        content = b""
        async for chunk in response.aiter_bytes():
            content += chunk
            if len(content) >= max_size:
                break
        return content[:max_size].decode(response.encoding or "utf-8", "replace")

    def _get_signature(self, payload: str, secret: str) -> tuple[str, int]:
        ts = int(time.time())
        message = f"{ts}.{payload}"

        hash = hmac.new(
            secret.encode("utf-8"),
            msg=message.encode("utf-8"),
            digestmod=sha256,
        )
        signature = hash.hexdigest()
        return signature, ts
