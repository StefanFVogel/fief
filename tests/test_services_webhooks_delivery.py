import ipaddress
import socket

import httpx
import pytest
import respx
from sqlalchemy import select

from fief import __version__, schemas
from fief.db import AsyncSession
from fief.models import Webhook, WebhookLog
from fief.repositories import WebhookLogRepository
from fief.services.webhooks import target
from fief.services.webhooks.delivery import WebhookDelivery, WebhookDeliveryError
from fief.services.webhooks.models import ClientCreated, WebhookEvent
from fief.settings import settings
from tests.data import TestData

PUBLIC_IP = "93.184.216.34"


@pytest.fixture(autouse=True)
def resolved_addresses(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    addresses = [PUBLIC_IP]

    async def _resolve_host(host: str):
        return [ipaddress.ip_address(address) for address in addresses]

    monkeypatch.setattr(target, "resolve_host", _resolve_host)
    return addresses


@pytest.fixture
def webhook_delivery(main_session: AsyncSession) -> WebhookDelivery:
    return WebhookDelivery(WebhookLogRepository(main_session))


@pytest.fixture
def webhook_event(test_data: TestData) -> WebhookEvent:
    object = test_data["clients"]["default_tenant"]
    return WebhookEvent(
        type=ClientCreated.key(),
        data=schemas.client.Client.model_validate(object).model_dump(),
    )


@pytest.mark.asyncio
class TestWebhookDelivery:
    async def test_deliver_success(
        self,
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        webhook = test_data["webhooks"]["all"]
        route_mock = respx_mock.post(f"https://{PUBLIC_IP}/webhook").mock(
            return_value=httpx.Response(200, text="Ok")
        )

        await webhook_delivery.deliver(webhook, webhook_event)

        assert route_mock.called
        request, _ = route_mock.calls.last

        assert "X-Fief-Webhook-Signature" in request.headers
        assert "X-Fief-Webhook-Timestamp" in request.headers
        assert request.content == webhook_event.model_dump_json().encode("utf-8")

        assert request.headers["user-agent"] == f"fief-server-webhooks/{__version__}"
        assert request.headers["host"] == "internal.bretagne.duchy"
        assert request.extensions["sni_hostname"] == "internal.bretagne.duchy"

        webhook_log_repository = WebhookLogRepository(main_session)
        webhook_logs = await webhook_log_repository.list(
            select(WebhookLog).order_by(WebhookLog.created_at.desc())
        )

        assert len(webhook_logs) == len(test_data["webhook_logs"]) + 1
        webhook_log = webhook_logs[0]
        assert webhook_log.webhook_id == webhook.id
        assert webhook_log.event == webhook_event.type
        assert webhook_log.response == "Ok"
        assert webhook_log.error_type is None
        assert webhook_log.error_message is None
        assert webhook_log.success

    async def test_deliver_status_error(
        self,
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        webhook = test_data["webhooks"]["all"]
        route_mock = respx_mock.post(f"https://{PUBLIC_IP}/webhook").mock(
            return_value=httpx.Response(400, text="Bad Request")
        )

        with pytest.raises(WebhookDeliveryError):
            await webhook_delivery.deliver(webhook, webhook_event)

        assert route_mock.called

        webhook_log_repository = WebhookLogRepository(main_session)
        webhook_logs = await webhook_log_repository.list(
            select(WebhookLog).order_by(WebhookLog.created_at.desc())
        )

        assert len(webhook_logs) == len(test_data["webhook_logs"]) + 1
        webhook_log = webhook_logs[0]
        assert webhook_log.webhook_id == webhook.id
        assert webhook_log.event == webhook_event.type
        assert webhook_log.response == "Bad Request"
        assert webhook_log.error_type == "HTTPStatusError"
        assert webhook_log.error_message is not None
        assert "Client error '400 Bad Request'" in webhook_log.error_message
        assert not webhook_log.success

    async def test_deliver_general_error(
        self,
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        webhook = test_data["webhooks"]["all"]
        route_mock = respx_mock.post(f"https://{PUBLIC_IP}/webhook").mock(
            side_effect=httpx.HTTPError("Something went wrong")
        )

        with pytest.raises(WebhookDeliveryError):
            await webhook_delivery.deliver(webhook, webhook_event)

        assert route_mock.called

        webhook_log_repository = WebhookLogRepository(main_session)
        webhook_logs = await webhook_log_repository.list(
            select(WebhookLog).order_by(WebhookLog.created_at.desc())
        )

        assert len(webhook_logs) == len(test_data["webhook_logs"]) + 1
        webhook_log = webhook_logs[0]
        assert webhook_log.webhook_id == webhook.id
        assert webhook_log.event == webhook_event.type
        assert webhook_log.response is None
        assert webhook_log.error_type == "HTTPError"
        assert webhook_log.error_message == "Something went wrong"
        assert not webhook_log.success

    async def test_deliver_response_truncated(
        self,
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        monkeypatch.setattr(settings, "webhooks_max_response_log_size", 10)
        webhook = test_data["webhooks"]["all"]
        respx_mock.post(f"https://{PUBLIC_IP}/webhook").mock(
            return_value=httpx.Response(200, text="A" * 1000)
        )

        await webhook_delivery.deliver(webhook, webhook_event)

        webhook_log_repository = WebhookLogRepository(main_session)
        webhook_logs = await webhook_log_repository.list(
            select(WebhookLog).order_by(WebhookLog.created_at.desc())
        )
        webhook_log = webhook_logs[0]
        assert webhook_log.response == "A" * 10
        assert webhook_log.success

    @pytest.mark.parametrize(
        "url,addresses",
        [
            ("http://127.0.0.1/webhook", []),
            ("http://10.0.0.1/webhook", []),
            ("http://169.254.169.254/latest/meta-data", []),
            ("http://[::1]/webhook", []),
            ("http://[::ffff:127.0.0.1]/webhook", []),
            ("http://0.0.0.0/webhook", []),
            ("http://internal.bretagne.duchy/webhook", ["192.168.1.10"]),
            ("http://internal.bretagne.duchy/webhook", ["fd00::1"]),
            ("http://internal.bretagne.duchy/webhook", [PUBLIC_IP, "10.0.0.1"]),
            ("http://internal.bretagne.duchy/webhook", ["64:ff9b::a00:1"]),
            ("http://internal.bretagne.duchy/webhook", ["fec0::1"]),
        ],
    )
    async def test_deliver_blocked_target(
        self,
        url: str,
        addresses: list[str],
        resolved_addresses: list[str],
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        resolved_addresses[:] = addresses
        webhook = Webhook(id=test_data["webhooks"]["all"].id, url=url, secret="SECRET")

        with pytest.raises(WebhookDeliveryError):
            await webhook_delivery.deliver(webhook, webhook_event)

        assert len(respx_mock.calls) == 0

        webhook_log_repository = WebhookLogRepository(main_session)
        webhook_logs = await webhook_log_repository.list(
            select(WebhookLog).order_by(WebhookLog.created_at.desc())
        )
        assert len(webhook_logs) == len(test_data["webhook_logs"]) + 1
        webhook_log = webhook_logs[0]
        assert webhook_log.response is None
        assert webhook_log.error_type == "WebhookTargetBlockedError"
        assert webhook_log.error_message is not None
        assert not webhook_log.success

    async def test_deliver_allowed_network(
        self,
        monkeypatch: pytest.MonkeyPatch,
        resolved_addresses: list[str],
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
    ):
        monkeypatch.setattr(
            settings,
            "webhooks_allowed_networks",
            [ipaddress.ip_network("10.0.0.0/8")],
        )
        resolved_addresses[:] = ["10.1.2.3"]
        webhook = test_data["webhooks"]["all"]
        route_mock = respx_mock.post("https://10.1.2.3/webhook").mock(
            return_value=httpx.Response(200, text="Ok")
        )

        await webhook_delivery.deliver(webhook, webhook_event)

        assert route_mock.called
        request, _ = route_mock.calls.last
        assert request.headers["host"] == "internal.bretagne.duchy"

    async def test_deliver_ipv6_address(
        self,
        resolved_addresses: list[str],
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
    ):
        resolved_addresses[:] = ["2606:4700::1"]
        webhook = test_data["webhooks"]["all"]
        route_mock = respx_mock.post("https://[2606:4700::1]/webhook").mock(
            return_value=httpx.Response(200, text="Ok")
        )

        await webhook_delivery.deliver(webhook, webhook_event)

        assert route_mock.called
        request, _ = route_mock.calls.last
        assert request.headers["host"] == "internal.bretagne.duchy"

    async def test_deliver_resolution_error(
        self,
        monkeypatch: pytest.MonkeyPatch,
        respx_mock: respx.MockRouter,
        webhook_delivery: WebhookDelivery,
        webhook_event: WebhookEvent,
        test_data: TestData,
        main_session: AsyncSession,
    ):
        async def _resolve_host(host: str):
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

        monkeypatch.setattr(target, "resolve_host", _resolve_host)
        webhook = test_data["webhooks"]["all"]

        with pytest.raises(WebhookDeliveryError):
            await webhook_delivery.deliver(webhook, webhook_event)

        assert len(respx_mock.calls) == 0

        webhook_log_repository = WebhookLogRepository(main_session)
        webhook_logs = await webhook_log_repository.list(
            select(WebhookLog).order_by(WebhookLog.created_at.desc())
        )
        webhook_log = webhook_logs[0]
        assert webhook_log.error_type == "gaierror"
        assert not webhook_log.success
