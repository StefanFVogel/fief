from enum import StrEnum
from typing import Annotated

from pydantic import AfterValidator, BaseModel, HttpUrl
from pydantic_core import PydanticCustomError

from fief.errors import APIErrorCode
from fief.schemas.generics import CreatedUpdatedAt, UUIDSchema
from fief.services.webhooks.models import WEBHOOK_EVENTS
from fief.services.webhooks.target import is_allowed_host

WebhookEventType = StrEnum(  # type: ignore
    "WebhookEventType",
    [event.key() for event in WEBHOOK_EVENTS],
)


def validate_webhook_url(url: HttpUrl) -> HttpUrl:
    if url.host is None or not is_allowed_host(url.host):
        raise PydanticCustomError(
            APIErrorCode.WEBHOOK_INTERNAL_URL.value,
            "Webhook URLs can't point to an internal address.",
        )
    return url


WebhookURL = Annotated[HttpUrl, AfterValidator(validate_webhook_url)]


class WebhookCreate(BaseModel):
    url: WebhookURL
    events: list[WebhookEventType]


class WebhookUpdate(BaseModel):
    url: WebhookURL | None = None
    events: list[WebhookEventType] | None = None


class BaseWebhook(UUIDSchema, CreatedUpdatedAt):
    url: HttpUrl
    events: list[WebhookEventType]


class Webhook(BaseWebhook):
    pass


class WebhookSecret(BaseWebhook):
    secret: str
