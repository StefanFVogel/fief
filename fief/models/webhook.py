import secrets

from sqlalchemy import JSON, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from fief.crypto.encryption import FernetEngine, StringEncryptedType
from fief.models.base import Base
from fief.models.generics import CreatedUpdatedAt, PydanticUrlString, UUIDModel
from fief.settings import settings


class Webhook(UUIDModel, CreatedUpdatedAt, Base):
    __tablename__ = "webhooks"

    url: Mapped[str] = mapped_column(
        PydanticUrlString(String)(length=255), nullable=False
    )
    secret: Mapped[str] = mapped_column(
        StringEncryptedType(Text, settings.encryption_key, FernetEngine),
        default=secrets.token_urlsafe,
        nullable=False,
    )
    events: Mapped[list[str]] = mapped_column(JSON, nullable=False, default=list)

    def regenerate_secret(self) -> str:
        self.secret = secrets.token_urlsafe()
        return self.secret
