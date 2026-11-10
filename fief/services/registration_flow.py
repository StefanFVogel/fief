import json
import urllib.parse
from typing import Any, TypeVar

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Request, Response

from fief.models import (
    OAuthAccount,
    RegistrationSession,
    RegistrationSessionFlow,
    Tenant,
    User,
    UserField,
)
from fief.repositories import OAuthAccountRepository, RegistrationSessionRepository
from fief.schemas.user import UF, UserCreate
from fief.services.user_manager import UserDoesNotExistError, UserManager
from fief.settings import settings

ResponseType = TypeVar("ResponseType", bound=Response)

REGISTRATION_TOKEN_AUDIENCE = "fief:register"


class InvalidRegistrationTokenError(Exception):
    pass


class RegistrationFlow:
    def __init__(
        self,
        registration_session_repository: RegistrationSessionRepository,
        oauth_account_repository: OAuthAccountRepository,
        user_manager: UserManager,
        user_create_model: type[UserCreate[UF]],
        user_fields: list[UserField],
    ) -> None:
        self.registration_session_repository = registration_session_repository
        self.oauth_account_repository = oauth_account_repository
        self.user_manager = user_manager
        self.user_create_model = user_create_model
        self.user_fields = user_fields

    async def create_registration_session(
        self,
        response: ResponseType,
        flow: RegistrationSessionFlow,
        *,
        tenant: Tenant,
        oauth_account: OAuthAccount | None = None,
    ) -> ResponseType:
        email = None
        oauth_account_id = None
        if oauth_account is not None:
            email = oauth_account.account_email
            oauth_account_id = oauth_account.id

        registration_session = RegistrationSession(
            flow=flow,
            email=email,
            oauth_account_id=oauth_account_id,
            tenant_id=tenant.id,
        )
        registration_session = await self.registration_session_repository.create(
            registration_session
        )

        response.set_cookie(
            settings.registration_session_cookie_name,
            registration_session.token,
            domain=settings.registration_session_cookie_domain,
            secure=settings.registration_session_cookie_secure,
            httponly=True,
        )

        return response

    async def delete_registration_session(
        self, response: ResponseType, registration_session: RegistrationSession
    ) -> ResponseType:
        response.delete_cookie(
            settings.registration_session_cookie_name,
            domain=settings.registration_session_cookie_domain,
        )
        await self.registration_session_repository.delete(registration_session)
        return response

    async def set_login_hint(
        self, response: ResponseType, registration_session: RegistrationSession
    ) -> ResponseType:
        login_hint = registration_session.email

        if registration_session.oauth_account:
            login_hint = str(registration_session.oauth_account.oauth_provider_id)

        if login_hint is None:
            return response

        response.set_cookie(
            settings.login_hint_cookie_name,
            value=urllib.parse.quote(login_hint),
            max_age=settings.login_hint_cookie_lifetime_seconds,
            domain=settings.login_hint_cookie_domain,
            secure=settings.login_hint_cookie_secure,
            httponly=True,
        )

        return response

    async def request_registration(
        self,
        data: dict[str, Any],
        tenant: Tenant,
        registration_session: RegistrationSession,
        request: Request,
    ) -> None:
        """
        Start a registration without telling whether the email is already taken.

        For a new email, a link to confirm the email and create the account is sent.
        For an existing account, its owner is told they already have one.
        """
        user_create = self._get_user_create(data, tenant)

        try:
            user = await self.user_manager.get_by_email(user_create.email, tenant.id)
        except UserDoesNotExistError:
            payload = {
                "aud": REGISTRATION_TOKEN_AUDIENCE,
                "tenant_id": str(tenant.id),
                "email": user_create.email,
                "fields": user_create.fields.model_dump(
                    mode="json", exclude_unset=True
                ),
                "oauth_account_id": str(registration_session.oauth_account_id)
                if registration_session.oauth_account_id is not None
                else None,
            }
            token = Fernet(settings.encryption_key).encrypt(
                json.dumps(payload).encode()
            )
            await self.user_manager.on_registration_confirmation_requested(
                tenant, user_create.email, token.decode(), request=request
            )
        else:
            await self.user_manager.on_existing_account_registration(
                user, request=request
            )

    def get_registration_token_payload(
        self, token: str, tenant: Tenant
    ) -> dict[str, Any]:
        try:
            payload = json.loads(
                Fernet(settings.encryption_key).decrypt(
                    token, ttl=settings.registration_confirmation_lifetime_seconds
                )
            )
        except (InvalidToken, ValueError) as e:
            raise InvalidRegistrationTokenError() from e

        if payload.get("aud") != REGISTRATION_TOKEN_AUDIENCE or payload.get(
            "tenant_id"
        ) != str(tenant.id):
            raise InvalidRegistrationTokenError()

        return payload

    async def confirm_registration(
        self,
        token: str,
        password: str,
        tenant: Tenant,
        registration_session: RegistrationSession | None,
        request: Request | None = None,
    ) -> User:
        """
        Create the account of a confirmed registration.

        The password is chosen by whoever opened the link, i.e. the owner of the email.
        The OAuth account is only linked in the browser which started the registration.
        """
        payload = self.get_registration_token_payload(token, tenant)

        user_create = self._get_user_create(
            {
                "email": payload["email"],
                "fields": payload["fields"],
                "password": password,
            },
            tenant,
        )
        user = await self.user_manager.create(user_create, tenant.id, request=request)
        user.email_verified = True
        await self.user_manager.user_repository.update(user)
        await self.user_manager.on_after_update(user, request=request)

        oauth_account = (
            registration_session.oauth_account
            if registration_session is not None
            else None
        )
        if (
            oauth_account is not None
            and str(oauth_account.id) == payload["oauth_account_id"]
            and oauth_account.user_id is None
        ):
            oauth_account.user = user
            await self.oauth_account_repository.update(oauth_account)

        return user

    async def create_user(
        self,
        data: dict[str, Any],
        tenant: Tenant,
        registration_session: RegistrationSession,
        request: Request | None = None,
    ) -> User:
        user_create = self._get_user_create(data, tenant)
        user = await self.user_manager.create(user_create, tenant.id, request=request)

        registration_session.email = user.email
        await self.registration_session_repository.update(registration_session)

        if registration_session.oauth_account is not None:
            registration_session.oauth_account.user = user
            await self.oauth_account_repository.update(
                registration_session.oauth_account
            )

        return user

    def _get_user_create(self, data: dict[str, Any], tenant: Tenant) -> UserCreate:
        user_create_dict: dict[str, Any] = {**data, "tenant_id": tenant.id}
        if "password" not in user_create_dict:
            user_create_dict["password"] = self.user_manager.password_helper.generate()
        return self.user_create_model(**user_create_dict)
