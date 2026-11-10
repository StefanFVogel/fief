import uuid
from datetime import UTC, datetime

import dramatiq

from fief import schemas
from fief.services.email_template.contexts import (
    ConfirmRegistrationContext,
    ExistingAccountRegistrationContext,
    WelcomeContext,
)
from fief.services.email_template.types import EmailTemplateType
from fief.tasks.base import TaskBase


class OnAfterRegisterTask(TaskBase):
    __name__ = "on_after_register"

    async def run(self, user_id: str):
        user = await self._get_user(uuid.UUID(user_id))
        tenant = await self._get_tenant(user.tenant_id)

        # Send welcome email
        context = WelcomeContext(
            tenant=schemas.tenant.Tenant.model_validate(tenant),
            user=schemas.user.UserEmailContext.model_validate(user),
        )
        async with self._get_email_subject_renderer() as email_subject_renderer:
            subject = await email_subject_renderer.render(
                EmailTemplateType.WELCOME, context
            )

        async with self._get_email_template_renderer() as email_template_renderer:
            html = await email_template_renderer.render(
                EmailTemplateType.WELCOME, context
            )

        self.email_provider.send_email(
            sender=tenant.get_email_sender(),
            recipient=(user.email, None),
            subject=subject,
            html=html,
        )


on_after_register = dramatiq.actor(OnAfterRegisterTask())


class OnRegistrationConfirmationRequestedTask(TaskBase):
    __name__ = "on_registration_confirmation_requested"

    async def run(self, tenant_id: str, email: str, confirm_url: str):
        tenant = await self._get_tenant(uuid.UUID(tenant_id))

        # The user doesn't exist yet: describe the account that will be created
        now = datetime.now(UTC)
        context = ConfirmRegistrationContext(
            tenant=schemas.tenant.Tenant.model_validate(tenant),
            user=schemas.user.UserEmailContext(
                id=uuid.uuid4(),
                email=email,
                tenant_id=tenant.id,
                fields={},
                created_at=now,
                updated_at=now,
            ),
            confirm_url=confirm_url,
        )
        async with self._get_email_subject_renderer() as email_subject_renderer:
            subject = await email_subject_renderer.render(
                EmailTemplateType.CONFIRM_REGISTRATION, context
            )

        async with self._get_email_template_renderer() as email_template_renderer:
            html = await email_template_renderer.render(
                EmailTemplateType.CONFIRM_REGISTRATION, context
            )

        self.email_provider.send_email(
            sender=tenant.get_email_sender(),
            recipient=(email, None),
            subject=subject,
            html=html,
        )


on_registration_confirmation_requested = dramatiq.actor(
    OnRegistrationConfirmationRequestedTask()
)


class OnExistingAccountRegistrationTask(TaskBase):
    __name__ = "on_existing_account_registration"

    async def run(self, user_id: str, login_url: str, forgot_password_url: str):
        user = await self._get_user(uuid.UUID(user_id))
        tenant = await self._get_tenant(user.tenant_id)

        context = ExistingAccountRegistrationContext(
            tenant=schemas.tenant.Tenant.model_validate(tenant),
            user=schemas.user.UserEmailContext.model_validate(user),
            login_url=login_url,
            forgot_password_url=forgot_password_url,
        )
        async with self._get_email_subject_renderer() as email_subject_renderer:
            subject = await email_subject_renderer.render(
                EmailTemplateType.EXISTING_ACCOUNT_REGISTRATION, context
            )

        async with self._get_email_template_renderer() as email_template_renderer:
            html = await email_template_renderer.render(
                EmailTemplateType.EXISTING_ACCOUNT_REGISTRATION, context
            )

        self.email_provider.send_email(
            sender=tenant.get_email_sender(),
            recipient=(user.email, None),
            subject=subject,
            html=html,
        )


on_existing_account_registration = dramatiq.actor(OnExistingAccountRegistrationTask())
