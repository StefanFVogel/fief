from unittest.mock import MagicMock

import pytest

from fief.services.email import EmailProvider
from fief.tasks.register import (
    OnAfterRegisterTask,
    OnExistingAccountRegistrationTask,
    OnRegistrationConfirmationRequestedTask,
)
from tests.data import TestData


@pytest.mark.asyncio
class TestTasksOnAfterRegister:
    async def test_send_welcome_email(self, main_session_manager, test_data: TestData):
        email_provider_mock = MagicMock(spec=EmailProvider)

        on_after_register = OnAfterRegisterTask(
            main_session_manager, email_provider_mock
        )

        user = test_data["users"]["regular"]
        await on_after_register.run(str(user.id))

        email_provider_mock.send_email.assert_called_once()


@pytest.mark.asyncio
class TestTasksOnRegistrationConfirmationRequested:
    async def test_send_confirmation_email(
        self, main_session_manager, test_data: TestData
    ):
        email_provider_mock = MagicMock(spec=EmailProvider)

        on_registration_confirmation_requested = (
            OnRegistrationConfirmationRequestedTask(
                main_session_manager, email_provider_mock
            )
        )

        tenant = test_data["tenants"]["default"]
        await on_registration_confirmation_requested.run(
            str(tenant.id),
            "louis@bretagne.duchy",
            "https://bretagne.fief.dev/register/confirm?token=AAA",
        )

        email_provider_mock.send_email.assert_called_once()
        kwargs = email_provider_mock.send_email.call_args.kwargs
        assert kwargs["recipient"] == ("louis@bretagne.duchy", None)
        assert (
            "CONFIRM_REGISTRATION https://bretagne.fief.dev/register/confirm?token=AAA"
            in kwargs["html"]
        )


@pytest.mark.asyncio
class TestTasksOnExistingAccountRegistration:
    async def test_send_existing_account_email(
        self, main_session_manager, test_data: TestData
    ):
        email_provider_mock = MagicMock(spec=EmailProvider)

        on_existing_account_registration = OnExistingAccountRegistrationTask(
            main_session_manager, email_provider_mock
        )

        user = test_data["users"]["regular"]
        await on_existing_account_registration.run(
            str(user.id),
            "https://bretagne.fief.dev/login",
            "https://bretagne.fief.dev/forgot",
        )

        email_provider_mock.send_email.assert_called_once()
        kwargs = email_provider_mock.send_email.call_args.kwargs
        assert kwargs["recipient"] == (user.email, None)
        assert (
            "EXISTING_ACCOUNT_REGISTRATION https://bretagne.fief.dev/login https://bretagne.fief.dev/forgot"
            in kwargs["html"]
        )
