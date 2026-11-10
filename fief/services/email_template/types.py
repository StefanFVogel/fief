from enum import StrEnum


class EmailTemplateType(StrEnum):
    BASE = "BASE"
    WELCOME = "WELCOME"
    VERIFY_EMAIL = "VERIFY_EMAIL"
    FORGOT_PASSWORD = "FORGOT_PASSWORD"
    CONFIRM_REGISTRATION = "CONFIRM_REGISTRATION"
    EXISTING_ACCOUNT_REGISTRATION = "EXISTING_ACCOUNT_REGISTRATION"

    def get_display_name(self) -> str:
        display_names = {
            EmailTemplateType.BASE: "Base",
            EmailTemplateType.WELCOME: "Welcome",
            EmailTemplateType.VERIFY_EMAIL: "Verify email",
            EmailTemplateType.FORGOT_PASSWORD: "Forgot password",
            EmailTemplateType.CONFIRM_REGISTRATION: "Confirm registration",
            EmailTemplateType.EXISTING_ACCOUNT_REGISTRATION: "Registration with an existing account",
        }
        return display_names[self]
