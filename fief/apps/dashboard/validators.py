import re

from wtforms import validators

from fief.models.theme import FONT_FAMILY_ALLOWED_CHARACTERS
from fief.services.localhost import is_localhost
from fief.settings import settings


class NotHTTPSURLValidationError(validators.ValidationError):
    def __init__(self):
        super().__init__("An HTTPS URL is required.")


class RedirectURLValidator(validators.Regexp):
    def __init__(self, message=None):
        regex = (
            r"^(?P<scheme>[a-z]+)://"
            r"(?P<host>[^\/\?:]+)"
            r"(?P<port>:[0-9]+)?"
            r"(?P<path>\/.*?)?"
            r"(?P<query>\?.*)?$"
        )
        super().__init__(regex, re.IGNORECASE, message)

    def __call__(self, form, field):
        message = self.message
        if message is None:
            message = "Invalid URL."

        match = super().__call__(form, field, message)
        scheme = match.group("scheme")
        host = match.group("host")

        if (
            settings.client_redirect_uri_ssl_required
            and scheme == "http"
            and not is_localhost(host)
        ):
            raise NotHTTPSURLValidationError()


class CSSColorValidator(validators.Regexp):
    def __init__(self, message=None):
        regex = r"^#([0-9a-f]{3,4}|[0-9a-f]{6}|[0-9a-f]{8})\Z"
        super().__init__(regex, re.IGNORECASE, message or "Invalid color.")


class FontFamilyValidator(validators.Regexp):
    def __init__(self, message=None):
        regex = rf"^[{FONT_FAMILY_ALLOWED_CHARACTERS}]+\Z"
        super().__init__(
            regex,
            0,
            message
            or "Only letters, digits, spaces, commas, quotes and hyphens are allowed.",
        )


class FontCSSURLValidator(validators.Regexp):
    def __init__(self, message=None):
        regex = r"^https?://[^\s'\"()\\]+\Z"
        super().__init__(regex, re.IGNORECASE, message or "Invalid URL.")
