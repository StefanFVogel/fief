import re
from urllib.parse import urlparse

from wtforms import validators

from fief.services.localhost import is_localhost
from fief.services.webhooks.target import is_allowed_host
from fief.settings import settings


class NotHTTPSURLValidationError(validators.ValidationError):
    def __init__(self):
        super().__init__("An HTTPS URL is required.")


class InternalWebhookURLValidationError(validators.ValidationError):
    def __init__(self):
        super().__init__("Webhook URLs can't point to an internal address.")


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


class WebhookURLValidator:
    def __call__(self, form, field):
        try:
            host = urlparse(field.data).hostname
        except ValueError:
            return
        if host is not None and not is_allowed_host(host):
            raise InternalWebhookURLValidationError()
