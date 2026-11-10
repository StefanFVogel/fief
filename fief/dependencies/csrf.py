import secrets

from fastapi import HTTPException, Request, status

from fief.middlewares.csrf import CSRF_FORM_FIELD_NAME, CSRF_HEADER_NAME, SAFE_METHODS
from fief.settings import settings


async def check_csrf_token(request: Request) -> None:
    if not settings.csrf_check_enabled or request.method in SAFE_METHODS:
        return

    csrf_token = request.headers.get(CSRF_HEADER_NAME)
    if csrf_token is None:
        form = await request.form()
        csrf_token = form.get(CSRF_FORM_FIELD_NAME)  # type: ignore[assignment]

    challenge_csrf_token = request.cookies.get(settings.csrf_cookie_name)
    if (
        not isinstance(csrf_token, str)
        or challenge_csrf_token is None
        or not secrets.compare_digest(
            csrf_token.encode(), challenge_csrf_token.encode()
        )
    ):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="CSRF failed."
        )
