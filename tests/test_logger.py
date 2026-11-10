import logging

import pytest

from fief.logger import init_logger, redact_access_log_query

ACCESS_LOG_FORMAT = '%s - "%s %s HTTP/%s" %d'


def _access_log_record(full_path: str) -> logging.LogRecord:
    return logging.LogRecord(
        "uvicorn.access",
        logging.INFO,
        __file__,
        0,
        ACCESS_LOG_FORMAT,
        ("127.0.0.1:50000", "GET", full_path, "1.1", 200),
        None,
    )


@pytest.mark.parametrize(
    "full_path,expected_path",
    [
        ("/reset?token=SECRET", "/reset?token=**********"),
        (
            "/callback?code=SECRET&state=SECRET&foo=bar",
            "/callback?code=**********&state=**********&foo=bar",
        ),
        (
            "/token?code_verifier=SECRET&id_token_hint=SECRET",
            "/token?code_verifier=**********&id_token_hint=**********",
        ),
        (
            "/authorize?code_challenge=abc&client_id=xyz",
            "/authorize?code_challenge=abc&client_id=xyz",
        ),
        ("/login", "/login"),
    ],
)
def test_redact_access_log_query(full_path: str, expected_path: str):
    record = _access_log_record(full_path)

    assert redact_access_log_query(record) is True
    message = record.getMessage()
    assert "SECRET" not in message
    assert message == f'127.0.0.1:50000 - "GET {expected_path} HTTP/1.1" 200'


def test_redact_access_log_query_ignores_other_records():
    record = logging.LogRecord(
        "uvicorn.access", logging.INFO, __file__, 0, "token=%s", ("SECRET",), None
    )

    assert redact_access_log_query(record) is True
    assert record.getMessage() == "token=SECRET"


def test_init_logger_adds_access_log_filter_once():
    init_logger()
    init_logger()

    access_logger = logging.getLogger("uvicorn.access")
    assert access_logger.filters.count(redact_access_log_query) == 1
