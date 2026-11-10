import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import call, patch

import pytest
from sqlalchemy.engine import URL
from typer.testing import CliRunner

from fief.cli.__main__ import app
from fief.cli.admin import chown_sqlite_database, engine
from fief.settings import settings

HELP_TIMEOUT_SECONDS = 60
HELP_WIDTH_COLUMNS = "200"


@pytest.mark.parametrize(
    "args,expected_output",
    [
        (["--help"], "Run the Fief server."),
        (["--help"], "Run the Fief worker."),
        (["run-server", "--help"], "migrate"),
        (["run-worker", "--help"], "--processes"),
    ],
)
def test_help(args: list[str], expected_output: str):
    result = subprocess.run(
        [sys.executable, "-m", "fief.cli", *args],
        capture_output=True,
        text=True,
        timeout=HELP_TIMEOUT_SECONDS,
        env={**os.environ, "COLUMNS": HELP_WIDTH_COLUMNS},
    )

    assert result.returncode == 0, result.stderr
    assert expected_output in result.stdout


def test_run_server_forwards_to_uvicorn():
    with patch("uvicorn.main.run") as uvicorn_run:
        result = CliRunner().invoke(
            app,
            [
                "run-server",
                "--host",
                "127.0.0.1",
                "--no-migrate",
                "--no-create-main-user",
                "--no-create-main-admin-api-key",
            ],
        )

    assert result.exit_code == 0, result.output
    uvicorn_run.assert_called_once()
    assert uvicorn_run.call_args.args == ("fief.app:app",)
    assert uvicorn_run.call_args.kwargs["host"] == "127.0.0.1"
    assert uvicorn_run.call_args.kwargs["port"] == settings.port


def test_run_worker_forwards_to_dramatiq():
    with patch("fief.cli.admin.dramatiq_cli.main") as dramatiq_main:
        result = CliRunner().invoke(app, ["run-worker", "-p", "1", "-t", "1"])

    assert result.exit_code == 0, result.output
    dramatiq_main.assert_called_once()
    dramatiq_args = dramatiq_main.call_args.args[0]
    assert dramatiq_args.broker == "fief.worker"
    assert dramatiq_args.processes == 1
    assert dramatiq_args.threads == 1


def test_info_masks_sensitive_settings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(settings, "database_password", "db-password-value")
    monkeypatch.setattr(settings, "fief_client_secret", "client-secret-value")
    monkeypatch.setattr(settings, "fief_encryption_key", "fief-encryption-key-value")
    monkeypatch.setattr(
        settings, "redis_url", "redis://user:redis-password-value@redis-host:6379"
    )
    monkeypatch.setattr(
        settings, "email_provider_params", {"api_key": "email-api-key-value"}
    )

    result = CliRunner().invoke(app, ["info"])

    assert result.exit_code == 0, result.output
    for secret_value in [
        "db-password-value",
        "client-secret-value",
        "fief-encryption-key-value",
        "redis-password-value",
        "email-api-key-value",
        settings.encryption_key.decode(),
        settings.secret.get_secret_value(),
    ]:
        assert secret_value not in result.output
    assert "redis_url: redis://user:**********@redis-host:6379" in result.output
    assert f"fief_client_id: {settings.fief_client_id}" in result.output
    assert f"port: {settings.port}" in result.output
    assert (
        "reset_password_token_lifetime_seconds: "
        f"{settings.reset_password_token_lifetime_seconds}"
    ) in result.output


class TestChownSQLiteDatabase:
    @pytest.fixture
    def sqlite_url(self, tmp_path: Path) -> URL:
        return URL.create("sqlite+aiosqlite", database=str(tmp_path / "fief.db"))

    def test_root_sqlite(self, tmp_path: Path, sqlite_url: URL):
        for name in ["fief.db", "fief.db-wal", "fief.db-shm"]:
            (tmp_path / name).touch()
        directory_stat = os.stat(tmp_path)

        with (
            patch("os.geteuid", return_value=0, create=True),
            patch("os.chown", create=True) as chown,
        ):
            chown_sqlite_database(sqlite_url)

        assert chown.call_args_list == [
            call(str(tmp_path / name), directory_stat.st_uid, directory_stat.st_gid)
            for name in ["fief.db", "fief.db-wal", "fief.db-shm"]
        ]

    def test_root_sqlite_missing_file(self, sqlite_url: URL):
        with (
            patch("os.geteuid", return_value=0, create=True),
            patch("os.chown", create=True) as chown,
        ):
            chown_sqlite_database(sqlite_url)

        chown.assert_not_called()

    def test_not_root(self, tmp_path: Path, sqlite_url: URL):
        (tmp_path / "fief.db").touch()

        with (
            patch("os.geteuid", return_value=1000, create=True),
            patch("os.chown", create=True) as chown,
        ):
            chown_sqlite_database(sqlite_url)

        chown.assert_not_called()

    def test_not_sqlite(self, tmp_path: Path):
        (tmp_path / "fief.db").touch()
        url = URL.create(
            "postgresql+asyncpg", host="localhost", database=str(tmp_path / "fief.db")
        )

        with (
            patch("os.geteuid", return_value=0, create=True),
            patch("os.chown", create=True) as chown,
        ):
            chown_sqlite_database(url)

        chown.assert_not_called()


def test_migrate_chowns_sqlite_database():
    with (
        patch("fief.cli.admin.migrate_schema") as migrate_schema,
        patch("fief.cli.admin.initializer.init_all") as init_all,
        patch("fief.cli.admin.chown_sqlite_database") as chown_sqlite_database,
    ):
        result = CliRunner().invoke(app, ["migrate"])

    assert result.exit_code == 0, result.output
    migrate_schema.assert_awaited_once()
    init_all.assert_awaited_once()
    chown_sqlite_database.assert_called_once_with(engine.url)
