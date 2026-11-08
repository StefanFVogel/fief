import os
import subprocess
import sys
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from fief.cli.__main__ import app
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
