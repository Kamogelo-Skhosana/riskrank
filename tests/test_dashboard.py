"""Tests for the dashboard API (in-process; no server or network).

Tickets: R035-R038
"""

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from riskrank import __version__, cli
from riskrank.cli import app as cli_app
from riskrank.config import ConfigError, Settings
from riskrank.dashboard.api import create_app


@pytest.fixture
def db_url(tmp_path):
    return f"sqlite:///{tmp_path / 'riskrank.db'}"


@pytest.fixture
def client(db_url):
    with TestClient(create_app(db_url)) as client:  # runs startup/shutdown
        yield client


# --- R035: app skeleton ------------------------------------------------------------


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_startup_creates_the_database_tables(client, tmp_path):
    assert (tmp_path / "riskrank.db").is_file()


def test_default_database_comes_from_settings(monkeypatch, tmp_path):
    url = f"sqlite:///{tmp_path / 'from-settings.db'}"
    settings = Settings("http://zap", "", "", "m", url)
    monkeypatch.setattr("riskrank.dashboard.api.load_settings", lambda: settings)
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
    assert (tmp_path / "from-settings.db").is_file()


def test_openapi_docs_are_served(client):
    assert client.get("/docs").status_code == 200
    schema = client.get("/openapi.json").json()
    assert schema["info"]["title"] == "riskrank dashboard"
    assert {"/health", "/scans", "/scans/trend", "/scans/{scan_id}"} <= set(schema["paths"])


@pytest.mark.parametrize(
    ("path", "ticket"),
    [("/scans", "R036"), ("/scans/1", "R037"), ("/scans/trend", "R038")],
)
def test_unfinished_endpoints_return_501(client, path, ticket):
    """/scans/trend must reach its own handler, not /scans/{scan_id} (route order)."""
    response = client.get(path)
    assert response.status_code == 501
    assert ticket in response.json()["detail"]


def test_health_reports_database_errors(client):
    client.app.state.engine.dispose()

    class BrokenSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, *args):
            from sqlalchemy.exc import OperationalError

            raise OperationalError("SELECT 1", {}, Exception("disk I/O error"))

    client.app.state.session_factory = BrokenSession
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Database unavailable"


# --- R035: `riskrank serve` ---------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def uvicorn_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **kw: calls.append((a, kw)))
    settings = Settings("http://zap", "", "", "m", "sqlite:///x.db")
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    return calls


def test_serve_runs_the_app_factory_with_defaults(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve"])
    assert result.exit_code == 0, result.output
    [(args, kwargs)] = uvicorn_calls
    assert args == ("riskrank.dashboard.api:create_app",)
    assert kwargs == {"factory": True, "host": "127.0.0.1", "port": 8000, "reload": False}
    assert "riskrank dashboard: http://localhost:8000" in result.output
    assert "Warning" not in result.output


def test_serve_options_override_settings(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve", "--host", "localhost", "--port", "9000", "--reload"])
    assert result.exit_code == 0, result.output
    [(_, kwargs)] = uvicorn_calls
    assert kwargs["host"] == "localhost" and kwargs["port"] == 9000 and kwargs["reload"]


def test_serve_warns_when_exposed_to_the_network(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code == 0
    assert "reachable from other machines" in result.output
    assert "http://localhost:8000" in result.output


def test_serve_rejects_invalid_port(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve", "--port", "70000"])
    assert result.exit_code != 0
    assert uvicorn_calls == []


def test_serve_config_error(monkeypatch):
    def bad():
        raise ConfigError("Invalid DASHBOARD_PORT: 'abc'.")

    monkeypatch.setattr(cli, "load_settings", bad)
    result = runner.invoke(cli_app, ["serve"])
    assert result.exit_code == cli.EXIT_CONFIG_ERROR
    assert "DASHBOARD_PORT" in result.output
