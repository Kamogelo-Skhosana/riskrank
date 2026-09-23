"""Tests for the ZAP client wrapper, using a fake HTTP session (no live ZAP).

Ticket: R006
"""

import json

import pytest
import requests

from riskrank.config import ConfigError, Settings
from riskrank.scanner.zap_client import ZapClient, ZapConnectionError, ZapError


def make_response(status: int = 200, body: object = None, raw: str | None = None):
    response = requests.Response()
    response.status_code = status
    response._content = (raw if raw is not None else json.dumps(body)).encode()
    return response


class FakeSession(requests.Session):
    """Records requests and returns a canned response (or raises)."""

    def __init__(self, response=None, exc: Exception | None = None):
        super().__init__()
        self.response = response
        self.exc = exc
        self.calls: list[dict] = []

    def get(self, url, params=None, timeout=None, **kwargs):
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        if self.exc:
            raise self.exc
        return self.response


def make_client(session: FakeSession, api_url: str = "http://localhost:8080") -> ZapClient:
    return ZapClient(api_url=api_url, api_key="secret-key", timeout=5, session=session)


def test_check_connection_returns_version():
    session = FakeSession(make_response(body={"version": "2.16.0"}))
    assert make_client(session).check_connection() == "2.16.0"


def test_request_builds_json_api_url_and_sends_key_in_header():
    session = FakeSession(make_response(body={"version": "2.16.0"}))
    make_client(session, api_url="http://zap:8090/").get_version()

    [call] = session.calls
    assert call["url"] == "http://zap:8090/JSON/core/view/version/"  # trailing / handled
    assert call["timeout"] == 5
    assert session.headers["X-ZAP-API-Key"] == "secret-key"
    assert "apikey" not in (call["params"] or {})  # key never in the query string


@pytest.mark.parametrize("exc", [requests.ConnectionError("refused"), requests.Timeout("slow")])
def test_unreachable_zap_raises_connection_error(exc):
    client = make_client(FakeSession(exc=exc))
    with pytest.raises(ZapConnectionError, match="Is ZAP running"):
        client.check_connection()


def test_bad_api_key_gives_clear_message():
    body = {"code": "bad_api_key", "message": "Missing parameter"}
    client = make_client(FakeSession(make_response(status=400, body=body)))
    with pytest.raises(ZapError, match="ZAP_API_KEY"):
        client.check_connection()


def test_other_api_error_includes_code_and_message():
    body = {"code": "internal_error", "message": "Something broke"}
    client = make_client(FakeSession(make_response(status=500, body=body)))
    with pytest.raises(ZapError, match="HTTP 500, internal_error\\): Something broke"):
        client.check_connection()


def test_non_json_response_raises_zap_error():
    client = make_client(FakeSession(make_response(status=200, raw="<html>proxy page</html>")))
    with pytest.raises(ZapError, match="non-JSON"):
        client.check_connection()


def test_unexpected_version_payload_raises_zap_error():
    client = make_client(FakeSession(make_response(body={"nope": 1})))
    with pytest.raises(ZapError, match="Unexpected response"):
        client.get_version()


def test_connection_error_is_a_zap_error():
    """Callers can catch ZapError to handle every ZAP failure."""
    assert issubclass(ZapConnectionError, ZapError)


def _settings(**overrides) -> Settings:
    values = {
        "zap_api_url": "http://localhost:8080",
        "zap_api_key": "abc123",
        "llm_api_key": "",
        "llm_model": "claude-sonnet-4-6",
        "database_url": "sqlite:///./riskrank.db",
    }
    values.update(overrides)
    return Settings(**values)


def test_from_settings_builds_client():
    client = ZapClient.from_settings(_settings(zap_api_url="http://zap:8090"))
    assert client.api_url == "http://zap:8090"
    assert client.api_key == "abc123"


def test_from_settings_requires_zap_api_key():
    with pytest.raises(ConfigError, match="ZAP_API_KEY"):
        ZapClient.from_settings(_settings(zap_api_key=""))
