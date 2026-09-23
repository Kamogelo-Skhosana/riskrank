"""Tests for the ZAP client wrapper, using a fake HTTP session (no live ZAP).

Tickets: R006, R007
"""

import json

import pytest
import requests

from riskrank.config import ConfigError, Settings
from riskrank.scanner.zap_client import (
    ZapClient,
    ZapConnectionError,
    ZapError,
    ZapScanTimeoutError,
)


def make_response(status: int = 200, body: object = None, raw: str | None = None):
    response = requests.Response()
    response.status_code = status
    response._content = (raw if raw is not None else json.dumps(body)).encode()
    return response


class FakeSession(requests.Session):
    """Records requests and returns canned responses in order (or raises).

    Pass one response, or a list to return them one per call.
    """

    def __init__(self, response=None, exc: Exception | None = None):
        super().__init__()
        self.responses = list(response) if isinstance(response, list) else [response]
        self.exc = exc
        self.calls: list[dict] = []

    def get(self, url, params=None, timeout=None, **kwargs):
        self.calls.append({"url": url, "params": params, "timeout": timeout})
        if self.exc:
            raise self.exc
        if len(self.responses) > 1:
            return self.responses.pop(0)
        return self.responses[0]


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


# --- R007: spider ------------------------------------------------------------


class FakeClock:
    """Deterministic clock + sleep so polling tests run instantly."""

    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def test_start_spider_sends_target_and_returns_scan_id():
    session = FakeSession(make_response(body={"scan": "3"}))
    scan_id = make_client(session).start_spider("http://localhost:3000")

    assert scan_id == "3"
    [call] = session.calls
    assert call["url"] == "http://localhost:8080/JSON/spider/action/scan/"
    assert call["params"] == {"url": "http://localhost:3000"}


def test_poll_spider_returns_percentage():
    session = FakeSession(make_response(body={"status": "45"}))
    assert make_client(session).poll_spider("3") == 45
    assert session.calls[0]["url"].endswith("/JSON/spider/view/status/")
    assert session.calls[0]["params"] == {"scanId": "3"}


@pytest.mark.parametrize(("raw", "expected"), [("-5", 0), ("150", 100), ("100", 100)])
def test_poll_spider_clamps_to_0_100(raw, expected):
    session = FakeSession(make_response(body={"status": raw}))
    assert make_client(session).poll_spider("3") == expected


def test_poll_spider_non_numeric_status_raises():
    session = FakeSession(make_response(body={"status": "does_not_exist"}))
    with pytest.raises(ZapError, match="non-numeric"):
        make_client(session).poll_spider("3")


def test_start_spider_unexpected_payload_raises():
    session = FakeSession(make_response(body={"oops": 1}))
    with pytest.raises(ZapError, match="spider/action/scan"):
        make_client(session).start_spider("http://localhost:3000")


def test_run_spider_polls_until_complete_and_reports_progress():
    session = FakeSession(
        [
            make_response(body={"scan": "7"}),
            make_response(body={"status": "0"}),
            make_response(body={"status": "60"}),
            make_response(body={"status": "100"}),
        ]
    )
    clock = FakeClock()
    progress: list[int] = []

    scan_id = make_client(session).run_spider(
        "http://localhost:3000",
        poll_interval=2,
        on_progress=progress.append,
        sleep=clock.sleep,
        clock=clock,
    )

    assert scan_id == "7"
    assert progress == [0, 60, 100]
    assert clock.sleeps == [2, 2]  # no sleep after the final 100%
    assert len(session.calls) == 4


def test_run_spider_times_out():
    session = FakeSession([make_response(body={"scan": "7"}), make_response(body={"status": "10"})])
    clock = FakeClock()

    with pytest.raises(ZapScanTimeoutError, match="spider 7 did not finish within 5s"):
        make_client(session).run_spider(
            "http://localhost:3000", poll_interval=2, timeout=5, sleep=clock.sleep, clock=clock
        )
    assert clock.now >= 5


def test_timeout_error_is_a_zap_error():
    assert issubclass(ZapScanTimeoutError, ZapError)
