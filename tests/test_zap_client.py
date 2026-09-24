"""Tests for the ZAP client wrapper, using a fake HTTP session (no live ZAP).

Tickets: R006, R007, R008, R009, R010
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

    Pass one response, or a list to return them one per call. List items
    that are exceptions are raised instead of returned.
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
        item = self.responses.pop(0) if len(self.responses) > 1 else self.responses[0]
        if isinstance(item, Exception):
            raise item
        return item


def make_client(
    session: FakeSession, api_url: str = "http://localhost:8080", **kwargs
) -> ZapClient:
    kwargs.setdefault("sleep", lambda seconds: None)  # never really wait between retries
    return ZapClient(api_url=api_url, api_key="secret-key", timeout=5, session=session, **kwargs)


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


# --- R008: active scan -------------------------------------------------------


def test_start_active_scan_sends_target_recursively_and_returns_scan_id():
    session = FakeSession(make_response(body={"scan": "4"}))
    scan_id = make_client(session).start_active_scan("http://localhost:3000")

    assert scan_id == "4"
    [call] = session.calls
    assert call["url"] == "http://localhost:8080/JSON/ascan/action/scan/"
    assert call["params"] == {"url": "http://localhost:3000", "recurse": "true"}


def test_poll_active_scan_returns_percentage():
    session = FakeSession(make_response(body={"status": "72"}))
    assert make_client(session).poll_active_scan("4") == 72
    assert session.calls[0]["url"].endswith("/JSON/ascan/view/status/")
    assert session.calls[0]["params"] == {"scanId": "4"}


def test_poll_active_scan_non_numeric_status_raises():
    session = FakeSession(make_response(body={"status": "does_not_exist"}))
    with pytest.raises(ZapError, match="ascan/view/status"):
        make_client(session).poll_active_scan("4")


def test_start_active_scan_zap_error_propagates():
    """E.g. ZAP refuses to scan a URL it hasn't seen (spider not run first)."""
    body = {"code": "url_not_found", "message": "URL Not Found in the Scan Tree"}
    session = FakeSession(make_response(status=400, body=body))
    with pytest.raises(ZapError, match="url_not_found"):
        make_client(session).start_active_scan("http://localhost:3000")


def test_run_active_scan_polls_until_complete_and_reports_progress():
    session = FakeSession(
        [
            make_response(body={"scan": "4"}),
            make_response(body={"status": "5"}),
            make_response(body={"status": "50"}),
            make_response(body={"status": "100"}),
        ]
    )
    clock = FakeClock()
    progress: list[int] = []

    scan_id = make_client(session).run_active_scan(
        "http://localhost:3000",
        poll_interval=3,
        on_progress=progress.append,
        sleep=clock.sleep,
        clock=clock,
    )

    assert scan_id == "4"
    assert progress == [5, 50, 100]
    assert clock.sleeps == [3, 3]


def test_run_active_scan_times_out():
    session = FakeSession([make_response(body={"scan": "4"}), make_response(body={"status": "30"})])
    clock = FakeClock()

    with pytest.raises(ZapScanTimeoutError, match="active scan 4 did not finish within 10s"):
        make_client(session).run_active_scan(
            "http://localhost:3000", poll_interval=4, timeout=10, sleep=clock.sleep, clock=clock
        )


# --- R009: alerts ------------------------------------------------------------


def _alert(n: int) -> dict:
    return {"alert": f"Alert {n}", "risk": "Low", "url": f"http://localhost:3000/p{n}"}


def test_get_alerts_single_page(sample_raw_zap_alert):
    session = FakeSession(make_response(body={"alerts": [sample_raw_zap_alert]}))
    alerts = make_client(session).get_alerts("http://localhost:3000")

    assert alerts == [sample_raw_zap_alert]
    [call] = session.calls
    assert call["url"] == "http://localhost:8080/JSON/core/view/alerts/"
    assert call["params"] == {"baseurl": "http://localhost:3000", "start": 0, "count": 500}


def test_get_alerts_no_alerts():
    session = FakeSession(make_response(body={"alerts": []}))
    assert make_client(session).get_alerts("http://localhost:3000") == []


def test_get_alerts_combines_multiple_pages():
    session = FakeSession(
        [
            make_response(body={"alerts": [_alert(1), _alert(2)]}),
            make_response(body={"alerts": [_alert(3), _alert(4)]}),
            make_response(body={"alerts": [_alert(5)]}),
        ]
    )
    alerts = make_client(session).get_alerts("http://localhost:3000", page_size=2)

    assert [a["alert"] for a in alerts] == [f"Alert {n}" for n in range(1, 6)]
    assert [c["params"]["start"] for c in session.calls] == [0, 2, 4]


def test_get_alerts_exact_multiple_of_page_size_stops_on_empty_page():
    session = FakeSession(
        [
            make_response(body={"alerts": [_alert(1), _alert(2)]}),
            make_response(body={"alerts": []}),
        ]
    )
    alerts = make_client(session).get_alerts("http://localhost:3000", page_size=2)
    assert len(alerts) == 2
    assert len(session.calls) == 2


def test_get_alerts_unexpected_payload_raises():
    session = FakeSession(make_response(body={"nope": []}))
    with pytest.raises(ZapError, match="core/view/alerts"):
        make_client(session).get_alerts("http://localhost:3000")


def test_get_alerts_rejects_invalid_page_size():
    with pytest.raises(ValueError, match="page_size"):
        make_client(FakeSession()).get_alerts("http://localhost:3000", page_size=0)


def test_get_alerts_output_feeds_normalizer(sample_raw_zap_alert):
    """End of Phase 1 scanner chain: ZAP alerts -> Finding objects."""
    from riskrank.scanner.normalizer import normalize_alerts

    session = FakeSession(make_response(body={"alerts": [sample_raw_zap_alert]}))
    [finding] = normalize_alerts(make_client(session).get_alerts("http://localhost:3000"))
    assert finding.type == "SQL Injection"
    assert finding.endpoint == "/api/login"


# --- R010: retries -------------------------------------------------------------


class RecordingSleep:
    def __init__(self):
        self.delays: list[float] = []

    def __call__(self, seconds: float) -> None:
        self.delays.append(seconds)


VERSION_OK = {"version": "2.16.0"}


def test_view_retries_connection_error_then_succeeds():
    session = FakeSession(
        [
            requests.ConnectionError("refused"),
            requests.ConnectionError("refused"),
            make_response(body=VERSION_OK),
        ]
    )
    sleep = RecordingSleep()
    assert make_client(session, sleep=sleep).get_version() == "2.16.0"
    assert len(session.calls) == 3
    assert sleep.delays == [1.0, 2.0]  # exponential backoff


def test_view_retries_read_timeout():
    session = FakeSession([requests.ReadTimeout("slow"), make_response(body=VERSION_OK)])
    assert make_client(session).get_version() == "2.16.0"
    assert len(session.calls) == 2


@pytest.mark.parametrize("status", [502, 503, 504])
def test_retryable_status_then_success(status):
    session = FakeSession(
        [make_response(status=status, raw="Bad Gateway"), make_response(body=VERSION_OK)]
    )
    assert make_client(session).get_version() == "2.16.0"
    assert len(session.calls) == 2


def test_gives_up_after_max_retries_on_connection_error():
    session = FakeSession(exc=requests.ConnectionError("refused"))
    sleep = RecordingSleep()
    with pytest.raises(ZapConnectionError, match="after 4 attempt.*Is ZAP running"):
        make_client(session, sleep=sleep, max_retries=3).get_version()
    assert len(session.calls) == 4
    assert sleep.delays == [1.0, 2.0, 4.0]


def test_gives_up_after_max_retries_on_retryable_status():
    body = {"code": "internal_error", "message": "overloaded"}
    session = FakeSession(make_response(status=503, body=body))
    with pytest.raises(ZapError, match="HTTP 503"):
        make_client(session, max_retries=2).get_version()
    assert len(session.calls) == 3


def test_non_retryable_status_fails_immediately():
    body = {"code": "bad_api_key", "message": ""}
    session = FakeSession(make_response(status=400, body=body))
    with pytest.raises(ZapError, match="ZAP_API_KEY"):
        make_client(session).get_version()
    assert len(session.calls) == 1


def test_action_retries_when_request_never_reached_zap():
    session = FakeSession([requests.ConnectTimeout("no route"), make_response(body={"scan": "1"})])
    assert make_client(session).start_spider("http://localhost:3000") == "1"
    assert len(session.calls) == 2


def test_action_read_timeout_is_not_retried():
    """ZAP may have started the scan already; retrying could launch a duplicate."""
    session = FakeSession([requests.ReadTimeout("slow"), make_response(body={"scan": "1"})])
    with pytest.raises(ZapConnectionError, match="ReadTimeout after 1 attempt"):
        make_client(session).start_active_scan("http://localhost:3000")
    assert len(session.calls) == 1


def test_zero_retries_disables_retrying():
    session = FakeSession(exc=requests.ConnectionError("refused"))
    with pytest.raises(ZapConnectionError):
        make_client(session, max_retries=0).get_version()
    assert len(session.calls) == 1


def test_negative_max_retries_rejected():
    with pytest.raises(ValueError, match="max_retries"):
        make_client(FakeSession(), max_retries=-1)


def test_retry_logs_warning(caplog):
    session = FakeSession([requests.ConnectionError("refused"), make_response(body=VERSION_OK)])
    with caplog.at_level("WARNING", logger="riskrank.scanner.zap_client"):
        make_client(session).get_version()
    assert "core/view/version failed (ConnectionError), retrying in 1.0s" in caplog.text


# --- Busy ZAP during scans -----------------------------------------------------


def test_read_timeout_message_says_zap_is_busy_not_down():
    session = FakeSession(exc=requests.ReadTimeout("slow"))
    with pytest.raises(ZapConnectionError) as exc:
        make_client(session, max_retries=0).get_version()
    message = str(exc.value)
    assert "is running but did not respond within 5s" in message
    assert "Is ZAP running?" not in message


def test_scan_keeps_waiting_while_zap_is_too_busy_to_answer(caplog):
    """Regression: a Juice Shop active scan died at 34% because status checks
    timed out while ZAP was busy. Polling must ride that out."""
    busy = requests.ReadTimeout("busy")
    session = FakeSession(
        [
            make_response(body={"scan": "4"}),
            make_response(body={"status": "34"}),
            busy,  # one poll = 1 try + 3 retries, all timing out
            busy,
            busy,
            busy,
            make_response(body={"status": "80"}),
            make_response(body={"status": "100"}),
        ]
    )
    clock = FakeClock()
    progress: list[int] = []

    with caplog.at_level("WARNING", logger="riskrank.scanner.zap_client"):
        scan_id = make_client(session).run_active_scan(
            "http://localhost:3000",
            poll_interval=2,
            on_progress=progress.append,
            sleep=clock.sleep,
            clock=clock,
        )

    assert scan_id == "4"
    assert progress == [34, 80, 100]
    assert "still waiting (last progress: 34%)" in caplog.text


def test_scan_gives_up_when_zap_stays_unresponsive():
    session = FakeSession(
        [
            make_response(body={"scan": "4"}),
            make_response(body={"status": "34"}),
            requests.ReadTimeout("busy"),  # repeated for every later call
        ]
    )
    clock = FakeClock()

    with pytest.raises(ZapConnectionError, match="stopped responding during active scan 4"):
        make_client(session).run_active_scan(
            "http://localhost:3000",
            poll_interval=10,
            unresponsive_timeout=60,
            sleep=clock.sleep,
            clock=clock,
        )
    assert clock.now >= 60


def test_unresponsive_timer_resets_after_a_successful_poll():
    busy = requests.ReadTimeout("busy")
    # Each busy poll consumes 4 calls (1 try + 3 retries).
    responses = [make_response(body={"scan": "4"})]
    for status in ("10", "20", "30"):
        responses += [busy] * 4 * 3  # 3 failed polls = 30s unresponsive
        responses.append(make_response(body={"status": status}))
    responses.append(make_response(body={"status": "100"}))
    clock = FakeClock()

    scan_id = make_client(FakeSession(responses)).run_active_scan(
        "http://localhost:3000",
        poll_interval=10,
        unresponsive_timeout=35,  # never exceeded, because it resets each time
        sleep=clock.sleep,
        clock=clock,
    )
    assert scan_id == "4"


def test_non_connection_error_during_poll_still_fails_immediately():
    body = {"code": "does_not_exist", "message": "scan gone"}
    session = FakeSession([make_response(body={"scan": "4"}), make_response(status=400, body=body)])
    clock = FakeClock()
    with pytest.raises(ZapError, match="does_not_exist"):
        make_client(session).run_active_scan(
            "http://localhost:3000", sleep=clock.sleep, clock=clock
        )


# --- Stopping scans after riskrank's time limit ----------------------------------------


@pytest.mark.parametrize(
    ("method", "endpoint"),
    [
        ("stop_spider", "/JSON/spider/action/stop/"),
        ("stop_active_scan", "/JSON/ascan/action/stop/"),
    ],
)
def test_stop_methods_call_zap(method, endpoint):
    session = FakeSession(make_response(body={"Result": "OK"}))
    getattr(make_client(session), method)("7")
    [call] = session.calls
    assert call["url"].endswith(endpoint)
    assert call["params"] == {"scanId": "7"}


def test_timeout_error_carries_scan_id_and_progress():
    session = FakeSession([make_response(body={"scan": "9"}), make_response(body={"status": "55"})])
    clock = FakeClock()
    with pytest.raises(ZapScanTimeoutError) as exc:
        make_client(session).run_active_scan(
            "http://localhost:3000", poll_interval=5, timeout=10, sleep=clock.sleep, clock=clock
        )
    assert exc.value.scan_id == "9"
    assert exc.value.progress == 55
