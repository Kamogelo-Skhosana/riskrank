"""Tests for the LLM client wrapper (no live API calls).

Ticket: R022
"""

from types import SimpleNamespace

import anthropic
import httpx2
import pytest

from riskrank.config import ConfigError, Settings
from riskrank.triage.llm_client import LLMClient, LLMError, RateLimiter

REQUEST = httpx2.Request("POST", "https://api.anthropic.com/v1/messages")


def api_error(cls, status: int, headers: dict | None = None):
    response = httpx2.Response(status, request=REQUEST, headers=headers or {})
    return cls("error", response=response, body={"error": {"message": "error"}})


def text_response(text: str, stop_reason: str = "end_turn"):
    return SimpleNamespace(
        content=[SimpleNamespace(type="text", text=text)], stop_reason=stop_reason
    )


class FakeMessages:
    """Returns (or raises) the queued outcomes in order; records requests."""

    def __init__(self, outcomes):
        self.outcomes = list(outcomes)
        self.requests: list[dict] = []

    def create(self, **kwargs):
        self.requests.append(kwargs)
        outcome = self.outcomes.pop(0) if len(self.outcomes) > 1 else self.outcomes[0]
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


class FakeClock:
    def __init__(self):
        self.now = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        self.sleeps.append(seconds)
        self.now += seconds


def make_llm(outcomes, **kwargs):
    messages = FakeMessages(outcomes)
    clock = FakeClock()
    kwargs.setdefault("requests_per_minute", 60_000)  # effectively no rate limit
    llm = LLMClient(
        api_key="test-key",
        model="test-model",
        client=SimpleNamespace(messages=messages),
        sleep=clock.sleep,
        clock=clock,
        **kwargs,
    )
    return llm, messages, clock


# --- happy path ------------------------------------------------------------------


def test_complete_returns_text_and_sends_expected_request():
    llm, messages, _ = make_llm([text_response('{"ok": true}')], max_tokens=500)
    assert llm.complete("Score this finding") == '{"ok": true}'

    [request] = messages.requests
    assert request["model"] == "test-model"
    assert request["max_tokens"] == 500
    assert request["messages"] == [{"role": "user", "content": "Score this finding"}]
    assert "system" not in request


def test_system_prompt_is_passed_when_given():
    llm, messages, _ = make_llm([text_response("hi")])
    llm.complete("prompt", system="You are a security reviewer.")
    assert messages.requests[0]["system"] == "You are a security reviewer."


def test_multiple_text_blocks_are_joined_and_other_blocks_ignored():
    response = SimpleNamespace(
        content=[
            SimpleNamespace(type="thinking", thinking="..."),
            SimpleNamespace(type="text", text="part 1 "),
            SimpleNamespace(type="text", text="part 2"),
        ],
        stop_reason="end_turn",
    )
    llm, _, _ = make_llm([response])
    assert llm.complete("p") == "part 1 part 2"


def test_empty_response_raises():
    llm, _, _ = make_llm([text_response("   ")])
    with pytest.raises(LLMError, match="empty response"):
        llm.complete("p")


def test_truncated_response_logs_warning(caplog):
    llm, _, _ = make_llm([text_response("partial", stop_reason="max_tokens")])
    with caplog.at_level("WARNING", logger="riskrank.triage.llm_client"):
        assert llm.complete("p") == "partial"
    assert "cut off at max_tokens" in caplog.text


# --- retries ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "error",
    [
        api_error(anthropic.RateLimitError, 429),
        api_error(anthropic.InternalServerError, 500),
        api_error(anthropic.OverloadedError, 529),
        anthropic.APIConnectionError(request=REQUEST),
        anthropic.APITimeoutError(request=REQUEST),
        api_error(anthropic.APIStatusError, 503),
        api_error(anthropic.APIStatusError, 408),
    ],
    ids=["429", "500", "529", "connection", "timeout", "503", "408"],
)
def test_transient_errors_are_retried(error):
    llm, messages, clock = make_llm([error, text_response("done")])
    assert llm.complete("p") == "done"
    assert len(messages.requests) == 2
    assert clock.sleeps == [2.0]


def test_backoff_is_exponential_and_gives_up_after_max_retries():
    llm, messages, clock = make_llm([api_error(anthropic.InternalServerError, 500)], max_retries=3)
    with pytest.raises(LLMError, match=r"HTTP 500.*after 4 attempt"):
        llm.complete("p")
    assert len(messages.requests) == 4
    assert clock.sleeps == [2.0, 4.0, 8.0]


def test_retry_after_header_is_honoured():
    error = api_error(anthropic.RateLimitError, 429, headers={"retry-after": "15"})
    llm, _, clock = make_llm([error, text_response("done")])
    llm.complete("p")
    assert clock.sleeps == [15.0]


def test_retry_after_is_capped():
    error = api_error(anthropic.RateLimitError, 429, headers={"retry-after": "3600"})
    llm, _, clock = make_llm([error, text_response("done")])
    llm.complete("p")
    assert clock.sleeps == [60.0]


def test_invalid_retry_after_falls_back_to_backoff():
    error = api_error(anthropic.RateLimitError, 429, headers={"retry-after": "soon"})
    llm, _, clock = make_llm([error, text_response("done")])
    llm.complete("p")
    assert clock.sleeps == [2.0]


def test_rate_limit_exhausted_message():
    llm, _, _ = make_llm([api_error(anthropic.RateLimitError, 429)], max_retries=1)
    with pytest.raises(LLMError, match="rate limit still exceeded after 2 attempt"):
        llm.complete("p")


def test_connection_exhausted_message():
    llm, _, _ = make_llm([anthropic.APIConnectionError(request=REQUEST)], max_retries=0)
    with pytest.raises(LLMError, match="Could not reach the LLM API after 1 attempt"):
        llm.complete("p")


def test_retry_logs_warning(caplog):
    llm, _, _ = make_llm([api_error(anthropic.OverloadedError, 529), text_response("ok")])
    with caplog.at_level("WARNING", logger="riskrank.triage.llm_client"):
        llm.complete("p")
    assert "LLM request failed (OverloadedError), retrying in 2.0s (attempt 2 of 4)" in caplog.text


# --- non-retryable errors ----------------------------------------------------------


@pytest.mark.parametrize(
    ("error", "message"),
    [
        (api_error(anthropic.AuthenticationError, 401), "LLM_API_KEY"),
        (api_error(anthropic.PermissionDeniedError, 403), "permission"),
        (api_error(anthropic.NotFoundError, 404), "model 'test-model' was not found"),
        (api_error(anthropic.BadRequestError, 400), "HTTP 400, BadRequestError"),
    ],
    ids=["401", "403", "404", "400"],
)
def test_non_retryable_errors_fail_immediately(error, message):
    llm, messages, clock = make_llm([error])
    with pytest.raises(LLMError, match=message):
        llm.complete("p")
    assert len(messages.requests) == 1
    assert clock.sleeps == []


def test_negative_max_retries_rejected():
    with pytest.raises(ValueError, match="max_retries"):
        make_llm([text_response("x")], max_retries=-1)


# --- rate limiting -------------------------------------------------------------------


def test_rate_limiter_spaces_out_calls():
    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=30, sleep=clock.sleep, clock=clock)  # every 2s
    limiter.wait()
    limiter.wait()
    clock.now += 0.5  # some work between calls
    limiter.wait()
    assert clock.sleeps == [2.0, 1.5]


def test_rate_limiter_does_not_wait_when_calls_are_already_spread_out():
    clock = FakeClock()
    limiter = RateLimiter(requests_per_minute=60, sleep=clock.sleep, clock=clock)
    limiter.wait()
    clock.now += 5
    limiter.wait()
    assert clock.sleeps == []


def test_rate_limiter_rejects_non_positive_rate():
    with pytest.raises(ValueError, match="requests_per_minute"):
        RateLimiter(0)


def test_complete_applies_rate_limit_between_requests():
    llm, _, clock = make_llm([text_response("a")], requests_per_minute=20)  # every 3s
    llm.complete("1")
    llm.complete("2")
    assert clock.sleeps == [3.0]


# --- construction ----------------------------------------------------------------------


def _settings(**overrides) -> Settings:
    values = {
        "zap_api_url": "http://localhost:8080",
        "zap_api_key": "zap",
        "llm_api_key": "llm-key",
        "llm_model": "claude-sonnet-4-6",
        "database_url": "sqlite:///./riskrank.db",
    }
    values.update(overrides)
    return Settings(**values)


def test_from_settings_builds_client_with_real_sdk_and_no_sdk_retries():
    llm = LLMClient.from_settings(_settings())
    assert llm.model == "claude-sonnet-4-6"
    assert isinstance(llm.client, anthropic.Anthropic)
    assert llm.client.max_retries == 0  # retries are handled by LLMClient itself


def test_from_settings_requires_llm_api_key():
    with pytest.raises(ConfigError, match="LLM_API_KEY"):
        LLMClient.from_settings(_settings(llm_api_key=""))


def test_other_api_errors_fail_immediately_with_generic_message():
    """E.g. a response the SDK couldn't validate: not an HTTP status problem."""
    error = anthropic.APIError("malformed response", request=REQUEST, body=None)
    llm, messages, _ = make_llm([error])
    with pytest.raises(LLMError, match="LLM request failed: malformed response"):
        llm.complete("p")
    assert len(messages.requests) == 1
