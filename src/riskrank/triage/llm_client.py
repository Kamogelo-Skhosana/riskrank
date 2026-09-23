"""LLM client wrapper for the triage layer.

Wraps the Anthropic Messages API with:
  * retries with exponential backoff for transient errors (rate limits,
    overload, 5xx, connection problems), honouring the API's retry-after
    header when it sends one;
  * basic client-side rate limiting (a minimum gap between requests), so
    triaging hundreds of findings doesn't hammer the API;
  * clear LLMError messages for problems the user has to fix (bad API key,
    unknown model, bad request).

Tests should never make live calls: inject a fake ``client`` (anything with
``messages.create(...)``) plus fake ``sleep``/``clock`` — see tests/test_llm_client.py.

Ticket: R022
"""

import logging
import time
from collections.abc import Callable
from typing import Any

import anthropic

from riskrank.config import Settings

logger = logging.getLogger(__name__)

DEFAULT_MAX_TOKENS = 1024
DEFAULT_TIMEOUT_SECONDS = 60.0
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_SECONDS = 2.0
DEFAULT_REQUESTS_PER_MINUTE = 50
MAX_RETRY_AFTER_SECONDS = 60.0

# HTTP statuses worth retrying: the request may well succeed a little later.
# 408 timeout, 409 conflict, 429 rate limit, and any 5xx (incl. 529 overloaded).
# Decided by status code rather than exception class, so it doesn't depend on
# how a given SDK version arranges its error hierarchy.
RETRYABLE_STATUS_CODES = frozenset({408, 409, 429})


def _is_retryable(exc: Exception) -> bool:
    if isinstance(exc, anthropic.APIConnectionError):  # includes APITimeoutError
        return True
    if isinstance(exc, anthropic.APIStatusError):
        return exc.status_code in RETRYABLE_STATUS_CODES or exc.status_code >= 500
    return False


class LLMError(Exception):
    """Raised when the LLM call fails and can't be recovered by retrying."""


class RateLimiter:
    """Enforces a minimum interval between calls (requests_per_minute)."""

    def __init__(
        self,
        requests_per_minute: float,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        if requests_per_minute <= 0:
            raise ValueError("requests_per_minute must be greater than 0")
        self.min_interval = 60.0 / requests_per_minute
        self._sleep = sleep
        self._clock = clock
        self._last_call: float | None = None

    def wait(self) -> None:
        """Block until the next call is allowed, then record it."""
        now = self._clock()
        if self._last_call is not None:
            remaining = self._last_call + self.min_interval - now
            if remaining > 0:
                self._sleep(remaining)
                now = self._clock()
        self._last_call = now


class LLMClient:
    def __init__(
        self,
        api_key: str,
        model: str,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        requests_per_minute: float = DEFAULT_REQUESTS_PER_MINUTE,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        client: Any = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        if max_retries < 0:
            raise ValueError("max_retries must be 0 or more")
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self._sleep = sleep
        self.rate_limiter = RateLimiter(requests_per_minute, sleep=sleep, clock=clock)
        # The SDK's own retries are disabled so all retry behaviour (and the
        # warnings the user sees) lives in one place: complete().
        self.client = client or anthropic.Anthropic(api_key=api_key, max_retries=0, timeout=timeout)

    @classmethod
    def from_settings(cls, settings: Settings, **kwargs: Any) -> "LLMClient":
        """Build a client from loaded Settings, requiring LLM_API_KEY."""
        settings.require("llm_api_key")
        return cls(api_key=settings.llm_api_key, model=settings.llm_model, **kwargs)

    def complete(self, prompt: str, system: str | None = None) -> str:
        """Send a prompt to the LLM and return the raw text response.

        Raises:
            LLMError: on a non-retryable error, or once retries run out.
        """
        request: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": [{"role": "user", "content": prompt}],
        }
        if system:
            request["system"] = system

        attempts = self.max_retries + 1
        for attempt in range(1, attempts + 1):
            self.rate_limiter.wait()
            try:
                response = self.client.messages.create(**request)
            except anthropic.APIError as exc:
                if not _is_retryable(exc) or attempt == attempts:
                    raise LLMError(self._describe(exc, attempt)) from exc
                delay = self._retry_delay(exc, attempt)
                logger.warning(
                    "LLM request failed (%s), retrying in %.1fs (attempt %d of %d)",
                    type(exc).__name__,
                    delay,
                    attempt + 1,
                    attempts,
                )
                self._sleep(delay)
            else:
                return self._extract_text(response)

        raise AssertionError("unreachable")  # pragma: no cover

    def _retry_delay(self, exc: Exception, attempt: int) -> float:
        """Exponential backoff, or the server's retry-after if it gave one."""
        delay = self.backoff_seconds * (2 ** (attempt - 1))
        response = getattr(exc, "response", None)
        retry_after = response.headers.get("retry-after") if response is not None else None
        if retry_after:
            try:
                delay = max(delay, float(retry_after))
            except ValueError:
                pass
        return min(delay, MAX_RETRY_AFTER_SECONDS)

    def _describe(self, exc: Exception, attempts: int) -> str:
        if isinstance(exc, anthropic.AuthenticationError):
            return "The LLM API rejected the API key. Check LLM_API_KEY in your .env file."
        if isinstance(exc, anthropic.PermissionDeniedError):
            return "The LLM API key doesn't have permission for this request."
        if isinstance(exc, anthropic.NotFoundError):
            return f"LLM model '{self.model}' was not found. Check LLM_MODEL in your .env file."
        if isinstance(exc, anthropic.RateLimitError):
            return f"LLM rate limit still exceeded after {attempts} attempt(s)."
        if isinstance(exc, anthropic.APIConnectionError):
            return (
                f"Could not reach the LLM API after {attempts} attempt(s) "
                f"({type(exc).__name__}). Check your internet connection."
            )
        if isinstance(exc, anthropic.APIStatusError):
            return (
                f"LLM API error (HTTP {exc.status_code}, {type(exc).__name__}) "
                f"after {attempts} attempt(s): {exc.message}"
            )
        return f"LLM request failed: {exc}"

    def _extract_text(self, response: Any) -> str:
        text = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        if getattr(response, "stop_reason", None) == "max_tokens":
            logger.warning(
                "LLM response was cut off at max_tokens=%d; consider raising it", self.max_tokens
            )
        if not text.strip():
            raise LLMError("The LLM returned an empty response.")
        return text
