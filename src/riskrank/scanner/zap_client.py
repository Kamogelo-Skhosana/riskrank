"""OWASP ZAP client wrapper.

Wraps ZAP's REST API for: triggering a spider (crawl), triggering an
active scan, polling both for completion, and fetching raw alerts
once the scan finishes.

ZAP's JSON API lives at ``{api_url}/JSON/{component}/{view|action}/{name}/``.
The API key is sent in the ``X-ZAP-API-Key`` header rather than the query
string, so it doesn't end up in logs.

Tickets: R006, R007, R008, R009, R010
"""

import logging
import time
from collections.abc import Callable
from typing import Any

import requests

from riskrank.config import Settings

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30.0
# Retries for transient failures: waits of 1s, 2s, 4s between attempts.
DEFAULT_MAX_RETRIES = 3
DEFAULT_BACKOFF_SECONDS = 1.0
# Gateway/overload statuses that are usually temporary (e.g. ZAP still starting).
RETRYABLE_STATUS_CODES = frozenset({502, 503, 504})
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_SPIDER_TIMEOUT_SECONDS = 10 * 60
# Active scans send attack payloads to every discovered URL, so they take far
# longer than a crawl.
DEFAULT_ACTIVE_SCAN_TIMEOUT_SECONDS = 60 * 60
# Alerts are fetched in pages so a large scan doesn't produce one huge response.
DEFAULT_ALERTS_PAGE_SIZE = 500
# While a scan runs, ZAP can be too busy to answer status checks for a while
# (seen on Juice Shop active scans). Keep waiting through that, but give up if
# ZAP stays unresponsive this long.
DEFAULT_UNRESPONSIVE_TIMEOUT_SECONDS = 5 * 60
# ZAP takes 30-60s to start (longer on a cold Docker host).
DEFAULT_READY_TIMEOUT_SECONDS = 120

ProgressCallback = Callable[[int], None]


class ZapError(Exception):
    """Raised when ZAP returns an error or an unexpected response."""


class ZapConnectionError(ZapError):
    """Raised when the ZAP instance can't be reached at all."""


class ZapScanTimeoutError(ZapError):
    """Raised when a spider/scan doesn't finish within the allowed time.

    Carries the scan ID and last progress so the caller can stop the scan in
    ZAP and carry on with the partial results collected so far.
    """

    def __init__(self, message: str, scan_id: str = "", progress: int = 0):
        super().__init__(message)
        self.scan_id = scan_id
        self.progress = progress


class ZapClient:
    """Thin wrapper around the ZAP REST API."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
        max_retries: int = DEFAULT_MAX_RETRIES,
        backoff_seconds: float = DEFAULT_BACKOFF_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
    ):
        if max_retries < 0:
            raise ValueError("max_retries must be 0 or more")
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self._sleep = sleep
        self.session = session or requests.Session()
        self.session.headers.update({"X-ZAP-API-Key": api_key, "Accept": "application/json"})

    @classmethod
    def from_settings(cls, settings: Settings) -> "ZapClient":
        """Build a client from loaded Settings, requiring a ZAP API key."""
        settings.require("zap_api_key")
        return cls(api_url=settings.zap_api_url, api_key=settings.zap_api_key)

    def _is_retryable_error(self, exc: requests.RequestException, kind: str) -> bool:
        """Decide whether a failed request is safe to retry.

        Views are read-only, so any connection error or timeout is retried.
        Actions (start a spider/scan) are only retried when the request
        can't have reached ZAP (connection refused / connect timeout). A read
        timeout on an action is NOT retried: ZAP may already have started
        the scan, and retrying would launch a duplicate.
        """
        if kind == "view":
            return isinstance(exc, (requests.ConnectionError, requests.Timeout))
        return isinstance(exc, requests.ConnectionError)  # includes ConnectTimeout

    def _connection_error_message(self, exc: Exception, attempts: int) -> str:
        """Explain a connection failure, distinguishing 'down' from 'too busy'."""
        detail = f"({type(exc).__name__} after {attempts} attempt(s))"
        if isinstance(exc, requests.ReadTimeout):
            # Connected fine, but ZAP didn't answer in time: it's running but busy.
            return (
                f"ZAP at {self.api_url} is running but did not respond within "
                f"{self.timeout:.0f}s {detail}. It may be overloaded by a running scan; "
                "try giving Docker more CPU/memory."
            )
        return (
            f"Could not reach ZAP at {self.api_url} {detail}. Is ZAP running? "
            "See docs/ARCHITECTURE.md for how to start it with Docker."
        )

    def _send(
        self,
        url: str,
        params: dict[str, Any],
        kind: str,
        endpoint: str,
        max_retries: int | None = None,
    ):
        """GET url, retrying transient failures with exponential backoff."""
        attempts = (self.max_retries if max_retries is None else max_retries) + 1
        for attempt in range(1, attempts + 1):
            reason: str
            try:
                response = self.session.get(url, params=params, timeout=self.timeout)
            except (requests.ConnectionError, requests.Timeout) as exc:
                if attempt == attempts or not self._is_retryable_error(exc, kind):
                    raise ZapConnectionError(self._connection_error_message(exc, attempt)) from exc
                reason = type(exc).__name__
            else:
                if response.status_code not in RETRYABLE_STATUS_CODES or attempt == attempts:
                    return response
                reason = f"HTTP {response.status_code}"

            delay = self.backoff_seconds * (2 ** (attempt - 1))
            logger.warning(
                "ZAP %s failed (%s), retrying in %.1fs (attempt %d of %d)",
                endpoint,
                reason,
                delay,
                attempt + 1,
                attempts,
            )
            self._sleep(delay)

        raise AssertionError("unreachable")  # pragma: no cover

    def _request(
        self,
        component: str,
        kind: str,
        name: str,
        params: dict[str, Any] | None = None,
        max_retries: int | None = None,
    ) -> dict[str, Any]:
        """Call a ZAP JSON API endpoint and return the decoded response.

        Transient failures (connection errors, timeouts, HTTP 502/503/504)
        are retried with exponential backoff; see _is_retryable_error() for
        why actions are retried more conservatively than views.

        Args:
            component: ZAP API component, e.g. "core", "spider", "ascan".
            kind: "view" (read) or "action" (trigger something).
            name: endpoint name, e.g. "version", "scan", "status".
            params: query parameters for the call.
            max_retries: override the client's retry count for this call.

        Raises:
            ZapConnectionError: ZAP is unreachable or timed out (after retries).
            ZapError: ZAP returned an error status or a non-JSON body.
        """
        endpoint = f"{component}/{kind}/{name}"
        url = f"{self.api_url}/JSON/{endpoint}/"
        response = self._send(url, params or {}, kind, endpoint, max_retries)

        try:
            body = response.json()
        except ValueError as exc:
            raise ZapError(
                f"ZAP returned a non-JSON response from {endpoint} "
                f"(HTTP {response.status_code})."
            ) from exc

        if not response.ok:
            code = body.get("code", "unknown_error") if isinstance(body, dict) else "unknown_error"
            message = body.get("message", "") if isinstance(body, dict) else ""
            if code == "bad_api_key":
                raise ZapError("ZAP rejected the API key. Check ZAP_API_KEY in your .env file.")
            raise ZapError(
                f"ZAP API error from {endpoint} "
                f"(HTTP {response.status_code}, {code}): {message}".rstrip(": ")
            )

        return body

    def get_version(self) -> str:
        """Return the version string of the connected ZAP instance."""
        body = self._request("core", "view", "version")
        return self._read_field(body, "version", "core/view/version")

    def check_connection(self) -> str:
        """Verify ZAP is reachable and the API key is accepted.

        Returns the ZAP version on success; raises ZapConnectionError or
        ZapError otherwise.
        """
        return self.get_version()

    def wait_until_ready(
        self,
        timeout: float = DEFAULT_READY_TIMEOUT_SECONDS,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        on_waiting: Callable[[], None] | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> str:
        """Wait for ZAP to accept API calls, e.g. right after `docker run` or
        `docker compose up`, and return its version.

        Only "can't connect yet" is waited out. Any other ZapError (such as
        a rejected API key) is raised immediately, since waiting won't fix it.

        Args:
            timeout: give up (ZapConnectionError) after this many seconds.
            poll_interval: seconds between attempts.
            on_waiting: called once, the first time ZAP isn't ready yet
                (e.g. to print "Waiting for ZAP to start...").
        """
        deadline = clock() + timeout
        announced = False
        while True:
            try:
                body = self._request("core", "view", "version", max_retries=0)
                return self._read_field(body, "version", "core/view/version")
            except ZapConnectionError as exc:
                if clock() >= deadline:
                    raise ZapConnectionError(
                        f"ZAP at {self.api_url} did not become ready within {timeout:.0f}s. "
                        "Is it running? (docker ps; see docs/ARCHITECTURE.md)"
                    ) from exc
                if on_waiting and not announced:
                    on_waiting()
                    announced = True
                sleep(poll_interval)

    def new_session(self) -> None:
        """Start a fresh ZAP session, discarding the sites and alerts of
        earlier scans so they can't leak into this scan's results."""
        self._request("core", "action", "newSession", {"name": "", "overwrite": "true"})

    def _read_field(self, body: dict[str, Any], field: str, endpoint: str) -> str:
        """Pull a required field out of a ZAP response, or raise ZapError."""
        try:
            return str(body[field])
        except (KeyError, TypeError) as exc:
            raise ZapError(f"Unexpected response from ZAP {endpoint}: {body!r}") from exc

    def _parse_progress(self, body: dict[str, Any], endpoint: str) -> int:
        """Parse ZAP's string percentage ("0".."100") into an int."""
        value = self._read_field(body, "status", endpoint)
        try:
            return max(0, min(100, int(value)))
        except ValueError as exc:
            raise ZapError(f"ZAP {endpoint} returned a non-numeric status: {value!r}") from exc

    def _wait_until_complete(
        self,
        poll: Callable[[str], int],
        scan_id: str,
        label: str,
        poll_interval: float,
        timeout: float,
        on_progress: ProgressCallback | None,
        sleep: Callable[[float], None],
        clock: Callable[[], float],
        unresponsive_timeout: float = DEFAULT_UNRESPONSIVE_TIMEOUT_SECONDS,
    ) -> None:
        """Call poll(scan_id) until it reports 100%, or raise on timeout.

        A status check that fails to reach ZAP doesn't abort the scan: ZAP is
        often too busy to answer while it attacks the target. Polling carries
        on until ZAP has been unresponsive for unresponsive_timeout seconds,
        then raises ZapConnectionError. Any other ZapError is raised at once.
        """
        deadline = clock() + timeout
        unresponsive_since: float | None = None
        progress = 0
        while True:
            try:
                progress = poll(scan_id)
            except ZapConnectionError:
                now = clock()
                if unresponsive_since is None:
                    unresponsive_since = now
                if now - unresponsive_since >= unresponsive_timeout:
                    raise ZapConnectionError(
                        f"ZAP stopped responding during {label} {scan_id} and has not "
                        f"answered for {now - unresponsive_since:.0f}s "
                        f"(last progress: {progress}%)."
                    ) from None
                logger.warning(
                    "ZAP is not answering %s status checks (probably busy scanning); "
                    "still waiting (last progress: %d%%)",
                    label,
                    progress,
                )
            else:
                unresponsive_since = None
                if on_progress:
                    on_progress(progress)
                if progress >= 100:
                    return

            if clock() >= deadline:
                raise ZapScanTimeoutError(
                    f"ZAP {label} {scan_id} did not finish within {timeout:.0f}s "
                    f"(last progress: {progress}%).",
                    scan_id=scan_id,
                    progress=progress,
                )
            sleep(poll_interval)

    def start_spider(self, target_url: str) -> str:
        """Trigger a spider (crawl) scan against target_url and return its scan ID."""
        body = self._request("spider", "action", "scan", {"url": target_url})
        return self._read_field(body, "scan", "spider/action/scan")

    def poll_spider(self, scan_id: str) -> int:
        """Return spider progress for scan_id as a percentage (0-100)."""
        body = self._request("spider", "view", "status", {"scanId": scan_id})
        return self._parse_progress(body, "spider/view/status")

    def run_spider(
        self,
        target_url: str,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        timeout: float = DEFAULT_SPIDER_TIMEOUT_SECONDS,
        on_progress: ProgressCallback | None = None,
        unresponsive_timeout: float = DEFAULT_UNRESPONSIVE_TIMEOUT_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> str:
        """Start a spider against target_url and block until it completes.

        Args:
            target_url: the URL to crawl.
            poll_interval: seconds between progress checks.
            timeout: give up (ZapScanTimeoutError) after this many seconds.
            on_progress: optional callback receiving each progress percentage,
                e.g. to drive a CLI progress display.
            unresponsive_timeout: keep waiting through failed status checks
                (ZAP busy) for up to this many seconds before giving up.
            sleep, clock: injectable for tests.

        Returns:
            The spider scan ID.
        """
        scan_id = self.start_spider(target_url)
        self._wait_until_complete(
            self.poll_spider,
            scan_id,
            "spider",
            poll_interval,
            timeout,
            on_progress,
            sleep,
            clock,
            unresponsive_timeout,
        )
        return scan_id

    def start_active_scan(self, target_url: str) -> str:
        """Trigger an active scan against target_url and return its scan ID.

        Scans recursively, i.e. every URL under target_url that the spider
        discovered. Run the spider first so ZAP knows those URLs.
        """
        body = self._request("ascan", "action", "scan", {"url": target_url, "recurse": "true"})
        return self._read_field(body, "scan", "ascan/action/scan")

    def count_urls(self, base_url: str) -> int:
        """How many URLs under base_url ZAP knows about (its "sites tree").

        Zero after a crawl means ZAP couldn't reach or crawl the target, and
        an active scan would fail with url_not_found.
        """
        body = self._request("core", "view", "urls", {"baseurl": base_url})
        urls = body.get("urls") if isinstance(body, dict) else None
        if not isinstance(urls, list):
            raise ZapError(f"Unexpected response from ZAP core/view/urls: {body!r}")
        return len(urls)

    def stop_spider(self, scan_id: str) -> None:
        """Stop a running spider (e.g. after it hit riskrank's time limit)."""
        self._request("spider", "action", "stop", {"scanId": scan_id})

    def stop_active_scan(self, scan_id: str) -> None:
        """Stop a running active scan. Alerts found so far stay available."""
        self._request("ascan", "action", "stop", {"scanId": scan_id})

    def poll_active_scan(self, scan_id: str) -> int:
        """Return active scan progress for scan_id as a percentage (0-100)."""
        body = self._request("ascan", "view", "status", {"scanId": scan_id})
        return self._parse_progress(body, "ascan/view/status")

    def run_active_scan(
        self,
        target_url: str,
        poll_interval: float = DEFAULT_POLL_INTERVAL_SECONDS,
        timeout: float = DEFAULT_ACTIVE_SCAN_TIMEOUT_SECONDS,
        on_progress: ProgressCallback | None = None,
        unresponsive_timeout: float = DEFAULT_UNRESPONSIVE_TIMEOUT_SECONDS,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> str:
        """Start an active scan against target_url and block until it completes.

        Arguments behave as in run_spider(); the default timeout is longer
        because active scans are much slower than crawls.

        Returns:
            The active scan ID.
        """
        scan_id = self.start_active_scan(target_url)
        self._wait_until_complete(
            self.poll_active_scan,
            scan_id,
            "active scan",
            poll_interval,
            timeout,
            on_progress,
            sleep,
            clock,
            unresponsive_timeout,
        )
        return scan_id

    def get_alerts(
        self, target_url: str, page_size: int = DEFAULT_ALERTS_PAGE_SIZE
    ) -> list[dict[str, Any]]:
        """Fetch all raw alerts ZAP has recorded for target_url.

        Call this after run_spider() and run_active_scan() have finished.
        Alerts are fetched in pages of page_size and combined, so large
        scans don't produce a single huge response. The returned dicts are
        ZAP's raw alert format, ready for scanner.normalizer.normalize_alerts().
        """
        if page_size < 1:
            raise ValueError("page_size must be at least 1")

        alerts: list[dict[str, Any]] = []
        start = 0
        while True:
            body = self._request(
                "core",
                "view",
                "alerts",
                {"baseurl": target_url, "start": start, "count": page_size},
            )
            page = body.get("alerts") if isinstance(body, dict) else None
            if not isinstance(page, list):
                raise ZapError(f"Unexpected response from ZAP core/view/alerts: {body!r}")

            alerts.extend(page)
            if len(page) < page_size:
                return alerts
            start += page_size
