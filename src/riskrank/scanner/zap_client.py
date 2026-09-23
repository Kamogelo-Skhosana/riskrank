"""OWASP ZAP client wrapper.

Wraps ZAP's REST API for: triggering a spider (crawl), triggering an
active scan, polling both for completion, and fetching raw alerts
once the scan finishes.

ZAP's JSON API lives at ``{api_url}/JSON/{component}/{view|action}/{name}/``.
The API key is sent in the ``X-ZAP-API-Key`` header rather than the query
string, so it doesn't end up in logs.

Tickets: R006, R007, R008, R009, R010
"""

import time
from collections.abc import Callable
from typing import Any

import requests

from riskrank.config import Settings

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_POLL_INTERVAL_SECONDS = 2.0
DEFAULT_SPIDER_TIMEOUT_SECONDS = 10 * 60

ProgressCallback = Callable[[int], None]


class ZapError(Exception):
    """Raised when ZAP returns an error or an unexpected response."""


class ZapConnectionError(ZapError):
    """Raised when the ZAP instance can't be reached at all."""


class ZapScanTimeoutError(ZapError):
    """Raised when a spider/scan doesn't finish within the allowed time."""


class ZapClient:
    """Thin wrapper around the ZAP REST API."""

    def __init__(
        self,
        api_url: str,
        api_key: str,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        session: requests.Session | None = None,
    ):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({"X-ZAP-API-Key": api_key, "Accept": "application/json"})

    @classmethod
    def from_settings(cls, settings: Settings) -> "ZapClient":
        """Build a client from loaded Settings, requiring a ZAP API key."""
        settings.require("zap_api_key")
        return cls(api_url=settings.zap_api_url, api_key=settings.zap_api_key)

    def _request(
        self, component: str, kind: str, name: str, params: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        """Call a ZAP JSON API endpoint and return the decoded response.

        Args:
            component: ZAP API component, e.g. "core", "spider", "ascan".
            kind: "view" (read) or "action" (trigger something).
            name: endpoint name, e.g. "version", "scan", "status".
            params: query parameters for the call.

        Raises:
            ZapConnectionError: ZAP is unreachable or timed out.
            ZapError: ZAP returned an error status or a non-JSON body.
        """
        url = f"{self.api_url}/JSON/{component}/{kind}/{name}/"
        try:
            response = self.session.get(url, params=params or {}, timeout=self.timeout)
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise ZapConnectionError(
                f"Could not reach ZAP at {self.api_url}. Is ZAP running? "
                "See docs/ARCHITECTURE.md for how to start it with Docker."
            ) from exc

        try:
            body = response.json()
        except ValueError as exc:
            raise ZapError(
                f"ZAP returned a non-JSON response from {component}/{kind}/{name} "
                f"(HTTP {response.status_code})."
            ) from exc

        if not response.ok:
            code = body.get("code", "unknown_error") if isinstance(body, dict) else "unknown_error"
            message = body.get("message", "") if isinstance(body, dict) else ""
            if code == "bad_api_key":
                raise ZapError("ZAP rejected the API key. Check ZAP_API_KEY in your .env file.")
            raise ZapError(
                f"ZAP API error from {component}/{kind}/{name} "
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
    ) -> None:
        """Call poll(scan_id) until it reports 100%, or raise on timeout."""
        deadline = clock() + timeout
        while True:
            progress = poll(scan_id)
            if on_progress:
                on_progress(progress)
            if progress >= 100:
                return
            if clock() >= deadline:
                raise ZapScanTimeoutError(
                    f"ZAP {label} {scan_id} did not finish within {timeout:.0f}s "
                    f"(last progress: {progress}%)."
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
            sleep, clock: injectable for tests.

        Returns:
            The spider scan ID.
        """
        scan_id = self.start_spider(target_url)
        self._wait_until_complete(
            self.poll_spider, scan_id, "spider", poll_interval, timeout, on_progress, sleep, clock
        )
        return scan_id

    def start_active_scan(self, target_url: str) -> str:
        """Trigger an active scan against target_url.

        TODO (R008): call /JSON/ascan/action/scan/, return scan ID.
        """
        raise NotImplementedError

    def poll_active_scan(self, scan_id: str) -> int:
        """Poll active scan progress. Returns percent complete (0-100).

        TODO (R008): call /JSON/ascan/view/status/
        """
        raise NotImplementedError

    def get_alerts(self, target_url: str) -> list[dict]:
        """Fetch raw alerts for target_url once scanning is complete.

        TODO (R009): call /JSON/core/view/alerts/, return raw alert dicts.
        """
        raise NotImplementedError
