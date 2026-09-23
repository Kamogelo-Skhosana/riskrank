"""OWASP ZAP client wrapper.

Wraps ZAP's REST API for: triggering a spider (crawl), triggering an
active scan, polling both for completion, and fetching raw alerts
once the scan finishes.

Tickets: R006, R007, R008, R009, R010
"""


class ZapClient:
    """Thin wrapper around the ZAP REST API."""

    def __init__(self, api_url: str, api_key: str):
        self.api_url = api_url
        self.api_key = api_key

    def start_spider(self, target_url: str) -> str:
        """Trigger a spider (crawl) scan against target_url.

        TODO (R007): call ZAP's /JSON/spider/action/scan/ endpoint,
        return the scan ID.
        """
        raise NotImplementedError

    def poll_spider(self, scan_id: str) -> int:
        """Poll spider scan progress. Returns percent complete (0-100).

        TODO (R007): call /JSON/spider/view/status/
        """
        raise NotImplementedError

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
