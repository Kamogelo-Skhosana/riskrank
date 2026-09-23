"""Normalizes raw ZAP alert dicts into riskrank's internal Finding model.

ZAP's /JSON/core/view/alerts/ endpoint returns alerts shaped like::

    {"alert": "SQL Injection", "risk": "High",
     "url": "https://target/api/login?id=1", "evidence": "...",
     "description": "...", "cweid": "89", ...}

This module maps those onto Finding objects so nothing downstream has to
know ZAP's field names.

Ticket: R013
"""

import logging
from urllib.parse import urlparse

from riskrank.scanner.models import Finding

logger = logging.getLogger(__name__)

# ZAP's risk labels, normalized to consistent capitalisation.
KNOWN_RISK_LEVELS = {
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}


def _clean_text(value: object) -> str | None:
    """Return a stripped string, or None for missing/empty values."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_cwe_id(value: object) -> int | None:
    """ZAP reports CWE IDs as strings; "-1", "0" or "" mean 'no CWE'."""
    try:
        cwe = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return cwe if cwe > 0 else None


def _endpoint_from_url(url: str) -> str:
    """Reduce a full URL to its path, e.g. https://x.com/api/login?a=1 -> /api/login.

    The query string is dropped because it often contains ZAP's attack
    payload rather than anything identifying the endpoint.
    """
    path = urlparse(url).path
    return path or "/"


def _normalize_risk(value: object) -> str | None:
    text = _clean_text(value)
    if text is None:
        return None
    return KNOWN_RISK_LEVELS.get(text.lower(), text)


def normalize_alerts(raw_alerts: list[dict]) -> list[Finding]:
    """Convert raw ZAP alert dicts into a list of Finding objects.

    Findings get sequential IDs (finding-001, finding-002, ...) in the
    order ZAP returned them. Alerts missing a type, risk level or URL
    can't be triaged meaningfully, so they are skipped with a warning
    rather than aborting the whole scan.
    """
    findings: list[Finding] = []

    for index, alert in enumerate(raw_alerts):
        # Older ZAP versions use "name" instead of "alert".
        finding_type = _clean_text(alert.get("alert") or alert.get("name"))
        severity = _normalize_risk(alert.get("risk"))
        url = _clean_text(alert.get("url"))

        if not (finding_type and severity and url):
            logger.warning(
                "Skipping malformed ZAP alert at index %d (needs alert, risk and url): %r",
                index,
                alert,
            )
            continue

        findings.append(
            Finding(
                id=f"finding-{len(findings) + 1:03d}",
                type=finding_type,
                severity_raw=severity,
                endpoint=_endpoint_from_url(url),
                evidence=_clean_text(alert.get("evidence")),
                description=_clean_text(alert.get("description")),
                cwe_id=_parse_cwe_id(alert.get("cweid")),
            )
        )

    return findings
