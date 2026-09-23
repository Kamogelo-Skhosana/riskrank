"""Shared pytest fixtures for riskrank tests.

Ticket: R004
"""

import pytest


@pytest.fixture
def sample_raw_zap_alert():
    """A sample raw ZAP alert dict, for normalizer tests (R014)."""
    return {
        "alert": "SQL Injection",
        "risk": "High",
        "url": "https://example-target.com/api/login",
        "evidence": "' OR '1'='1",
        "description": "SQL injection may be possible.",
        "cweid": "89",
    }


@pytest.fixture
def sample_finding():
    """A sample normalized Finding, for triage/report tests (R025, R028)."""
    from riskrank.scanner.models import Finding

    return Finding(
        id="finding-001",
        type="SQL Injection",
        severity_raw="High",
        endpoint="/api/login",
        evidence="' OR '1'='1",
        description="SQL injection may be possible.",
        cwe_id=89,
    )
