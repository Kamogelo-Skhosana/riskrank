"""Shared pytest fixtures for riskrank tests.

Tickets: R004, R025
"""

import socket

import pytest


class NetworkAccessInTestsError(ConnectionError):
    """Raised when a test tries to open a network connection.

    Subclasses ConnectionError (an OSError) so HTTP libraries treat it like
    any other failed connection, e.g. the Anthropic SDK raises
    APIConnectionError and requests raises ConnectionError.
    """


@pytest.fixture(autouse=True)
def block_network(monkeypatch):
    """Fail any test that tries to open a network connection (R025).

    Tests must never make live LLM or ZAP calls: they'd be slow, flaky, cost
    money and need real API keys in CI. Everything should go through fakes
    (FakeLLM, FakeSession, a fake Anthropic client). If a test accidentally
    reaches a real client, this makes it fail loudly instead of silently
    calling out.
    """

    def guard(self, address, *args, **kwargs):
        raise NetworkAccessInTestsError(
            f"Test tried to open a network connection to {address!r}. "
            "Use a fake client instead of a real one."
        )

    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket.socket, "connect_ex", guard)


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
