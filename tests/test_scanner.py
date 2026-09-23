"""Tests for the scanner layer.

Tickets: R006-R014
"""

import json
import logging
from pathlib import Path

import pytest

from riskrank.scanner.models import Finding
from riskrank.scanner.normalizer import normalize_alerts

SAMPLE_ALERTS_PATH = Path(__file__).resolve().parent.parent / "examples" / "sample_zap_alerts.json"


@pytest.fixture
def sample_zap_alerts() -> list[dict]:
    """Raw ZAP output from examples/sample_zap_alerts.json."""
    return json.loads(SAMPLE_ALERTS_PATH.read_text(encoding="utf-8"))


# --- R014: normalizer --------------------------------------------------------


def test_normalize_single_alert_maps_all_fields(sample_raw_zap_alert):
    [finding] = normalize_alerts([sample_raw_zap_alert])

    assert isinstance(finding, Finding)
    assert finding.id == "finding-001"
    assert finding.type == "SQL Injection"
    assert finding.severity_raw == "High"
    assert finding.endpoint == "/api/login"
    assert finding.evidence == "' OR '1'='1"
    assert finding.description == "SQL injection may be possible."
    assert finding.cwe_id == 89


def test_normalize_sample_file(sample_zap_alerts):
    findings = normalize_alerts(sample_zap_alerts)

    assert [f.id for f in findings] == ["finding-001", "finding-002", "finding-003"]
    assert [f.type for f in findings] == [
        "SQL Injection",
        "Cross Site Scripting (Reflected)",
        "X-Content-Type-Options Header Missing",
    ]
    assert [f.severity_raw for f in findings] == ["High", "Medium", "Low"]
    assert [f.endpoint for f in findings] == ["/api/login", "/search", "/"]
    assert [f.cwe_id for f in findings] == [89, 79, 16]


def test_triage_fields_left_empty(sample_raw_zap_alert):
    """Scores are filled in later by the triage layer, not the normalizer."""
    [finding] = normalize_alerts([sample_raw_zap_alert])
    assert finding.exploitability_score is None
    assert finding.business_impact_score is None
    assert finding.priority_tier is None


def test_empty_input_returns_empty_list():
    assert normalize_alerts([]) == []


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://example.com/api/login", "/api/login"),
        ("https://example.com/search?q=<script>", "/search"),
        ("https://example.com", "/"),
        ("https://example.com/", "/"),
    ],
)
def test_endpoint_is_url_path_without_query(sample_raw_zap_alert, url, expected):
    [finding] = normalize_alerts([{**sample_raw_zap_alert, "url": url}])
    assert finding.endpoint == expected


@pytest.mark.parametrize(
    ("cweid", "expected"),
    [("89", 89), (" 79 ", 79), (352, 352), ("-1", None), ("0", None), ("", None), (None, None)],
)
def test_cwe_id_parsing(sample_raw_zap_alert, cweid, expected):
    [finding] = normalize_alerts([{**sample_raw_zap_alert, "cweid": cweid}])
    assert finding.cwe_id == expected


@pytest.mark.parametrize(
    ("risk", "expected"),
    [("HIGH", "High"), ("medium", "Medium"), ("Low", "Low"), ("Informational", "Informational")],
)
def test_risk_capitalisation_is_normalized(sample_raw_zap_alert, risk, expected):
    [finding] = normalize_alerts([{**sample_raw_zap_alert, "risk": risk}])
    assert finding.severity_raw == expected


def test_blank_evidence_and_description_become_none(sample_raw_zap_alert):
    alert = {**sample_raw_zap_alert, "evidence": "   ", "description": ""}
    [finding] = normalize_alerts([alert])
    assert finding.evidence is None
    assert finding.description is None


def test_missing_optional_fields(sample_raw_zap_alert):
    alert = {k: sample_raw_zap_alert[k] for k in ("alert", "risk", "url")}
    [finding] = normalize_alerts([alert])
    assert finding.evidence is None
    assert finding.description is None
    assert finding.cwe_id is None


def test_legacy_name_field_used_when_alert_missing(sample_raw_zap_alert):
    alert = {k: v for k, v in sample_raw_zap_alert.items() if k != "alert"}
    alert["name"] = "Legacy Alert Name"
    [finding] = normalize_alerts([alert])
    assert finding.type == "Legacy Alert Name"


@pytest.mark.parametrize("missing_field", ["alert", "risk", "url"])
def test_malformed_alert_skipped_with_warning(sample_raw_zap_alert, caplog, missing_field):
    bad = {k: v for k, v in sample_raw_zap_alert.items() if k != missing_field}
    good = {**sample_raw_zap_alert, "alert": "Good Alert"}

    with caplog.at_level(logging.WARNING, logger="riskrank.scanner.normalizer"):
        findings = normalize_alerts([bad, good])

    assert [f.type for f in findings] == ["Good Alert"]
    assert findings[0].id == "finding-001"  # IDs stay sequential after a skip
    assert "Skipping malformed ZAP alert" in caplog.text
