"""Tests for the scanner layer.

Tickets: R006-R014
"""


def test_normalize_alerts_placeholder(sample_raw_zap_alert):
    """TODO (R014): replace with a real assertion once normalize_alerts
    (R013) is implemented — check the raw alert maps correctly onto
    a Finding object.
    """
    assert sample_raw_zap_alert["alert"] == "SQL Injection"
