"""Normalizes raw ZAP alert dicts into riskrank's internal Finding model.

Ticket: R013
"""

from riskrank.scanner.models import Finding


def normalize_alerts(raw_alerts: list[dict]) -> list[Finding]:
    """Convert raw ZAP alert dicts into a list of Finding objects.

    TODO (R013): map ZAP's alert field names (alert, risk, url, evidence,
    description, cweid) onto the Finding model.
    """
    raise NotImplementedError
