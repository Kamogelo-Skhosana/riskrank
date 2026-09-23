"""JSON export of findings.

Ticket: R017
"""

from riskrank.scanner.models import Finding


def export_json(findings: list[Finding], path: str) -> None:
    """Write findings to a JSON file at path.

    TODO (R017): serialize list[Finding] to JSON and write to disk.
    """
    raise NotImplementedError
