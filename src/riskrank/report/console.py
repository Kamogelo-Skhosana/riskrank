"""Console output formatter for raw findings (Phase 1).

Ticket: R016
"""

from riskrank.scanner.models import Finding


def print_findings(findings: list[Finding]) -> None:
    """Print a readable summary of findings to the console.

    TODO (R016): format as a simple table (type, severity, endpoint).
    """
    raise NotImplementedError
