"""Markdown report generation for triaged, ranked findings (Phase 2).

Tickets: R029, R030, R031
"""

from riskrank.scanner.models import Finding

REPORT_TEMPLATE = """# riskrank Report — {target_url}

Scanned: {scan_date}
Findings: {finding_count}

{findings_section}
"""


def generate_markdown_report(target_url: str, findings: list[Finding]) -> str:
    """Render a prioritized Markdown report from ranked findings.

    TODO (R029/R030): loop over findings (already ranked by
    triage.rank_findings), render each with its priority tier,
    explanation, and suggested fix.
    """
    raise NotImplementedError


def write_report(content: str, path: str) -> None:
    """Write the rendered report to disk.

    TODO (R031): write content to path.
    """
    raise NotImplementedError
