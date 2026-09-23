"""Console output formatter for raw findings (Phase 1).

Ticket: R016
"""

from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text

from riskrank.scanner.models import Finding

# ZAP's severity levels, most to least severe.
SEVERITY_ORDER = ["High", "Medium", "Low", "Informational"]
SEVERITY_STYLES = {
    "High": "bold red",
    "Medium": "yellow",
    "Low": "cyan",
    "Informational": "dim",
}


def _severity_rank(finding: Finding) -> int:
    """Sort key: known severities in order, anything unexpected last."""
    try:
        return SEVERITY_ORDER.index(finding.severity_raw)
    except ValueError:
        return len(SEVERITY_ORDER)


def severity_summary(findings: list[Finding]) -> str:
    """One-line count per severity, e.g. 'High: 1 · Medium: 2 · Low: 0 · Informational: 0'."""
    counts = Counter(f.severity_raw for f in findings)
    levels = SEVERITY_ORDER + sorted(set(counts) - set(SEVERITY_ORDER))
    return " · ".join(f"{level}: {counts.get(level, 0)}" for level in levels)


def print_findings(findings: list[Finding], console: Console | None = None) -> None:
    """Print a readable table of raw findings, most severe first.

    Findings are ordered by the scanner's own severity label (the AI
    ranking comes in Phase 2); ties keep ZAP's original order. All
    finding text is rendered literally, so scanner output containing
    square brackets (e.g. /api/[id]) can't be misread as rich markup.

    Args:
        findings: normalized findings to display.
        console: rich Console to print to (defaults to stdout); injectable
            for tests.
    """
    console = console or Console()

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    table = Table(title=f"Raw findings ({len(findings)})", title_justify="left")
    table.add_column("ID", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("CWE", justify="right", no_wrap=True)

    for finding in sorted(findings, key=_severity_rank):
        table.add_row(
            Text(finding.id),
            Text(finding.severity_raw, style=SEVERITY_STYLES.get(finding.severity_raw, "")),
            Text(finding.type),
            Text(finding.endpoint),
            Text(str(finding.cwe_id) if finding.cwe_id is not None else "-"),
        )

    console.print(table)
    console.print(Text(severity_summary(findings)))
