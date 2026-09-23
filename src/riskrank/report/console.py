"""Console output formatter for findings.

Untriaged findings are listed by scanner severity (Phase 1). Once AI triage
has run, the table adds Tier and Score columns and follows the AI ranking.

Tickets: R016, R034
"""

from collections import Counter

from rich.console import Console
from rich.table import Table
from rich.text import Text

from riskrank.scanner.models import SEVERITY_ORDER, Finding, severity_rank
from riskrank.triage.triage import rank_findings

TIER_STYLES = {
    "Critical": "bold white on red",
    "High": "bold red",
    "Medium": "yellow",
    "Low": "cyan",
}
SEVERITY_STYLES = {
    "High": "bold red",
    "Medium": "yellow",
    "Low": "cyan",
    "Informational": "dim",
}


def _severity_rank(finding: Finding) -> int:
    """Sort key: known severities in order, anything unexpected last."""
    return severity_rank(finding.severity_raw)


def severity_summary(findings: list[Finding]) -> str:
    """One-line count per severity, e.g. 'High: 1 · Medium: 2 · Low: 0 · Informational: 0'."""
    counts = Counter(f.severity_raw for f in findings)
    levels = SEVERITY_ORDER + sorted(set(counts) - set(SEVERITY_ORDER))
    return " · ".join(f"{level}: {counts.get(level, 0)}" for level in levels)


def print_findings(findings: list[Finding], console: Console | None = None) -> None:
    """Print a readable table of findings, most important first.

    If any finding has been triaged, the table shows Tier and Score columns
    and follows the AI ranking (rank_findings); otherwise findings are
    ordered by the scanner's own severity, ties keeping ZAP's order. All
    finding text is rendered literally, so scanner output containing square
    brackets (e.g. /api/[id]) can't be misread as rich markup.

    Args:
        findings: normalized (and possibly triaged) findings to display.
        console: rich Console to print to (defaults to stdout); injectable
            for tests.
    """
    console = console or Console()

    if not findings:
        console.print("[green]No findings.[/green]")
        return

    triaged = any(f.priority_score is not None for f in findings)
    title = "Findings, AI-ranked" if triaged else "Raw findings"
    table = Table(title=f"{title} ({len(findings)})", title_justify="left")
    table.add_column("ID", no_wrap=True)
    if triaged:
        table.add_column("Tier", no_wrap=True)
        table.add_column("Score", justify="right", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("Type")
    table.add_column("Endpoint", overflow="fold")
    table.add_column("CWE", justify="right", no_wrap=True)

    ordered = rank_findings(findings) if triaged else sorted(findings, key=_severity_rank)
    for finding in ordered:
        row = [Text(finding.id)]
        if triaged:
            tier = finding.priority_tier or "-"
            row.append(Text(tier, style=TIER_STYLES.get(tier, "dim")))
            score = finding.priority_score
            row.append(Text(str(score) if score is not None else "-"))
        row += [
            Text(finding.severity_raw, style=SEVERITY_STYLES.get(finding.severity_raw, "")),
            Text(finding.type),
            Text(finding.endpoint),
            Text(str(finding.cwe_id) if finding.cwe_id is not None else "-"),
        ]
        table.add_row(*row)

    console.print(table)
    console.print(Text(severity_summary(findings)))
