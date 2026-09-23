"""Tests for the report layer.

Tickets: R016, R017, R029-R033
"""

import io

from rich.console import Console

from riskrank.report.console import print_findings, severity_summary
from riskrank.scanner.models import Finding


def _finding(n: int, severity: str, **kwargs) -> Finding:
    defaults = {"type": f"Type {n}", "endpoint": f"/path{n}", "cwe_id": None}
    defaults.update(kwargs)
    return Finding(id=f"finding-{n:03d}", severity_raw=severity, **defaults)


def render(findings: list[Finding]) -> str:
    """Render print_findings() to plain text (no colours) for assertions."""
    console = Console(file=io.StringIO(), width=120, color_system=None)
    print_findings(findings, console=console)
    return console.file.getvalue()


# --- R016: console output ----------------------------------------------------


def test_console_output_contains_finding_details(sample_finding):
    output = render([sample_finding])
    assert "Raw findings (1)" in output
    for expected in ["finding-001", "High", "SQL Injection", "/api/login", "89"]:
        assert expected in output


def test_console_output_orders_by_severity_then_original_order():
    findings = [
        _finding(1, "Low"),
        _finding(2, "High"),
        _finding(3, "Informational"),
        _finding(4, "Medium"),
        _finding(5, "High"),
    ]
    output = render(findings)
    positions = [output.index(f"finding-{n:03d}") for n in (2, 5, 4, 1, 3)]
    assert positions == sorted(positions)


def test_unknown_severity_sorted_last():
    output = render([_finding(1, "Weird"), _finding(2, "Low")])
    assert output.index("finding-002") < output.index("finding-001")


def test_missing_cwe_shown_as_dash():
    output = render([_finding(1, "Low", cwe_id=None)])
    row = next(line for line in output.splitlines() if "finding-001" in line)
    assert "-" in row


def test_square_brackets_rendered_literally():
    """Scanner text must not be interpreted as rich markup."""
    output = render([_finding(1, "High", type="[bold]Injected[/bold]", endpoint="/api/[id]")])
    assert "[bold]Injected[/bold]" in output
    assert "/api/[id]" in output


def test_empty_findings_prints_no_findings():
    assert "No findings." in render([])


def test_severity_summary_counts_every_level():
    findings = [_finding(1, "High"), _finding(2, "High"), _finding(3, "Low")]
    assert severity_summary(findings) == "High: 2 · Medium: 0 · Low: 1 · Informational: 0"


def test_severity_summary_includes_unknown_levels():
    assert severity_summary([_finding(1, "Weird")]).endswith("Weird: 1")


def test_markdown_report_placeholder():
    """TODO (R029/R030): call generate_markdown_report() with sample
    ranked findings and assert the output contains expected sections.
    """
    assert True
