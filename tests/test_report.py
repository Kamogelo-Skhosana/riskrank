"""Tests for the report layer.

Tickets: R016, R017, R029-R033
"""

import io
import json
from datetime import UTC, datetime

import pytest
from rich.console import Console

from riskrank import __version__
from riskrank.report.console import print_findings, severity_summary
from riskrank.report.json_export import build_export, export_json
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


# --- R017: JSON export -------------------------------------------------------


FIXED_TIME = datetime(2026, 9, 23, 18, 0, tzinfo=UTC)


def test_export_json_writes_expected_document(tmp_path, sample_finding):
    path = export_json(
        [sample_finding],
        tmp_path / "findings.json",
        target_url="http://localhost:3000",
        scanned_at=FIXED_TIME,
    )

    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["riskrank_version"] == __version__
    assert data["target_url"] == "http://localhost:3000"
    assert data["scanned_at"] == "2026-09-23T18:00:00+00:00"
    assert data["finding_count"] == 1
    [finding] = data["findings"]
    assert finding["id"] == "finding-001"
    assert finding["type"] == "SQL Injection"
    assert finding["endpoint"] == "/api/login"
    assert finding["cwe_id"] == 89


def test_export_includes_every_finding_field_even_when_null(sample_finding):
    [finding] = build_export([sample_finding], scanned_at=FIXED_TIME)["findings"]
    for key in [
        "exploitability_score",
        "business_impact_score",
        "priority_tier",
        "ai_explanation",
        "suggested_fix",
    ]:
        assert key in finding
        assert finding[key] is None


def test_export_round_trips_back_into_findings(tmp_path, sample_finding):
    from riskrank.scanner.models import Finding

    path = export_json([sample_finding], tmp_path / "f.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert [Finding(**f) for f in data["findings"]] == [sample_finding]


def test_export_empty_findings(tmp_path):
    data = json.loads(export_json([], tmp_path / "empty.json").read_text(encoding="utf-8"))
    assert data["finding_count"] == 0
    assert data["findings"] == []


def test_export_creates_parent_directories(tmp_path, sample_finding):
    path = export_json([sample_finding], tmp_path / "out" / "nested" / "findings.json")
    assert path.is_file()


def test_export_keeps_non_ascii_readable(tmp_path):
    finding = _finding(1, "Low", evidence="café — naïve")
    path = export_json([finding], tmp_path / "f.json")
    assert "café — naïve" in path.read_text(encoding="utf-8")


def test_scanned_at_defaults_to_now_in_utc(sample_finding):
    scanned_at = datetime.fromisoformat(build_export([sample_finding])["scanned_at"])
    assert scanned_at.tzinfo is not None
    assert abs((datetime.now(UTC) - scanned_at).total_seconds()) < 60


def test_export_to_unwritable_path_raises(tmp_path, sample_finding):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a directory")
    with pytest.raises(OSError):
        export_json([sample_finding], blocker / "findings.json")


def test_markdown_report_placeholder():
    """TODO (R029/R030): call generate_markdown_report() with sample
    ranked findings and assert the output contains expected sections.
    """
    assert True
