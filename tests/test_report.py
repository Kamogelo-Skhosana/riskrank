"""Tests for the report layer.

Tickets: R016, R017, R029-R033
"""

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from jinja2 import UndefinedError
from rich.console import Console

from riskrank import __version__
from riskrank.report.console import print_findings, severity_summary
from riskrank.report.json_export import build_export, export_json
from riskrank.report.markdown import (
    TEMPLATE_NAME,
    code_block,
    create_environment,
    cwe_link,
    inline_code,
    md,
)
from riskrank.scanner.models import Finding
from tests.fixtures.sample_report_context import SAMPLE_REPORT_CONTEXT


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


# --- R029: Markdown report template + filters ------------------------------------------

SAMPLE_REPORT_DOC = Path(__file__).resolve().parent.parent / "docs" / "sample-report.md"


def render_sample(context=None) -> str:
    template = create_environment().get_template(TEMPLATE_NAME)
    return template.render(report=context or SAMPLE_REPORT_CONTEXT)


def test_sample_report_doc_matches_template():
    """docs/sample-report.md must be what the template actually produces.

    If you change the template, regenerate the doc (see its header comment).
    """
    doc = SAMPLE_REPORT_DOC.read_text(encoding="utf-8")
    body = doc.split("-->\n\n", 1)[1]
    assert body == render_sample()


def test_template_sections_in_priority_order():
    output = render_sample()
    positions = [
        output.index(heading)
        for heading in [
            "# riskrank report: http://localhost:3000",
            "## Summary",
            "**Fix first:** SQL Injection (Critical, score 81/100).",
            "## Fix first (Critical and High)",
            "### 1. [Critical] SQL Injection",
            "### 2. [High] Sensitive File Exposure",
            "## Other issues (Medium and Low)",
            "### 3. [Medium]",
            "### 4. [Low]",
            "## Not triaged",
            "## How to read this report",
        ]
    ]
    assert positions == sorted(positions)


def test_template_shows_scores_endpoints_and_advice():
    output = render_sample()
    assert "- **Score:** 81/100 (exploitability 9/10 × business impact 9/10)" in output
    assert "[CWE-89](https://cwe.mitre.org/data/definitions/89.html)" in output
    assert "- **Found on 17 endpoints:**" in output
    assert "  - …and 12 more" in output
    assert "**How to fix:** Use parameterised queries" in output
    assert "```text\n' OR 1=1--\n```" in output


def test_template_omits_empty_sections():
    context = {**SAMPLE_REPORT_CONTEXT, "fix_first": [], "untriaged": []}
    output = render_sample(context)
    assert "## Fix first" not in output
    assert "## Not triaged" not in output
    assert "No Critical or High issues. The highest-priority issue is" in output


def test_template_with_nothing_triaged():
    context = {**SAMPLE_REPORT_CONTEXT, "fix_first": [], "other": []}
    assert "No triaged issues." in render_sample(context)


def test_template_fails_loudly_on_missing_values():
    context = {k: v for k, v in SAMPLE_REPORT_CONTEXT.items() if k != "summary"}
    with pytest.raises(UndefinedError):
        render_sample(context)


def test_template_is_shipped_with_the_package():
    import riskrank.report

    template = Path(riskrank.report.__file__).parent / "templates" / TEMPLATE_NAME
    assert template.is_file()


@pytest.mark.parametrize(
    ("raw", "escaped"),
    [
        ("plain text", "plain text"),
        ("a*b_c", "a\\*b\\_c"),
        ("[click](http://evil)", "\\[click\\](http://evil)"),
        ("<script>alert(1)</script>", "\\<script\\>alert(1)\\</script\\>"),
        ("a | b", "a \\| b"),
        ("back\\slash", "back\\\\slash"),
        ("line one\n# not a heading", "line one # not a heading"),
    ],
)
def test_md_escapes_inline_markdown(raw, escaped):
    assert md(raw) == escaped


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("/api/login", "`/api/login`"),
        ("/a`b", "``/a`b``"),
        ("`/start", "`` `/start ``"),
    ],
)
def test_inline_code_cannot_be_closed_by_its_content(raw, expected):
    assert inline_code(raw) == expected


def test_code_block_uses_a_longer_fence_than_the_content():
    block = code_block("x\n````\ny")
    assert block.startswith("`````text\n")
    assert block.endswith("\n`````")


def test_code_block_default_fence():
    assert code_block("SELECT 1\n") == "```text\nSELECT 1\n```"


def test_cwe_link():
    assert cwe_link(79) == "[CWE-79](https://cwe.mitre.org/data/definitions/79.html)"


def test_hostile_values_cannot_break_the_report():
    issue = {
        **SAMPLE_REPORT_CONTEXT["other"][1],
        "type": "Evil | type\n## Injected heading",
        "endpoints": ["/x`y"],
        "evidence": "```\n## escaped fence",
    }
    output = render_sample({**SAMPLE_REPORT_CONTEXT, "other": [issue]})
    assert "\n## Injected heading" not in output
    assert "Evil \\| type ## Injected heading" in output
    assert "``/x`y``" in output
    assert "````text\n```\n## escaped fence\n````" in output
