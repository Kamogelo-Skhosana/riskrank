"""Tests for the report layer.

Tickets: R016, R017, R029-R033
"""

import io
import json
import re
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
    build_report_context,
    code_block,
    create_environment,
    cwe_link,
    generate_markdown_report,
    group_into_issues,
    inline_code,
    md,
    write_report,
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


def test_triaged_findings_show_tier_and_score_in_ai_order():
    findings = [
        _finding(1, "High", exploitability_score=2, business_impact_score=2),
        _finding(2, "Low", exploitability_score=9, business_impact_score=9),
        _finding(3, "Medium"),  # not triaged
    ]
    output = render(findings)
    assert "Findings, AI-ranked (3)" in output
    assert "Tier" in output and "Score" in output
    # AI ranking, not scanner severity: the scanner-"Low" finding comes first.
    order = [output.index(f"finding-{n:03d}") for n in (2, 1, 3)]
    assert order == sorted(order)
    row = next(line for line in output.splitlines() if "finding-002" in line)
    assert "Critical" in row and "81" in row


def test_untriaged_table_has_no_tier_column():
    output = render([_finding(1, "High")])
    assert "Raw findings (1)" in output
    assert "Tier" not in output


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


# --- R030: Markdown report generator -----------------------------------------------------

REPORT_TIME = datetime(2026, 9, 24, 10, 15, tzinfo=UTC)


def triaged(fid, type_, endpoint, exploit, impact, severity="Medium", **extra):
    extra.setdefault("ai_explanation", f"Why {type_} matters.")
    extra.setdefault("suggested_fix", f"How to fix {type_}.")
    return Finding(
        id=fid,
        type=type_,
        severity_raw=severity,
        endpoint=endpoint,
        exploitability_score=exploit,
        business_impact_score=impact,
        **extra,
    )


def untriaged(fid, type_, endpoint, severity="Informational"):
    return Finding(id=fid, type=type_, severity_raw=severity, endpoint=endpoint)


def report(findings, **kwargs):
    kwargs.setdefault("scanned_at", REPORT_TIME)
    return generate_markdown_report("http://localhost:3000", findings, **kwargs)


def test_generate_report_end_to_end():
    findings = [
        triaged("f1", "CSP Header Not Set", "/", 4, 5),
        triaged(
            "f2",
            "SQL Injection",
            "/rest/user/login",
            9,
            9,
            "High",
            cwe_id=89,
            evidence="' OR 1=1--",
        ),
        triaged("f3", "CSP Header Not Set", "/main.js", 4, 5),
        untriaged("f4", "User Agent Fuzzer", "/assets"),
    ]
    output = report(findings)

    assert output.startswith("# riskrank report: http://localhost:3000\n")
    assert "**Scanned:** 2026-09-24 10:15 UTC · **Findings:** 4 raw, 3 distinct issues" in output
    assert "**Fix first:** SQL Injection (Critical, score 81/100)." in output
    assert "### 1. [Critical] SQL Injection" in output
    assert "### 2. [Medium] CSP Header Not Set" in output
    assert "- **Found on 2 endpoints:**\n  - `/`\n  - `/main.js`" in output
    assert "| User Agent Fuzzer | Informational | 1 |" in output
    assert "```text\n' OR 1=1--\n```" in output


def test_summary_counts_issues_and_occurrences_per_tier():
    context = build_report_context(
        "t",
        [
            triaged("a", "A", "/1", 9, 9),
            triaged("b", "A", "/2", 9, 9),
            triaged("c", "B", "/1", 6, 6),
            triaged("d", "C", "/1", 1, 1),
            untriaged("e", "D", "/1"),
        ],
        scanned_at=REPORT_TIME,
    )
    assert context.summary == [
        {"tier": "Critical", "issues": 1, "occurrences": 2},
        {"tier": "High", "issues": 1, "occurrences": 1},
        {"tier": "Medium", "issues": 0, "occurrences": 0},
        {"tier": "Low", "issues": 1, "occurrences": 1},
        {"tier": "Not triaged", "issues": 1, "occurrences": 1},
    ]
    assert [i.type for i in context.fix_first] == ["A", "B"]
    assert [i.type for i in context.other] == ["C"]
    assert [i.type for i in context.untriaged] == ["D"]
    assert [i.rank for i in context.fix_first + context.other + context.untriaged] == [1, 2, 3, 4]


def test_no_not_triaged_row_when_everything_is_triaged():
    context = build_report_context("t", [triaged("a", "A", "/", 5, 5)], REPORT_TIME)
    assert [row["tier"] for row in context.summary] == ["Critical", "High", "Medium", "Low"]
    assert context.untriaged == []


def test_group_takes_advice_from_the_highest_scoring_occurrence():
    findings = [
        triaged("low", "XSS", "/search", 2, 2, ai_explanation="minor here"),
        triaged("high", "XSS", "/admin", 8, 8, ai_explanation="serious here"),
    ]
    [issue] = group_into_issues(findings)
    assert issue.tier == "Critical"
    assert issue.score == 64
    assert issue.explanation == "serious here"
    assert issue.all_endpoints == ["/admin", "/search"]  # most important first


def test_group_fills_missing_evidence_and_cwe_from_other_occurrences():
    findings = [
        triaged("top", "XSS", "/a", 9, 9),
        triaged("other", "XSS", "/b", 1, 1, evidence="<script>", cwe_id=79),
    ]
    [issue] = group_into_issues(findings)
    assert issue.evidence == "<script>"
    assert issue.cwe_id == 79


def test_group_deduplicates_endpoints():
    findings = [triaged(str(i), "Timestamp", "/styles.css", 1, 1) for i in range(12)]
    [issue] = group_into_issues(findings)
    assert issue.all_endpoints == ["/styles.css"]
    assert issue.occurrences == 1


def test_endpoint_list_is_capped():
    findings = [triaged(str(i), "CSP", f"/page{i}", 4, 5) for i in range(8)]
    output = report(findings, max_endpoints=3)
    assert "- **Found on 8 endpoints:**" in output
    assert "  - `/page2`\n  - …and 5 more" in output
    assert "`/page3`" not in output


def test_type_with_some_untriaged_occurrences_is_still_triaged():
    findings = [untriaged("u", "XSS", "/b", "High"), triaged("t", "XSS", "/a", 7, 7)]
    [issue] = group_into_issues(findings)
    assert issue.tier == "High"  # 7x7 = 49
    assert issue.all_endpoints == ["/a", "/b"]


def test_findings_need_not_be_pre_sorted_or_have_consistent_tiers():
    stale = triaged("a", "A", "/", 1, 1).model_copy(update={"priority_tier": "Critical"})
    output = report([stale, triaged("b", "B", "/", 9, 9)])
    assert output.index("[Critical] B") < output.index("[Low] A")


def test_report_with_no_findings():
    output = report([])
    assert "**Findings:** 0 raw, 0 distinct issues" in output
    assert "No triaged issues." in output
    assert "## Fix first" not in output


def test_report_with_only_untriaged_findings():
    output = report([untriaged("a", "A", "/"), untriaged("b", "B", "/", "High")])
    assert "No triaged issues." in output
    # Untriaged issues are ordered by scanner severity.
    assert output.index("| B | High | 1 |") < output.index("| A | Informational | 1 |")


def test_single_issue_uses_singular_wording():
    output = report([triaged("a", "A", "/", 5, 5)])
    assert "1 distinct issue ·" in output
    assert "- **Found on 1 endpoint:**" in output


def test_scanned_at_is_shown_in_utc():
    from datetime import timedelta, timezone

    sast = timezone(timedelta(hours=2))
    output = report([], scanned_at=datetime(2026, 9, 24, 12, 15, tzinfo=sast))
    assert "2026-09-24 10:15 UTC" in output


def test_naive_scanned_at_is_treated_as_utc():
    naive = datetime(2026, 9, 24, 10, 15)  # noqa: DTZ001 - naive on purpose
    assert "2026-09-24 10:15 UTC" in report([], scanned_at=naive)


def test_scanned_at_defaults_to_now():
    output = generate_markdown_report("t", [])
    assert datetime.now(UTC).strftime("%Y-%m-%d") in output


def test_hostile_finding_text_is_escaped_in_generated_report():
    finding = triaged(
        "x",
        "Evil <img src=x onerror=alert(1)>",
        "/a`b",
        9,
        9,
        ai_explanation="See [this](http://phish.example) now",
    )
    output = report([finding])
    assert re.search(r"(?<!\\)<img", output) is None  # no unescaped HTML tag
    assert "\\<img src=x onerror=alert(1)\\>" in output
    assert "\\[this\\](http://phish.example)" in output
    assert "``/a`b``" in output


# --- R031: writing the report to disk -------------------------------------------------------


def test_write_report_writes_utf8_with_unix_newlines(tmp_path):
    path = write_report("# Report\n\nCafé — ✓\n", tmp_path / "report.md")
    assert path == (tmp_path / "report.md").resolve()
    assert path.read_bytes() == "# Report\n\nCafé — ✓\n".encode()


def test_write_report_creates_parent_directories(tmp_path):
    path = write_report("x", tmp_path / "reports" / "2026" / "report.md")
    assert path.read_text(encoding="utf-8") == "x"


def test_write_report_overwrites_existing_file(tmp_path):
    target = tmp_path / "report.md"
    target.write_text("old", encoding="utf-8")
    write_report("new", target)
    assert target.read_text(encoding="utf-8") == "new"


def test_write_report_unwritable_path_raises(tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a directory")
    with pytest.raises(OSError):
        write_report("x", blocker / "report.md")
