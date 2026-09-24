"""End-to-end test of the full pipeline, offline (R034).

    riskrank scan <url> --context ... -o findings.json -r report.md
      -> ZAP (faked) -> normalize -> context -> AI triage (faked LLM)
      -> rank -> console table + JSON + Markdown report + SQLite

Only the two external services are faked: ZAP and the LLM. Everything in
between is the real code, exactly as a user runs it.

Ticket: R034
"""

import json
from pathlib import Path
from typing import ClassVar

import pytest
from typer.testing import CliRunner

from riskrank import cli
from riskrank.cli import app
from riskrank.config import Settings
from riskrank.report.persistence import get_engine, load_scan
from riskrank.triage.llm_client import LLMError

ROOT = Path(__file__).resolve().parent.parent
SAMPLE_ALERTS = json.loads((ROOT / "examples" / "sample_zap_alerts.json").read_text("utf-8"))
EXAMPLE_CONTEXT = ROOT / "examples" / "context.example.toml"

runner = CliRunner()


def zap_alerts() -> list[dict]:
    """The sample alerts plus the kind of repetition a real scan produces:
    the missing-header alert on 20 more pages."""
    header_alert = SAMPLE_ALERTS[2]
    repeats = [
        {**header_alert, "url": f"https://example-target.com/page{i}.html"} for i in range(20)
    ]
    return SAMPLE_ALERTS + repeats


class FakeZap:
    def __init__(self, alerts):
        self.alerts = alerts

    def check_connection(self):
        return "2.17.0"

    def run_spider(self, url, on_progress=None, **kwargs):
        on_progress and on_progress(100)
        return "1"

    def run_active_scan(self, url, on_progress=None, **kwargs):
        on_progress and on_progress(100)
        return "2"

    def get_alerts(self, url):
        return self.alerts


class FakeLLM:
    """Scores by finding type, like a consistent reviewer would."""

    SCORES: ClassVar[dict[str, tuple[int, int]]] = {
        "SQL Injection": (9, 9),
        "Cross Site Scripting (Reflected)": (6, 5),
        "X-Content-Type-Options Header Missing": (2, 1),
    }

    def __init__(self):
        self.calls = 0

    def complete(self, prompt: str, system: str | None = None) -> str:
        self.calls += 1
        finding_type = prompt.split("Type: ", 1)[1].split("\n", 1)[0]
        exploit, impact = self.SCORES[finding_type]
        return json.dumps(
            {
                "exploitability_score": exploit,
                "business_impact_score": impact,
                "priority_tier": "High",  # deliberately off: tiers come from scores
                "explanation": f"Why {finding_type} matters here.",
                "suggested_fix": f"How to fix {finding_type}.",
            }
        )


@pytest.fixture
def pipeline(monkeypatch, tmp_path):
    db_file = tmp_path / "riskrank.db"
    settings = Settings(
        zap_api_url="http://localhost:8080",
        zap_api_key="zap-key",
        llm_api_key="llm-key",
        llm_model="test-model",
        database_url=f"sqlite:///{db_file}",
    )
    llm = FakeLLM()
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(
        cli.ZapClient, "from_settings", classmethod(lambda cls, s: FakeZap(zap_alerts()))
    )
    monkeypatch.setattr(cli.LLMClient, "from_settings", classmethod(lambda cls, s: llm))
    return {"llm": llm, "db_file": db_file, "tmp": tmp_path}


def run(pipeline, *extra):
    out, report = pipeline["tmp"] / "findings.json", pipeline["tmp"] / "report.md"
    result = runner.invoke(
        app,
        [
            "scan",
            "http://example-target.com",
            "-c",
            str(EXAMPLE_CONTEXT),
            "-o",
            str(out),
            "-r",
            str(report),
            *extra,
        ],
    )
    return result, out, report


def test_full_pipeline_produces_ranked_triaged_outputs(pipeline):
    result, out, report = run(pipeline)
    assert result.exit_code == 0, result.output

    # Triage: 23 findings, but only one LLM call per issue type.
    assert pipeline["llm"].calls == 3
    assert "Triaged 23 of 23 finding(s) using 3 AI call(s)" in result.output

    # Console: AI-ranked table; SQLi (finding-001) before XSS (002) before the header (003).
    assert "Findings, AI-ranked (23)" in result.output
    rows = [result.output.index(f"finding-00{n}") for n in (1, 2, 3)]
    assert rows == sorted(rows)

    # JSON: every finding carries its scores and a score-derived tier.
    data = json.loads(out.read_text("utf-8"))
    assert data["finding_count"] == 23
    by_type = {f["type"]: f for f in data["findings"]}
    assert by_type["SQL Injection"]["priority_score"] == 81
    assert by_type["SQL Injection"]["priority_tier"] == "Critical"
    assert by_type["Cross Site Scripting (Reflected)"]["priority_tier"] == "Medium"
    assert by_type["X-Content-Type-Options Header Missing"]["priority_tier"] == "Low"

    # Markdown report: 3 grouped issues, prioritized.
    md = report.read_text("utf-8")
    assert "**Findings:** 23 raw, 3 distinct issues" in md
    assert "**Fix first:** SQL Injection (Critical, score 81/100)." in md
    assert md.index("### 1. [Critical] SQL Injection") < md.index(
        "### 2. [Medium] Cross Site Scripting (Reflected)"
    )
    assert "### 3. [Low] X-Content-Type-Options Header Missing" in md
    assert "- **Found on 21 endpoints:**" in md
    assert "**How to fix:** How to fix SQL Injection." in md
    assert "## Not triaged" not in md

    # Database: saved with the same triage results.
    engine = get_engine(f"sqlite:///{pipeline['db_file']}")
    scan, findings = load_scan(engine, 1)
    engine.dispose()
    assert scan.finding_count == 23
    assert {f.type: f.priority_tier for f in findings}["SQL Injection"] == "Critical"


def test_no_triage_flag_skips_the_llm(pipeline):
    result, _, report = run(pipeline, "--no-triage")
    assert result.exit_code == 0, result.output
    assert pipeline["llm"].calls == 0
    assert "Raw findings (23)" in result.output
    assert "## Not triaged" in report.read_text("utf-8")


def test_triage_required_without_api_key_fails_before_scanning(monkeypatch, tmp_path):
    settings = Settings("http://localhost:8080", "zap-key", "", "m", f"sqlite:///{tmp_path}/x.db")
    zap_used = []
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(
        cli.ZapClient,
        "from_settings",
        classmethod(lambda cls, s: zap_used.append(1) or FakeZap([])),
    )
    result = runner.invoke(app, ["scan", "http://example-target.com", "--triage"])
    assert result.exit_code == cli.EXIT_CONFIG_ERROR
    assert "LLM_API_KEY" in result.output


def test_default_without_api_key_scans_but_skips_triage(monkeypatch, tmp_path):
    settings = Settings("http://localhost:8080", "zap-key", "", "m", f"sqlite:///{tmp_path}/x.db")
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(
        cli.ZapClient, "from_settings", classmethod(lambda cls, s: FakeZap(SAMPLE_ALERTS))
    )
    result = runner.invoke(app, ["scan", "http://example-target.com", "--no-save"])
    assert result.exit_code == 0, result.output
    assert "AI triage skipped: set LLM_API_KEY" in result.output
    assert "Raw findings (3)" in result.output


def test_triage_failures_do_not_fail_the_scan(pipeline):
    def broken(prompt, system=None):
        raise LLMError("The LLM API rejected the API key.")

    pipeline["llm"].complete = broken
    result, _, report = run(pipeline)

    assert result.exit_code == 0, result.output
    assert "Triaged 0 of 23 finding(s)" in result.output
    assert "Warning: 23 finding(s) could not be triaged" in result.output
    assert "The LLM API rejected the API key." in result.output
    assert "## Not triaged" in report.read_text("utf-8")


def test_scan_with_no_findings_makes_no_llm_calls(pipeline, monkeypatch):
    monkeypatch.setattr(cli.ZapClient, "from_settings", classmethod(lambda cls, s: FakeZap([])))
    result, _, report = run(pipeline)
    assert result.exit_code == 0, result.output
    assert pipeline["llm"].calls == 0
    assert "No findings." in result.output
    assert "**Findings:** 0 raw, 0 distinct issues" in report.read_text("utf-8")
