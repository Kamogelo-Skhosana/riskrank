"""Tests for the demo data and `riskrank demo` (R049)."""

from pathlib import Path

import pytest
from typer.testing import CliRunner

from riskrank import cli
from riskrank.cli import app
from riskrank.config import Settings
from riskrank.dashboard.api import get_risk_trend, get_scan_detail
from riskrank.demo import DEMO_TARGET, demo_scan_findings, seed_demo_data
from riskrank.report.persistence import get_engine, get_session_factory

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def engine(tmp_path):
    engine = get_engine(f"sqlite:///{tmp_path / 'demo.db'}")
    yield engine
    engine.dispose()


def test_seed_saves_four_weekly_scans(engine):
    ids = seed_demo_data(engine)
    assert len(ids) == 4
    with get_session_factory(engine)() as session:
        trend = get_risk_trend(session, target=DEMO_TARGET)
    days = [(p.scanned_at - trend.points[0].scanned_at).days for p in trend.points]
    assert days == [0, 7, 14, 21]


def test_demo_tells_the_documented_story(engine):
    """docs/DEMO.md quotes these numbers; keep them true."""
    seed_demo_data(engine)
    with get_session_factory(engine)() as session:
        trend = get_risk_trend(session, target=DEMO_TARGET)
    assert [p.risk_score for p in trend.points] == [205, 205, 124, 82]
    assert [p.change for p in trend.points] == [None, 0, -81, -42]

    demo_md = (ROOT / "docs" / "DEMO.md").read_text(encoding="utf-8")
    assert "from 205 to 82" in demo_md


def test_top_issue_and_ranking_of_first_scan(engine):
    ids = seed_demo_data(engine)
    with get_session_factory(engine)() as session:
        detail = get_scan_detail(session, ids[0])
    assert detail.scan.top_finding.type == "SQL Injection"
    assert detail.scan.top_finding.priority_score == 81
    tiers = [(i.type, i.priority_tier) for i in detail.issues]
    assert tiers[0] == ("SQL Injection", "Critical")
    # A scanner-"Medium" issue outranks a scanner-"High" one (as DEMO.md claims).
    types = [t for t, _ in tiers]
    assert types.index("Sensitive File Exposure") < types.index("Cross Site Scripting (DOM Based)")
    assert tiers[-1] == ("User Agent Fuzzer", None)  # an untriaged issue too


def test_seed_is_idempotent_unless_forced(engine):
    assert len(seed_demo_data(engine)) == 4
    assert seed_demo_data(engine) == []
    assert len(seed_demo_data(engine, force=True)) == 4


def test_demo_findings_have_unique_ids_per_scan():
    for findings in demo_scan_findings():
        ids = [f.id for f in findings]
        assert len(ids) == len(set(ids))


def test_demo_target_is_clearly_not_a_real_scan_target():
    assert DEMO_TARGET.startswith("http://demo.") and DEMO_TARGET.endswith(".local")


# --- `riskrank demo` ---------------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def settings(monkeypatch, tmp_path):
    settings = Settings("http://zap", "", "", "m", f"sqlite:///{tmp_path / 'cli.db'}")
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    return settings


def test_demo_command_loads_sample_scans(settings):
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0, result.output
    assert f"Loaded 4 sample scans of {DEMO_TARGET}" in result.output
    assert "sample data for demos, not a real scan" in result.output
    assert "riskrank serve" in result.output


def test_demo_command_twice_does_not_duplicate(settings):
    runner.invoke(app, ["demo"])
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == 0
    assert "already loaded" in result.output
    assert "Loaded" in runner.invoke(app, ["demo", "--force"]).output


def test_demo_command_config_error(monkeypatch):
    def bad():
        raise cli.ConfigError("Invalid DATABASE_URL")

    monkeypatch.setattr(cli, "load_settings", bad)
    result = runner.invoke(app, ["demo"])
    assert result.exit_code == cli.EXIT_CONFIG_ERROR


def test_demo_guide_commands_exist():
    guide = (ROOT / "docs" / "DEMO.md").read_text(encoding="utf-8")
    assert "riskrank demo" in guide
    assert "/app/examples/context.example.toml" in guide
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "COPY examples ./examples" in dockerfile  # so the guide's -c path exists in the image
    assert (ROOT / "docs" / "sample-report.md").is_file()
