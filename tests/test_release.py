"""Final end-to-end checks across all three phases (R050).

One scan goes through the real CLI (only ZAP and the LLM are faked) and must
then be visible, consistently, in every output: console, JSON, Markdown report,
database, dashboard JSON API and dashboard pages.
"""

import json
import tomllib
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from riskrank import __version__, cli
from riskrank.cli import app
from riskrank.config import Settings
from riskrank.dashboard.api import create_app
from tests.test_e2e import EXAMPLE_CONTEXT, FakeLLM, FakeZap, zap_alerts

ROOT = Path(__file__).resolve().parent.parent
TARGET = "http://example-target.com"


def test_version_is_1_0_0_everywhere():
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert pyproject["project"]["version"] == __version__ == "1.0.0"
    assert "## v1.0.0" in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")


def test_every_ticket_is_done():
    tickets = (ROOT / "docs" / "TICKETS.md").read_text(encoding="utf-8")
    assert tickets.count("- [x] **R") == 50
    assert "- [ ]" not in tickets


@pytest.fixture
def scanned(monkeypatch, tmp_path):
    """Run one full `riskrank scan` (phases 1 + 2) into a temp database."""
    db_url = f"sqlite:///{tmp_path / 'riskrank.db'}"
    settings = Settings("http://localhost:8080", "zap-key", "llm-key", "m", db_url)
    settings.scan_allowlist = ["example-target.com"]
    llm = FakeLLM()
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(
        cli.ZapClient, "from_settings", classmethod(lambda cls, s: FakeZap(zap_alerts()))
    )
    monkeypatch.setattr(cli.LLMClient, "from_settings", classmethod(lambda cls, s: llm))

    out, report = tmp_path / "findings.json", tmp_path / "report.md"
    result = CliRunner().invoke(
        app,
        ["scan", TARGET, "-y", "-c", str(EXAMPLE_CONTEXT), "-o", str(out), "-r", str(report)],
    )
    assert result.exit_code == 0, result.output
    return {
        "output": result.output,
        "json": json.loads(out.read_text(encoding="utf-8")),
        "report": report.read_text(encoding="utf-8"),
        "db_url": db_url,
        "llm_calls": llm.calls,
    }


def test_one_scan_is_consistent_across_every_output(scanned):
    # Phase 1-2: CLI, JSON and Markdown report
    assert scanned["llm_calls"] == 3  # 23 findings, 3 issue types
    assert "Findings, AI-ranked (23)" in scanned["output"]
    assert "Saved scan #1 to the database" in scanned["output"]
    assert scanned["json"]["riskrank_version"] == "1.0.0"
    top_json = max(scanned["json"]["findings"], key=lambda f: f["priority_score"])
    assert (top_json["type"], top_json["priority_tier"]) == ("SQL Injection", "Critical")
    assert "**Fix first:** SQL Injection (Critical, score 81/100)." in scanned["report"]

    # Phase 3: the dashboard shows the same scan
    with TestClient(create_app(scanned["db_url"])) as client:
        [row] = client.get("/scans").json()["items"]
        assert row["finding_count"] == 23
        assert row["riskrank_version"] == "1.0.0"
        assert row["top_finding"]["type"] == "SQL Injection"
        assert row["top_finding"]["priority_score"] == 81

        detail = client.get("/scans/1").json()
        assert [i["type"] for i in detail["issues"]] == [
            "SQL Injection",
            "Cross Site Scripting (Reflected)",
            "X-Content-Type-Options Header Missing",
        ]
        # The report lists the issues in the same order as the dashboard.
        positions = [scanned["report"].index(f"] {i['type']}") for i in detail["issues"]]
        assert positions == sorted(positions)

        [point] = client.get("/scans/trend", params={"target": TARGET}).json()["points"]
        assert point["risk_score"] == 81 + 30 + 2  # each issue once, at its highest score

        for path in ("/", "/scan/1", "/trend", "/health", "/docs"):
            assert client.get(path).status_code == 200, path
        assert "SQL Injection" in client.get("/scan/1").text
        assert f"<code>{TARGET}</code>" in client.get("/").text


def test_second_scan_shows_improvement_on_the_trend(scanned, monkeypatch):
    fixed = [a for a in zap_alerts() if a["alert"] != "SQL Injection"]
    monkeypatch.setattr(cli.ZapClient, "from_settings", classmethod(lambda cls, s: FakeZap(fixed)))
    result = CliRunner().invoke(app, ["scan", TARGET, "-y", "--no-triage"])
    assert result.exit_code == 0, result.output
    monkeypatch.setattr(cli.LLMClient, "from_settings", classmethod(lambda cls, s: FakeLLM()))
    result = CliRunner().invoke(app, ["scan", TARGET, "-y"])
    assert result.exit_code == 0, result.output

    with TestClient(create_app(scanned["db_url"])) as client:
        points = client.get("/scans/trend", params={"target": TARGET}).json()["points"]
    # The untriaged (--no-triage) scan is left out instead of showing a false 0.
    assert [p["risk_score"] for p in points] == [113, 32]
    assert points[-1]["change"] == 32 - 113  # fixing the SQL injection shows as a drop


def test_package_declares_its_dependencies():
    """`pip install riskrank` must pull in everything the CLI needs."""
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requirements = [
        line.strip()
        for line in (ROOT / "requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    ]
    assert sorted(pyproject["project"]["dependencies"]) == sorted(requirements)
