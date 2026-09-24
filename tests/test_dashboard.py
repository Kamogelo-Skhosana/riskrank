"""Tests for the dashboard API (in-process; no server or network).

Tickets: R035-R038
"""

from datetime import UTC, datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from riskrank import __version__, cli
from riskrank.cli import app as cli_app
from riskrank.config import ConfigError, Settings
from riskrank.dashboard.api import MAX_PAGE_SIZE, create_app
from riskrank.report.persistence import get_engine, save_scan
from riskrank.scanner.models import Finding


@pytest.fixture
def db_url(tmp_path):
    return f"sqlite:///{tmp_path / 'riskrank.db'}"


@pytest.fixture
def client(db_url):
    with TestClient(create_app(db_url)) as client:  # runs startup/shutdown
        yield client


# --- R035: app skeleton ------------------------------------------------------------


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "version": __version__}


def test_startup_creates_the_database_tables(client, tmp_path):
    assert (tmp_path / "riskrank.db").is_file()


def test_default_database_comes_from_settings(monkeypatch, tmp_path):
    url = f"sqlite:///{tmp_path / 'from-settings.db'}"
    settings = Settings("http://zap", "", "", "m", url)
    monkeypatch.setattr("riskrank.dashboard.api.load_settings", lambda: settings)
    with TestClient(create_app()) as client:
        assert client.get("/health").status_code == 200
    assert (tmp_path / "from-settings.db").is_file()


def test_openapi_docs_are_served(client):
    assert client.get("/docs").status_code == 200
    schema = client.get("/openapi.json").json()
    assert schema["info"]["title"] == "riskrank dashboard"
    assert {"/health", "/scans", "/scans/trend", "/scans/{scan_id}"} <= set(schema["paths"])


def test_unfinished_trend_endpoint_returns_501(client):
    """/scans/trend must reach its own handler, not /scans/{scan_id} (route order)."""
    response = client.get("/scans/trend")
    assert response.status_code == 501
    assert "R038" in response.json()["detail"]


def test_health_reports_database_errors(client):
    client.app.state.engine.dispose()

    class BrokenSession:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, *args):
            from sqlalchemy.exc import OperationalError

            raise OperationalError("SELECT 1", {}, Exception("disk I/O error"))

    client.app.state.session_factory = BrokenSession
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["detail"] == "Database unavailable"


# --- R035: `riskrank serve` ---------------------------------------------------------

runner = CliRunner()


@pytest.fixture
def uvicorn_calls(monkeypatch):
    calls = []
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **kw: calls.append((a, kw)))
    settings = Settings("http://zap", "", "", "m", "sqlite:///x.db")
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    return calls


def test_serve_runs_the_app_factory_with_defaults(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve"])
    assert result.exit_code == 0, result.output
    [(args, kwargs)] = uvicorn_calls
    assert args == ("riskrank.dashboard.api:create_app",)
    assert kwargs == {"factory": True, "host": "127.0.0.1", "port": 8000, "reload": False}
    assert "riskrank dashboard: http://localhost:8000" in result.output
    assert "Warning" not in result.output


def test_serve_options_override_settings(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve", "--host", "localhost", "--port", "9000", "--reload"])
    assert result.exit_code == 0, result.output
    [(_, kwargs)] = uvicorn_calls
    assert kwargs["host"] == "localhost" and kwargs["port"] == 9000 and kwargs["reload"]


def test_serve_warns_when_exposed_to_the_network(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve", "--host", "0.0.0.0"])
    assert result.exit_code == 0
    assert "reachable from other machines" in result.output
    assert "http://localhost:8000" in result.output


def test_serve_rejects_invalid_port(uvicorn_calls):
    result = runner.invoke(cli_app, ["serve", "--port", "70000"])
    assert result.exit_code != 0
    assert uvicorn_calls == []


def test_serve_config_error(monkeypatch):
    def bad():
        raise ConfigError("Invalid DASHBOARD_PORT: 'abc'.")

    monkeypatch.setattr(cli, "load_settings", bad)
    result = runner.invoke(cli_app, ["serve"])
    assert result.exit_code == cli.EXIT_CONFIG_ERROR
    assert "DASHBOARD_PORT" in result.output


# --- R036: GET /scans --------------------------------------------------------------

T0 = datetime(2026, 9, 20, 10, 0, tzinfo=UTC)


def finding(fid, type_="XSS", endpoint="/", exploit=None, impact=None):
    return Finding(
        id=fid,
        type=type_,
        severity_raw="Medium",
        endpoint=endpoint,
        exploitability_score=exploit,
        business_impact_score=impact,
    )


@pytest.fixture
def save(db_url):
    """save(target, findings, days_after_T0) -> scan id, into the app's database."""
    engine = get_engine(db_url)

    def _save(target, findings, day=0):
        return save_scan(engine, target, findings, scanned_at=T0 + timedelta(days=day))

    yield _save
    engine.dispose()


def test_scans_empty(client):
    assert client.get("/scans").json() == {"items": [], "total": 0, "limit": 50, "offset": 0}


def test_scans_summary_row(client, save):
    scan_id = save(
        "http://localhost:3000",
        [
            finding("f1", "SQL Injection", "/rest/user/login", 9, 9),  # 81 Critical
            finding("f2", "XSS", "/search", 6, 6),  # 36 High
            finding("f3", "XSS", "/about", 6, 6),  # 36 High
            finding("f4", "Header", "/", 2, 2),  # 4 Low
            finding("f5", "Info", "/"),  # not triaged
        ],
    )
    [row] = client.get("/scans").json()["items"]

    assert row["id"] == scan_id
    assert row["target_url"] == "http://localhost:3000"
    assert datetime.fromisoformat(row["scanned_at"]) == T0
    assert row["riskrank_version"] == __version__
    assert row["finding_count"] == 5
    assert row["triaged_count"] == 4
    assert row["tier_counts"] == {"Critical": 1, "High": 2, "Medium": 0, "Low": 1}
    assert row["top_finding"] == {
        "type": "SQL Injection",
        "endpoint": "/rest/user/login",
        "priority_tier": "Critical",
        "priority_score": 81,
    }


def test_untriaged_scan_has_no_top_finding(client, save):
    save("t", [finding("f1"), finding("f2")])
    [row] = client.get("/scans").json()["items"]
    assert row["top_finding"] is None
    assert row["triaged_count"] == 0
    assert row["tier_counts"] == {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}


def test_top_finding_tie_break_matches_ranking(client, save):
    # Both score 36; the easier-to-exploit one wins, as in rank_findings().
    save("t", [finding("a", "A", "/a", 4, 9), finding("b", "B", "/b", 9, 4)])
    [row] = client.get("/scans").json()["items"]
    assert row["top_finding"]["type"] == "B"


def test_scans_are_newest_first_and_counted_separately(client, save):
    old = save("t", [finding("f1", "Old", "/", 9, 9)], day=0)
    new = save("t", [finding("f1", "New", "/", 1, 1)], day=3)
    middle = save("t", [], day=1)
    items = client.get("/scans").json()["items"]
    assert [i["id"] for i in items] == [new, middle, old]
    assert [i["finding_count"] for i in items] == [1, 0, 1]
    assert items[0]["top_finding"]["type"] == "New"


def test_filter_by_target(client, save):
    save("http://a", [], day=0)
    b1 = save("http://b", [], day=1)
    body = client.get("/scans", params={"target": "http://b"}).json()
    assert [i["id"] for i in body["items"]] == [b1]
    assert body["total"] == 1


def test_pagination(client, save):
    ids = [save("t", [], day=d) for d in range(5)]  # newest = ids[-1]
    body = client.get("/scans", params={"limit": 2, "offset": 1}).json()
    assert [i["id"] for i in body["items"]] == [ids[3], ids[2]]
    assert (body["total"], body["limit"], body["offset"]) == (5, 2, 1)


@pytest.mark.parametrize(
    "params",
    [{"limit": 0}, {"limit": MAX_PAGE_SIZE + 1}, {"offset": -1}, {"limit": "abc"}],
)
def test_invalid_pagination_is_rejected(client, params):
    assert client.get("/scans", params=params).status_code == 422


def test_scans_query_count_does_not_grow_with_page_size(client, save):
    """Three queries per page (+1 count), not one per scan."""
    from sqlalchemy import event

    for day in range(10):
        save("t", [finding("f1", "A", "/", 5, 5)], day=day)
    engine = client.app.state.engine
    statements = []

    def listener(conn, cursor, statement, *args):
        statements.append(statement)

    event.listen(engine, "before_cursor_execute", listener)
    try:
        client.get("/scans")
    finally:
        event.remove(engine, "before_cursor_execute", listener)
    assert len([s for s in statements if s.lstrip().upper().startswith("SELECT")]) == 4


# --- R037: GET /scans/{scan_id} ---------------------------------------------------------


def detailed(fid, type_, endpoint, exploit=None, impact=None, **extra):
    extra.setdefault("ai_explanation", f"Why {type_}." if exploit else None)
    extra.setdefault("suggested_fix", f"Fix {type_}." if exploit else None)
    return Finding(
        id=fid,
        type=type_,
        severity_raw=extra.pop("severity_raw", "Medium"),
        endpoint=endpoint,
        exploitability_score=exploit,
        business_impact_score=impact,
        **extra,
    )


@pytest.fixture
def juice_scan(save):
    return save(
        "http://localhost:3000",
        [
            detailed("finding-001", "CSP Header Not Set", "/", 4, 5),  # 20 Medium
            detailed(
                "finding-002",
                "SQL Injection",
                "/rest/user/login",
                9,
                9,
                severity_raw="High",
                cwe_id=89,
                evidence="' OR 1=1--",
            ),  # 81 Critical
            detailed("finding-003", "CSP Header Not Set", "/main.js", 4, 5),
            detailed("finding-004", "User Agent Fuzzer", "/assets", severity_raw="Informational"),
        ],
    )


def test_scan_detail(client, juice_scan):
    response = client.get(f"/scans/{juice_scan}")
    assert response.status_code == 200
    body = response.json()

    assert body["scan"]["id"] == juice_scan
    assert body["scan"]["finding_count"] == 4
    assert body["scan"]["top_finding"]["type"] == "SQL Injection"

    issues = body["issues"]
    assert [(i["rank"], i["type"], i["priority_tier"]) for i in issues] == [
        (1, "SQL Injection", "Critical"),
        (2, "CSP Header Not Set", "Medium"),
        (3, "User Agent Fuzzer", None),
    ]
    sqli = issues[0]
    assert sqli["priority_score"] == 81
    assert sqli["cwe_id"] == 89
    assert sqli["evidence"] == "' OR 1=1--"
    assert sqli["explanation"] == "Why SQL Injection."
    assert sqli["suggested_fix"] == "Fix SQL Injection."
    assert issues[1]["endpoints"] == ["/", "/main.js"]
    assert issues[1]["occurrences"] == 2

    findings = body["findings"]
    assert [f["id"] for f in findings] == [
        "finding-002",
        "finding-001",
        "finding-003",
        "finding-004",
    ]
    assert findings[0]["priority_score"] == 81
    assert findings[-1]["priority_tier"] is None


def test_scan_detail_matches_the_markdown_report_order(client, juice_scan, db_url):
    """Dashboard and report use the same ranking + grouping."""
    from riskrank.report.markdown import build_report_context
    from riskrank.report.persistence import load_scan

    engine = get_engine(db_url)
    _, findings = load_scan(engine, juice_scan)
    engine.dispose()
    report = build_report_context("t", findings)
    report_order = [i.type for i in report.fix_first + report.other + report.untriaged]

    api_order = [i["type"] for i in client.get(f"/scans/{juice_scan}").json()["issues"]]
    assert api_order == report_order


@pytest.mark.parametrize(
    ("tiers", "issue_types", "finding_ids"),
    [
        (["Critical"], ["SQL Injection"], ["finding-002"]),
        (["Medium"], ["CSP Header Not Set"], ["finding-001", "finding-003"]),
        (
            ["Critical", "Medium"],
            ["SQL Injection", "CSP Header Not Set"],
            ["finding-002", "finding-001", "finding-003"],
        ),
        (["High"], [], []),
    ],
)
def test_filter_by_tier(client, juice_scan, tiers, issue_types, finding_ids):
    body = client.get(f"/scans/{juice_scan}", params={"tier": tiers}).json()
    assert [i["type"] for i in body["issues"]] == issue_types
    assert [f["id"] for f in body["findings"]] == finding_ids
    assert body["scan"]["finding_count"] == 4  # summary always covers the whole scan


def test_tier_filter_keeps_overall_issue_ranks(client, juice_scan):
    body = client.get(f"/scans/{juice_scan}", params={"tier": "Medium"}).json()
    assert body["issues"][0]["rank"] == 2


def test_invalid_tier_is_rejected(client, juice_scan):
    assert client.get(f"/scans/{juice_scan}", params={"tier": "Urgent"}).status_code == 422


def test_unknown_scan_returns_404(client):
    response = client.get("/scans/999")
    assert response.status_code == 404
    assert response.json()["detail"] == "Scan 999 not found."


def test_non_numeric_scan_id_returns_422(client):
    assert client.get("/scans/abc").status_code == 422


def test_scan_with_no_findings(client, save):
    scan_id = save("t", [])
    body = client.get(f"/scans/{scan_id}").json()
    assert body["issues"] == [] and body["findings"] == []
    assert body["scan"]["top_finding"] is None
