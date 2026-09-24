"""Tests for the dashboard: JSON API and HTML pages (in-process; no server or network).

Tickets: R035-R043 (API, pages, theme and API wiring)
"""

import html as html_lib
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from riskrank import __version__, cli
from riskrank.cli import app as cli_app
from riskrank.config import ConfigError, Settings
from riskrank.dashboard.api import MAX_PAGE_SIZE, create_app
from riskrank.dashboard.pages import build_trend_chart, nice_ceiling
from riskrank.dashboard.schemas import TierCounts, TrendPoint
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


def test_trend_route_is_not_captured_by_scan_id_route(client):
    """/scans/trend must reach its own handler, not /scans/{scan_id} (route order)."""
    response = client.get("/scans/trend")
    assert response.status_code == 200
    assert response.json() == {"target": None, "points": []}


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


# --- R038: GET /scans/trend --------------------------------------------------------------


def test_trend_point_values(client, save):
    scan_id = save(
        "http://t",
        [
            detailed("f1", "SQL Injection", "/login", 9, 9),  # 81 Critical
            detailed("f2", "XSS", "/a", 6, 6),  # 36 High
            detailed("f3", "XSS", "/b", 4, 4),  # 16 Medium: same issue, lower score
            detailed("f4", "Header", "/", 2, 2),  # 4 Low
            detailed("f5", "Info", "/"),  # not triaged
        ],
    )
    [point] = client.get("/scans/trend").json()["points"]
    assert point["scan_id"] == scan_id
    assert point["target_url"] == "http://t"
    assert datetime.fromisoformat(point["scanned_at"]) == T0
    assert point["finding_count"] == 5
    assert point["triaged_count"] == 4
    assert point["issue_count"] == 3
    # Each issue counted once at its highest score: 81 + 36 + 4.
    assert point["risk_score"] == 121
    assert point["max_score"] == 81
    assert point["tier_counts"] == {"Critical": 1, "High": 1, "Medium": 1, "Low": 1}
    assert point["change"] is None


def test_repeated_noise_does_not_inflate_risk(client, save):
    one = save("t", [detailed("f1", "Header", "/", 5, 5)])
    many = save("t", [detailed(f"f{i}", "Header", f"/{i}", 5, 5) for i in range(50)], day=1)
    points = {p["scan_id"]: p for p in client.get("/scans/trend").json()["points"]}
    assert points[one]["risk_score"] == points[many]["risk_score"] == 25
    assert points[many]["change"] == 0


def test_trend_is_oldest_first_with_change_per_target(client, save):
    s1 = save("http://a", [detailed("f1", "SQLi", "/", 9, 9)], day=0)  # 81
    s2 = save("http://b", [detailed("f1", "XSS", "/", 5, 5)], day=1)  # 25
    s3 = save("http://a", [detailed("f1", "XSS", "/", 5, 5)], day=2)  # 25 (SQLi fixed)
    s4 = save("http://a", [], day=3)  # 0
    points = client.get("/scans/trend").json()["points"]
    assert [p["scan_id"] for p in points] == [s1, s2, s3, s4]
    assert [p["change"] for p in points] == [None, None, -56, -25]


def test_trend_filter_by_target(client, save):
    save("http://a", [], day=0)
    b = save("http://b", [], day=1)
    body = client.get("/scans/trend", params={"target": "http://b"}).json()
    assert body["target"] == "http://b"
    assert [p["scan_id"] for p in body["points"]] == [b]


def test_trend_limit_keeps_the_most_recent_scans(client, save):
    ids = [save("t", [], day=d) for d in range(5)]
    points = client.get("/scans/trend", params={"limit": 2}).json()["points"]
    assert [p["scan_id"] for p in points] == ids[-2:]  # still oldest first


def test_untriaged_scans_are_left_out_of_the_trend(client, save):
    """No AI scores = no risk score; plotting it as 0 would show a false drop."""
    first = save("t", [detailed("f1", "A", "/", 5, 5)], day=0)
    save("t", [detailed("f1", "Info", "/")], day=1)  # --no-triage run
    third = save("t", [detailed("f1", "A", "/", 4, 4)], day=2)
    points = client.get("/scans/trend").json()["points"]
    assert [p["scan_id"] for p in points] == [first, third]
    assert points[1]["change"] == 16 - 25  # compared with the last *triaged* scan


def test_scan_with_no_findings_is_a_real_zero(client, save):
    save("t", [], day=0)
    [point] = client.get("/scans/trend").json()["points"]
    assert (point["risk_score"], point["max_score"], point["issue_count"]) == (0, None, 0)


def test_trend_limit_counts_only_triaged_scans(client, save):
    ids = [save("t", [detailed("f1", "A", "/", 5, 5)], day=d) for d in range(3)]
    save("t", [detailed("f1", "Info", "/")], day=9)
    points = client.get("/scans/trend", params={"limit": 2}).json()["points"]
    assert [p["scan_id"] for p in points] == ids[-2:]


@pytest.mark.parametrize("params", [{"limit": 0}, {"limit": 1001}, {"limit": "x"}])
def test_trend_rejects_invalid_limit(client, params):
    assert client.get("/scans/trend", params=params).status_code == 422


def badge(tier):
    return (
        f'<span class="badge tier-{tier.lower()}">'
        f'<span class="badge-dot" aria-hidden="true"></span>{tier}</span>'
    )


# --- R039: scan list page -------------------------------------------------------------


def test_scan_list_page_empty_state(client):
    response = client.get("/")
    assert response.status_code == 200
    assert response.headers["content-type"].startswith("text/html")
    assert "<h1>Scan history</h1>" in response.text
    assert "No scans yet. Run <code>riskrank scan &lt;url&gt;</code>" in response.text


def test_scan_list_page_shows_date_target_and_top_finding(client, save):
    scan_id = save(
        "http://localhost:3000",
        [
            detailed("f1", "SQL Injection", "/rest/user/login", 9, 9),
            detailed("f2", "Header", "/", 2, 2),
            detailed("f3", "Info", "/"),
        ],
    )
    html = client.get("/").text

    assert "2026-09-20 10:00 UTC" in html
    assert '<time datetime="2026-09-20T10:00:00+00:00">' in html
    assert "<code>http://localhost:3000</code>" in html
    assert badge("Critical") + "\n          SQL Injection" in html
    assert "score 81/100" in html
    assert "<code>/rest/user/login</code>" in html
    assert "1 Critical · 0 High · 0 Medium · 1 Low" in html
    assert "2 triaged" in html  # 3 findings, 2 triaged
    assert f'href="/scan/{scan_id}"' in html  # detail page (R040)


def test_scan_list_page_untriaged_scan(client, save):
    save("t", [detailed("f1", "Info", "/")])
    html = client.get("/").text
    assert "Not triaged" in html


def test_scan_list_page_is_newest_first(client, save):
    save("http://old", [], day=0)
    save("http://new", [], day=5)
    html = client.get("/").text
    assert html.index("http://new") < html.index("http://old")


def test_scan_list_page_escapes_untrusted_text(client, save):
    save(
        "http://t/<script>alert(1)</script>",
        [detailed("f1", "<img src=x onerror=alert(1)>", "/<b>", 9, 9)],
    )
    html = client.get("/").text
    assert "<script>alert(1)</script>" not in html
    assert "<img src=x" not in html
    assert "&lt;script&gt;" in html and "&lt;img src=x" in html


def test_scan_list_page_filter_by_target(client, save):
    save("http://a", [])
    save("http://b", [])
    html = client.get("/", params={"target": "http://b"}).text
    assert "<code>http://b</code>" in html
    assert "<code>http://a</code>" not in html
    assert 'value="http://b"' in html
    assert "1 scan of <code>http://b</code>" in html


def test_scan_list_page_filter_with_no_matches(client, save):
    save("http://a", [])
    html = client.get("/", params={"target": "http://zzz"}).text
    assert "No scans of <code>http://zzz</code> yet." in html


def test_scan_list_page_pagination(client, save, monkeypatch):
    monkeypatch.setattr("riskrank.dashboard.pages.PAGE_SIZE", 2)
    for day in range(5):
        save(f"http://t{day}", [], day=day)

    first = client.get("/").text
    assert "Page 1 of 3" in first
    assert 'href="/?page=2" rel="next"' in first
    assert 'rel="prev"' not in first
    assert "http://t4" in first and "http://t2" not in first

    middle = client.get("/", params={"page": 2}).text
    assert 'href="/" rel="prev"' in middle and 'href="/?page=3" rel="next"' in middle

    last = client.get("/", params={"page": 3}).text
    assert "http://t0" in last and 'rel="next"' not in last


def test_pagination_links_keep_the_target_filter(client, save, monkeypatch):
    monkeypatch.setattr("riskrank.dashboard.pages.PAGE_SIZE", 1)
    save("http://a", [], day=0)
    save("http://a", [], day=1)
    html = client.get("/", params={"target": "http://a"}).text
    assert 'href="/?target=http%3A%2F%2Fa&amp;page=2"' in html


def test_scan_list_page_rejects_invalid_page(client):
    assert client.get("/", params={"page": 0}).status_code == 422


def test_pages_are_not_in_the_api_docs(client):
    assert "/" not in client.get("/openapi.json").json()["paths"]


def test_dashboard_templates_are_shipped_with_the_package():
    import riskrank.dashboard

    templates = Path(riskrank.dashboard.__file__).parent / "templates"
    assert (templates / "base.html").is_file()
    assert (templates / "scans.html").is_file()


def test_page_links_are_relative_paths(client):
    html = client.get("/").text
    assert 'action="/"' in html
    assert "http://testserver" not in html


# --- R040: scan detail page -----------------------------------------------------------


def test_scan_detail_page(client, juice_scan):
    response = client.get(f"/scan/{juice_scan}")
    assert response.status_code == 200
    html = response.text

    assert f"Scan #{juice_scan}: <code>http://localhost:3000</code>" in html
    assert "4 findings" in html and "3 triaged" in html
    assert f'href="/scans/{juice_scan}">JSON</a>' in html
    assert "<strong>Fix first:</strong> SQL Injection" in html
    # Summary table
    assert "<td>" + badge("Critical") + '</td><td class="num">1</td>' in html
    # Issues in priority order, with explanations and fixes
    assert html.index("<span>1.</span>") < html.index("<span>2.</span>")
    assert badge("Critical") + " <span>SQL Injection</span></h3>" in html
    assert badge("Medium") + " <span>CSP Header Not Set</span></h3>" in html
    assert '<article class="issue tier-critical"' in html
    assert "(exploitability 9/10 × business impact 9/10)" in html
    assert "<strong>Why it matters:</strong> Why SQL Injection." in html
    assert "<strong>How to fix:</strong> Fix SQL Injection." in html
    assert 'href="https://cwe.mitre.org/data/definitions/89.html"' in html
    assert "<pre><code>&#39; OR 1=1--</code></pre>" in html
    assert "Found on 2 endpoints:" in html
    # Untriaged issues are listed separately
    assert '<h2 id="untriaged-heading">Not triaged</h2>' in html
    assert "<td>User Agent Fuzzer</td>" in html


def test_scan_list_links_to_detail_page(client, juice_scan):
    detail_href = f'href="/scan/{juice_scan}"'
    assert detail_href in client.get("/").text
    assert client.get(f"/scan/{juice_scan}").status_code == 200


def test_scan_detail_page_tier_filter(client, juice_scan):
    html = client.get(f"/scan/{juice_scan}", params={"tier": "Medium"}).text
    assert "<span>CSP Header Not Set</span></h3>" in html
    assert "<span>SQL Injection</span></h3>" not in html
    assert "Not triaged" not in html.split('<h2 id="issues-heading">')[1]
    assert '<strong aria-current="page">Medium</strong>' in html
    assert f'href="/scan/{juice_scan}">All</a>' in html
    # Issue keeps its overall rank number
    assert "<span>2.</span>" in html


def test_scan_detail_page_tier_with_no_issues(client, juice_scan):
    html = client.get(f"/scan/{juice_scan}", params={"tier": "High"}).text
    assert "No High issues in this scan." in html


def test_scan_detail_page_invalid_tier(client, juice_scan):
    assert client.get(f"/scan/{juice_scan}", params={"tier": "Urgent"}).status_code == 422


def test_scan_detail_page_not_found(client):
    response = client.get("/scan/999")
    assert response.status_code == 404


def test_scan_detail_page_untriaged_scan(client, save):
    scan_id = save("t", [detailed("f1", "Info", "/")])
    html = client.get(f"/scan/{scan_id}").text
    assert "hasn't been AI-triaged" in html
    assert "<td>Info</td>" in html


def test_scan_detail_page_empty_scan(client, save):
    scan_id = save("t", [])
    assert "No findings in this scan." in client.get(f"/scan/{scan_id}").text


def test_scan_detail_page_collapses_long_endpoint_lists(client, save):
    scan_id = save("t", [detailed(f"f{i}", "CSP", f"/page{i}", 4, 5) for i in range(14)])
    html = client.get(f"/scan/{scan_id}").text
    assert "Found on 14 endpoints:" in html
    assert "<summary>Show 4 more</summary>" in html
    assert html.index("<code>/page9</code>") < html.index("Show 4 more")
    assert html.index("Show 4 more") < html.index("<code>/page13</code>")


def test_scan_detail_page_escapes_untrusted_text(client, save):
    scan_id = save(
        "t",
        [
            detailed(
                "f1",
                "<script>alert(1)</script>",
                "/<img src=x>",
                9,
                9,
                ai_explanation="<b>bold</b> claim",
                evidence="</code></pre><script>x</script>",
            )
        ],
    )
    html = client.get(f"/scan/{scan_id}").text
    assert "<script>" not in html
    assert "<img src=x>" not in html
    assert "<b>bold</b>" not in html
    assert "&lt;/code&gt;&lt;/pre&gt;&lt;script&gt;" in html


def test_external_links_open_safely(client, juice_scan):
    html = client.get(f"/scan/{juice_scan}").text
    assert 'rel="noopener noreferrer" target="_blank"' in html


# --- R041: risk trend page -------------------------------------------------------------


@pytest.mark.parametrize(
    ("value", "expected"),
    [(0, 4), (1, 4), (4, 4), (5, 8), (9, 12), (30, 40), (90, 100), (121, 200), (1000, 1000)],
)
def test_nice_ceiling(value, expected):
    top = nice_ceiling(value)
    assert top == expected
    assert top >= value and top % 4 == 0


def trend_point(scan_id, day, risk):
    return TrendPoint(
        scan_id=scan_id,
        target_url="t",
        scanned_at=T0 + timedelta(days=day),
        finding_count=1,
        triaged_count=1,
        issue_count=1,
        risk_score=risk,
        max_score=risk,
        tier_counts=TierCounts(),
        change=None,
    )


def test_trend_chart_geometry():
    chart = build_trend_chart(
        [trend_point(1, 0, 100), trend_point(2, 10, 0), trend_point(3, 20, 50)]
    )
    assert chart.y_ticks[0] == (chart.plot_bottom, 0)
    assert chart.y_ticks[-1] == (chart.plot_top, 100)
    xs = [d.x for d in chart.dots]
    assert xs[0] == chart.plot_left and xs[-1] == chart.plot_right
    assert xs[1] == pytest.approx((chart.plot_left + chart.plot_right) / 2)  # time-proportional
    ys = [d.y for d in chart.dots]
    assert ys[0] == chart.plot_top and ys[1] == chart.plot_bottom
    assert chart.line_path.startswith(f"M{xs[0]},{ys[0]} L")
    assert chart.area_path.endswith("Z")
    assert [label[2] for label in chart.x_labels] == ["start", "end"]


def test_trend_chart_uneven_time_gaps_are_honest():
    chart = build_trend_chart([trend_point(1, 0, 5), trend_point(2, 1, 5), trend_point(3, 10, 5)])
    xs = [d.x for d in chart.dots]
    assert (xs[1] - xs[0]) < (xs[2] - xs[1]) / 5


def test_trend_chart_single_point_is_centred():
    chart = build_trend_chart([trend_point(1, 0, 30)])
    [dot] = chart.dots
    assert dot.x == pytest.approx((chart.plot_left + chart.plot_right) / 2)
    assert [label[2] for label in chart.x_labels] == ["middle"]


def test_trend_chart_same_instant_uses_even_spacing():
    chart = build_trend_chart([trend_point(1, 0, 5), trend_point(2, 0, 5), trend_point(3, 0, 5)])
    xs = [d.x for d in chart.dots]
    assert xs == sorted(xs) and len(set(xs)) == 3


def test_trend_chart_no_points():
    assert build_trend_chart([]) is None


def test_trend_page_empty_state(client):
    html = client.get("/trend").text
    assert "<h1>Risk trend</h1>" in html
    assert "No scans yet." in html
    assert "<svg" not in html


def test_trend_page_defaults_to_most_recent_target(client, save):
    save("http://old", [detailed("f1", "A", "/", 5, 5)], day=0)
    save("http://new", [detailed("f1", "A", "/", 9, 9)], day=0)
    save("http://new", [detailed("f1", "A", "/", 2, 2)], day=3)
    html = client.get("/trend").text

    assert "Risk score of <code>http://new</code> over time" in html
    assert '<option value="http://new" selected>' in html
    assert '<option value="http://old">' in html
    assert html.index('value="http://new"') < html.index('value="http://old"')
    # Latest value tile + change vs previous scan (lower risk is good)
    assert '<div class="tile-value">4</div>' in html
    assert "▼ 77 lower" in html and 'class="delta down"' in html
    # Chart: two points, line + area, direct end label, accessible description
    assert html.count('class="dot"') == 2
    assert '<path class="line"' in html and '<path class="area"' in html
    assert 'class="end-label"' in html
    assert 'role="img"' in html and "Values are in the table below." in html
    # Table view: newest first, with links to the detail pages
    rows = html.split("<tbody>")[-1]
    assert rows.index("2026-09-23 10:00 UTC") < rows.index("2026-09-20 10:00 UTC")
    assert 'href="/scan/' in rows


def test_trend_page_select_target(client, save):
    save("http://a", [detailed("f1", "A", "/", 5, 5)], day=0)
    save("http://b", [], day=1)
    html = client.get("/trend", params={"target": "http://a"}).text
    assert "Risk score of <code>http://a</code>" in html
    assert '<div class="tile-value">25</div>' in html


def test_trend_page_unknown_target(client, save):
    save("http://a", [], day=0)
    assert (
        "No AI-triaged scans of <code>http://zzz</code> yet."
        in client.get("/trend", params={"target": "http://zzz"}).text
    )


def test_trend_page_risk_increase_is_flagged(client, save):
    save("t", [detailed("f1", "A", "/", 2, 2)], day=0)
    save("t", [detailed("f1", "A", "/", 9, 9)], day=1)
    html = client.get("/trend").text
    assert "▲ 77 higher" in html and 'class="delta up"' in html


def test_trend_page_single_scan_has_no_line(client, save):
    save("t", [detailed("f1", "A", "/", 5, 5)])
    html = client.get("/trend").text
    assert html.count('class="dot"') == 1
    assert '<path class="line"' not in html
    assert "than the previous scan" not in html


def test_trend_page_escapes_target_everywhere(client, save):
    evil = "http://t/</script><script>alert(1)</script>"
    save(evil, [detailed("f1", "A", "/", 5, 5)])
    html = client.get("/trend").text
    assert "<script>alert(1)</script>" not in html
    assert html.count("</script>") == 2  # only the page's own scripts (watcher + chart)


def test_trend_page_tooltip_data_is_json(client, save):
    save("t", [detailed("f1", "A", "/", 5, 5)])
    html = client.get("/trend").text
    assert 'const data = [{"change": null, "critical": 0, "date": "2026-09-20 10:00 UTC"' in html
    assert "innerHTML" not in html  # tooltip uses textContent only


def test_navigation_links_to_trend(client):
    assert 'href="/trend">Risk trend</a>' in client.get("/").text


# --- R042: dashboard theme ---------------------------------------------------------------


@pytest.mark.parametrize(("path", "current"), [("/", "Scans"), ("/trend", "Risk trend")])
def test_nav_marks_the_current_section(client, path, current):
    html = client.get(path).text
    assert f'aria-current="page">{current}</a>' in html
    assert html.count('aria-current="page">') == 1


def test_detail_page_is_in_the_scans_section(client, juice_scan):
    assert 'aria-current="page">Scans</a>' in client.get(f"/scan/{juice_scan}").text


@pytest.mark.parametrize("path", ["/", "/trend"])
def test_theme_supports_light_and_dark(client, path):
    html = client.get(path).text
    assert '<meta name="color-scheme" content="light dark">' in html
    assert "@media (prefers-color-scheme: dark)" in html
    assert ':root[data-theme="dark"]' in html
    assert ":focus-visible" in html


def test_tier_badges_pair_colour_with_the_tier_name(client, juice_scan):
    html = client.get(f"/scan/{juice_scan}").text
    for tier in ("Critical", "High", "Medium", "Low"):
        assert badge(tier) in html  # summary table shows every tier with its name
    assert 'class="badge-dot" aria-hidden="true"' in html


def test_tables_scroll_instead_of_overflowing_on_small_screens(client, save):
    save("t", [])
    assert '<div class="table-wrap">' in client.get("/").text


# --- R043: frontend wired to the JSON API -----------------------------------------------


def banner_attrs(page_html):
    match = re.search(
        r'id="new-scan-banner"[^>]*data-watch-url="([^"]*)" data-latest-id="(\d+)"', page_html
    )
    assert match, "new-scan banner missing"
    return html_lib.unescape(match.group(1)), int(match.group(2))


def test_scan_list_watches_the_api_for_new_scans(client, save):
    save("http://a", [], day=0)
    newest = save("http://b", [], day=1)
    page = client.get("/").text
    watch_url, latest = banner_attrs(page)
    assert watch_url == "/scans?limit=1"
    assert latest == newest
    assert '<div id="new-scan-banner" class="banner" role="status" hidden' in page

    # The URL the page polls really is the JSON API, and answers with the newest scan.
    assert client.get(watch_url).json()["items"][0]["id"] == newest


def test_watcher_keeps_the_target_filter(client, save):
    a = save("http://a", [], day=5)
    save("http://b", [], day=9)
    watch_url, latest = banner_attrs(client.get("/", params={"target": "http://a"}).text)
    assert watch_url == "/scans?target=http%3A%2F%2Fa&limit=1"
    assert latest == a


def test_watcher_on_empty_dashboard_starts_from_zero(client):
    watch_url, latest = banner_attrs(client.get("/").text)
    assert (watch_url, latest) == ("/scans?limit=1", 0)


def test_watcher_detects_a_new_scan_via_the_api(client, save):
    """Simulates the browser: remember the latest id, a scan finishes, poll again."""
    save("t", [], day=0)
    watch_url, latest = banner_attrs(client.get("/").text)
    assert client.get(watch_url).json()["items"][0]["id"] == latest  # nothing new yet
    save("t", [], day=1)
    assert client.get(watch_url).json()["items"][0]["id"] > latest  # banner would show


def test_trend_page_watches_its_target(client, save):
    s1 = save("http://a", [detailed("f1", "A", "/", 5, 5)], day=0)
    save("http://b", [], day=-1)
    watch_url, latest = banner_attrs(client.get("/trend").text)
    assert watch_url == "/scans?target=http%3A%2F%2Fa&limit=1"
    assert latest == s1


def test_watcher_script_never_writes_api_data_into_the_page(client):
    page = client.get("/").text
    script = page.split('id="new-scan-banner"', 1)[1].split("</script>", 1)[0]
    assert "innerHTML" not in script and "insertAdjacentHTML" not in script
    assert 'document.visibilityState !== "visible"' in script  # no polling in background tabs


@pytest.mark.parametrize(
    ("page", "api"),
    [
        ("/", "/scans"),
        ("/?target=http%3A%2F%2Fa", "/scans?target=http%3A%2F%2Fa"),
        ("/trend", "/scans/trend?target=http%3A%2F%2Fa"),
    ],
)
def test_pages_link_to_their_json(client, save, page, api):
    save("http://a", [detailed("f1", "A", "/", 5, 5)])
    html_text = client.get(page).text
    assert f'<a class="api-link" href="{html_lib.escape(api)}">JSON</a>' in html_text
    assert client.get(api).status_code == 200


def test_detail_page_links_to_its_json(client, juice_scan):
    html_text = client.get(f"/scan/{juice_scan}").text
    assert f'<a class="api-link" href="/scans/{juice_scan}">JSON</a>' in html_text


def test_pages_and_api_agree(client, juice_scan, save):
    """The pages are rendered from the same data the JSON API returns."""
    save("http://localhost:3000", [detailed("f1", "XSS", "/", 6, 6)], day=1)

    api_scans = client.get("/scans").json()["items"]
    page = client.get("/").text
    positions = [page.index(f'href="/scan/{s["id"]}"') for s in api_scans]
    assert positions == sorted(positions)  # same order

    detail = client.get(f"/scans/{juice_scan}").json()
    detail_page = client.get(f"/scan/{juice_scan}").text
    for issue in detail["issues"]:
        if issue["priority_tier"]:
            assert f"<span>{issue['rank']}.</span>" in detail_page
            assert f"{issue['priority_score']}/100" in detail_page

    trend = client.get("/scans/trend", params={"target": "http://localhost:3000"}).json()
    trend_page = client.get("/trend").text
    for point in trend["points"]:
        assert f'<td class="num">{point["risk_score"]}</td>' in trend_page
