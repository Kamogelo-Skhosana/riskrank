"""Tests for the CLI entry point (ZAP is faked; no live scans).

Tickets: R015, R016, R017, R019, R031, R033
"""

import json

import pytest
from typer.testing import CliRunner

from riskrank import cli
from riskrank.cli import app
from riskrank.config import ConfigError, Settings
from riskrank.scanner.zap_client import ZapConnectionError, ZapError, ZapScanTimeoutError

runner = CliRunner()


class FakeZapClient:
    """Stands in for ZapClient: records calls and returns canned alerts."""

    def __init__(self, alerts=None, fail_with: Exception | None = None):
        self.alerts = alerts or []
        self.fail_with = fail_with
        self.calls: list[str] = []

    def check_connection(self):
        self.calls.append("check_connection")
        if self.fail_with:
            raise self.fail_with
        return "2.16.0"

    def run_spider(self, url, on_progress=None, **kwargs):
        self.calls.append(f"run_spider {url}")
        if on_progress:
            on_progress(100)
        return "1"

    def run_active_scan(self, url, on_progress=None, **kwargs):
        self.calls.append(f"run_active_scan {url}")
        if on_progress:
            on_progress(100)
        return "2"

    def count_urls(self, url):
        return getattr(self, "known_urls", 1)

    def get_alerts(self, url):
        self.calls.append(f"get_alerts {url}")
        return self.alerts


@pytest.fixture
def db_file(tmp_path):
    return tmp_path / "riskrank.db"


@pytest.fixture
def fake_zap(monkeypatch, sample_raw_zap_alert, db_file):
    """Patch settings + ZapClient so `riskrank scan` uses FakeZapClient
    and saves to a temporary database."""
    client = FakeZapClient(alerts=[sample_raw_zap_alert])
    settings = Settings("http://localhost:8080", "key", "", "model", f"sqlite:///{db_file}")
    monkeypatch.setattr(cli, "load_settings", lambda: settings)
    monkeypatch.setattr(cli.ZapClient, "from_settings", classmethod(lambda cls, s: client))
    return client


def test_help_lists_scan_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output


def test_scan_runs_pipeline_and_prints_findings(fake_zap):
    """`riskrank scan <url>` must be accepted as a subcommand and run end to end."""
    result = runner.invoke(app, ["scan", "http://localhost:3000"])

    assert result.exit_code == 0, result.output
    assert fake_zap.calls == [
        "check_connection",
        "run_spider http://localhost:3000",
        "run_active_scan http://localhost:3000",
        "get_alerts http://localhost:3000",
    ]
    assert "Connected to ZAP 2.16.0" in result.output
    assert "SQL Injection" in result.output
    assert "/api/login" in result.output


def test_scan_with_no_alerts(fake_zap):
    fake_zap.alerts = []
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
    assert result.exit_code == 0
    assert "No findings." in result.output


def test_scan_zap_failure_exits_with_error(fake_zap):
    fake_zap.fail_with = ZapConnectionError("Could not reach ZAP. Is ZAP running?")
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
    assert result.exit_code == cli.EXIT_SCAN_FAILED
    assert "Scan failed" in result.output
    assert "Is ZAP running?" in result.output


def test_scan_config_error_exits_with_config_code(monkeypatch):
    def bad_settings():
        raise ConfigError("Missing required configuration: ZAP_API_KEY.")

    monkeypatch.setattr(cli, "load_settings", bad_settings)
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
    assert result.exit_code == cli.EXIT_CONFIG_ERROR
    assert "ZAP_API_KEY" in result.output


def test_scan_output_writes_json(fake_zap, tmp_path):
    out = tmp_path / "findings.json"
    result = runner.invoke(app, ["scan", "http://localhost:3000", "--output", str(out)])

    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["target_url"] == "http://localhost:3000"
    assert data["finding_count"] == 1
    assert data["findings"][0]["type"] == "SQL Injection"
    assert "Saved 1 finding(s) to" in result.output


def test_scan_short_output_flag(fake_zap, tmp_path):
    out = tmp_path / "f.json"
    result = runner.invoke(app, ["scan", "http://localhost:3000", "-o", str(out)])
    assert result.exit_code == 0
    assert out.is_file()


def test_scan_without_output_writes_no_file(fake_zap, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["scan", "http://localhost:3000", "--no-save"])
    assert result.exit_code == 0
    assert list(tmp_path.iterdir()) == []


def test_scan_output_write_failure_exits_with_error(fake_zap, tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a directory")
    result = runner.invoke(
        app, ["scan", "http://localhost:3000", "--output", str(blocker / "f.json")]
    )
    assert result.exit_code == cli.EXIT_SCAN_FAILED
    assert "Could not write JSON output" in result.output


def test_scan_with_valid_context_file(fake_zap, tmp_path):
    ctx = tmp_path / "context.toml"
    ctx.write_text('[[endpoints]]\npattern = "/api/*"\nrequires_auth = true\n', encoding="utf-8")
    result = runner.invoke(app, ["scan", "http://localhost:3000", "--context", str(ctx)])
    assert result.exit_code == 0, result.output
    assert "Using target context from" in result.output
    assert "(1 endpoint rule(s))" in result.output


def test_scan_with_invalid_context_file_fails_before_scanning(fake_zap, tmp_path):
    ctx = tmp_path / "context.toml"
    ctx.write_text("[default]\nrequires_login = true\n", encoding="utf-8")
    result = runner.invoke(app, ["scan", "http://localhost:3000", "-c", str(ctx)])
    assert result.exit_code == cli.EXIT_CONFIG_ERROR
    assert "Context file error" in result.output
    assert fake_zap.calls == []  # never started the scan


def test_scan_report_writes_markdown(fake_zap, tmp_path):
    out = tmp_path / "report.md"
    result = runner.invoke(app, ["scan", "http://localhost:3000", "--report", str(out)])

    assert result.exit_code == 0, result.output
    content = out.read_text(encoding="utf-8")
    assert content.startswith("# riskrank report: http://localhost:3000\n")
    assert "**Findings:** 1 raw, 1 distinct issue" in content
    # Triage isn't wired into the scan yet, so the finding is listed as not triaged.
    assert "| SQL Injection | High | 1 |" in content
    assert "Saved Markdown report to" in result.output


def test_scan_short_report_flag_with_json_output(fake_zap, tmp_path):
    result = runner.invoke(
        app,
        [
            "scan",
            "http://localhost:3000",
            "-r",
            str(tmp_path / "r.md"),
            "-o",
            str(tmp_path / "f.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert (tmp_path / "r.md").is_file()
    assert (tmp_path / "f.json").is_file()


def test_scan_report_write_failure_exits_with_error(fake_zap, tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("not a directory")
    result = runner.invoke(
        app, ["scan", "http://localhost:3000", "--report", str(blocker / "report.md")]
    )
    assert result.exit_code == cli.EXIT_SCAN_FAILED
    assert "Could not write Markdown report" in result.output


def test_scan_saves_to_database_by_default(fake_zap, db_file):
    from riskrank.report.persistence import get_engine, load_scan

    result = runner.invoke(app, ["scan", "http://localhost:3000"])

    assert result.exit_code == 0, result.output
    assert "Saved scan #1 to the database" in result.output
    engine = get_engine(f"sqlite:///{db_file}")
    scan, findings = load_scan(engine, 1)
    engine.dispose()
    assert scan.target_url == "http://localhost:3000"
    assert scan.finding_count == 1
    assert [f.type for f in findings] == ["SQL Injection"]


def test_each_scan_gets_a_new_id(fake_zap):
    runner.invoke(app, ["scan", "http://localhost:3000"])
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
    assert "Saved scan #2 to the database" in result.output


def test_no_save_skips_the_database(fake_zap, db_file):
    result = runner.invoke(app, ["scan", "http://localhost:3000", "--no-save"])
    assert result.exit_code == 0
    assert "Saved scan" not in result.output
    assert not db_file.exists()


def test_database_failure_is_a_warning_not_an_error(fake_zap, db_file, tmp_path):
    db_file.mkdir()  # a directory where the database file should be
    out = tmp_path / "findings.json"
    result = runner.invoke(app, ["scan", "http://localhost:3000", "-o", str(out)])
    assert result.exit_code == 0, result.output
    assert "Warning: could not save the scan to the database" in result.output
    assert out.is_file()  # other outputs still written


# --- Scan time limits: keep partial results -------------------------------------------


class SlowZapClient(FakeZapClient):
    """Spider and/or active scan run past riskrank's time limit."""

    def __init__(self, alerts, slow=("active",), stop_fails=False):
        super().__init__(alerts=alerts)
        self.slow = set(slow)
        self.stop_fails = stop_fails
        self.timeouts: list[float | None] = []

    def run_spider(self, url, on_progress=None, **kwargs):
        self.calls.append(f"run_spider {url}")
        if "spider" in self.slow:
            raise ZapScanTimeoutError("spider timed out", scan_id="1", progress=40)
        return "1"

    def run_active_scan(self, url, on_progress=None, timeout=None, **kwargs):
        self.calls.append(f"run_active_scan {url}")
        self.timeouts.append(timeout)
        if "active" in self.slow:
            raise ZapScanTimeoutError("scan timed out", scan_id="2", progress=55)
        return "2"

    def _stop(self, what, scan_id):
        self.calls.append(f"{what} {scan_id}")
        if self.stop_fails:
            raise ZapError("ZAP API error")

    def stop_spider(self, scan_id):
        self._stop("stop_spider", scan_id)

    def stop_active_scan(self, scan_id):
        self._stop("stop_active_scan", scan_id)


@pytest.fixture
def slow_zap(monkeypatch, fake_zap, sample_raw_zap_alert):
    client = SlowZapClient([sample_raw_zap_alert])
    monkeypatch.setattr(cli.ZapClient, "from_settings", classmethod(lambda cls, s: client))
    return client


def test_active_scan_timeout_keeps_partial_results(slow_zap, tmp_path):
    out = tmp_path / "findings.json"
    result = runner.invoke(app, ["scan", "http://localhost:3000", "-o", str(out)])

    assert result.exit_code == 0, result.output
    assert "stop_active_scan 2" in slow_zap.calls
    assert slow_zap.calls[-1] == "get_alerts http://localhost:3000"  # alerts still fetched
    assert "active scan hit the 60-minute limit at 55%" in result.output
    assert "results are partial" in result.output
    assert json.loads(out.read_text(encoding="utf-8"))["finding_count"] == 1


def test_spider_timeout_is_stopped_and_active_scan_still_runs(slow_zap):
    slow_zap.slow = {"spider"}
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
    assert result.exit_code == 0, result.output
    assert slow_zap.calls.index("stop_spider 1") < slow_zap.calls.index(
        "run_active_scan http://localhost:3000"
    )
    assert "crawl hit the 10-minute limit at 40%" in result.output


def test_max_scan_minutes_sets_the_active_scan_timeout(slow_zap):
    slow_zap.slow = set()
    runner.invoke(app, ["scan", "http://localhost:3000", "--max-scan-minutes", "120"])
    assert slow_zap.timeouts == [7200]


def test_max_scan_minutes_must_be_positive(slow_zap):
    result = runner.invoke(app, ["scan", "http://localhost:3000", "--max-scan-minutes", "0"])
    assert result.exit_code != 0


def test_failure_to_stop_scan_is_reported_but_not_fatal(slow_zap):
    slow_zap.stop_fails = True
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
    assert result.exit_code == 0, result.output
    assert "Could not stop the active scan in ZAP" in result.output
    assert "Restart ZAP to clear it" in result.output


@pytest.mark.parametrize(
    ("url", "docker_hint"),
    [("http://localhost:3000", True), ("http://host.docker.internal:3000", False)],
)
def test_nothing_crawled_gives_a_clear_error(fake_zap, url, docker_hint):
    fake_zap.known_urls = 0
    result = runner.invoke(app, ["scan", url])

    assert result.exit_code == cli.EXIT_SCAN_FAILED
    assert "crawl found no pages" in result.output
    assert "run_active_scan" not in " ".join(fake_zap.calls)  # never attempted
    assert ("host.docker.internal" in result.output.replace(url, "")) is docker_hint
