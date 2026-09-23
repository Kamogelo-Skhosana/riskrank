"""Tests for the CLI entry point (ZAP is faked; no live scans).

Tickets: R015, R016, R017, R019
"""

import json

import pytest
from typer.testing import CliRunner

from riskrank import cli
from riskrank.cli import app
from riskrank.config import ConfigError, Settings
from riskrank.scanner.zap_client import ZapConnectionError

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

    def run_spider(self, url, on_progress=None):
        self.calls.append(f"run_spider {url}")
        if on_progress:
            on_progress(100)
        return "1"

    def run_active_scan(self, url, on_progress=None):
        self.calls.append(f"run_active_scan {url}")
        if on_progress:
            on_progress(100)
        return "2"

    def get_alerts(self, url):
        self.calls.append(f"get_alerts {url}")
        return self.alerts


@pytest.fixture
def fake_zap(monkeypatch, sample_raw_zap_alert):
    """Patch settings + ZapClient so `riskrank scan` uses FakeZapClient."""
    client = FakeZapClient(alerts=[sample_raw_zap_alert])
    settings = Settings("http://localhost:8080", "key", "", "model", "sqlite:///x.db")
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
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
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
