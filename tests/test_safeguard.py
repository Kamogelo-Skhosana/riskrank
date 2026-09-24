"""Tests for the responsible-use safeguards.

Tickets: R044, R045
"""

import functools

import pytest
from typer.testing import CliRunner

from riskrank import cli
from riskrank.cli import app
from riskrank.dashboard.safeguard import confirm_target_ownership

# --- R044: target ownership confirmation ------------------------------------------


def test_flag_confirms_without_asking():
    asked = []
    result = confirm_target_ownership("http://t", assume_yes=True, ask=asked.append)
    assert (result.confirmed, result.method) == (True, "flag")
    assert asked == []


def test_prompt_yes_confirms():
    questions = []

    def ask(question):
        questions.append(question)
        return True

    result = confirm_target_ownership("http://t", ask=ask, interactive=True)
    assert (result.confirmed, result.method) == (True, "prompt")
    assert questions == ["Do you own http://t or have permission to test it?"]


def test_prompt_no_declines():
    result = confirm_target_ownership("http://t", ask=lambda q: False, interactive=True)
    assert (result.confirmed, result.method) == (False, "declined")


def test_non_interactive_without_flag_is_refused():
    """Silence never counts as consent (e.g. CI, piped input)."""
    result = confirm_target_ownership(
        "http://t", ask=lambda q: pytest.fail("must not prompt"), interactive=False
    )
    assert (result.confirmed, result.method) == (False, "non-interactive")


def test_interactive_defaults_to_whether_stdin_is_a_terminal(monkeypatch):
    monkeypatch.setattr("sys.stdin.isatty", lambda: False)
    assert confirm_target_ownership("http://t").method == "non-interactive"


# --- R044: `riskrank scan` integration --------------------------------------------

runner = CliRunner()


@pytest.fixture
def zap_contacted(monkeypatch):
    """Records whether the scan got as far as loading settings / ZAP."""
    calls = []

    def fake_load_settings():
        calls.append("load_settings")
        raise cli.ConfigError("stop here")  # end the test run right after confirmation

    monkeypatch.setattr(cli, "load_settings", fake_load_settings)
    return calls


def as_interactive(monkeypatch):
    monkeypatch.setattr(
        cli,
        "confirm_target_ownership",
        functools.partial(cli.confirm_target_ownership, interactive=True),
    )


def test_scan_refused_non_interactively_without_yes(zap_contacted):
    result = runner.invoke(app, ["scan", "http://example.com"])
    assert result.exit_code == cli.EXIT_NOT_CONFIRMED
    assert "ACTIVE scan" in result.output
    assert "Scan refused" in result.output and "--yes" in result.output
    assert zap_contacted == []  # nothing loaded, nothing sent


def test_scan_prompt_answered_no_cancels(monkeypatch, zap_contacted):
    as_interactive(monkeypatch)
    result = runner.invoke(app, ["scan", "http://example.com"], input="n\n")
    assert result.exit_code == cli.EXIT_NOT_CONFIRMED
    assert "Do you own http://example.com" in result.output
    assert "Scan cancelled" in result.output
    assert zap_contacted == []


def test_scan_prompt_defaults_to_no(monkeypatch, zap_contacted):
    as_interactive(monkeypatch)
    result = runner.invoke(app, ["scan", "http://example.com"], input="\n")
    assert result.exit_code == cli.EXIT_NOT_CONFIRMED
    assert zap_contacted == []


def test_scan_prompt_answered_yes_continues(monkeypatch, zap_contacted):
    as_interactive(monkeypatch)
    result = runner.invoke(app, ["scan", "http://example.com"], input="y\n")
    assert zap_contacted == ["load_settings"]
    assert result.exit_code == cli.EXIT_CONFIG_ERROR  # the fake settings stop the run


@pytest.mark.parametrize("flag", ["--yes", "-y"])
def test_scan_yes_flag_skips_prompt_and_warning(zap_contacted, flag):
    result = runner.invoke(app, ["scan", "http://example.com", flag])
    assert zap_contacted == ["load_settings"]
    assert "Do you own" not in result.output
    assert "ACTIVE scan" not in result.output
