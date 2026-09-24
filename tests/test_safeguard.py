"""Tests for the responsible-use safeguards.

Tickets: R044, R045
"""

import functools
from pathlib import Path

import pytest
from typer.testing import CliRunner

from riskrank import cli
from riskrank.cli import app
from riskrank.config import ConfigError, Settings, load_settings
from riskrank.dashboard.safeguard import (
    AllowlistError,
    confirm_target_ownership,
    is_target_allowed,
    parse_allowlist,
    parse_allowlist_entry,
)

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


# --- R045: scan-target allowlist ----------------------------------------------------

JUICE_ALLOWLIST = ["localhost", "127.0.0.1", "host.docker.internal"]


@pytest.mark.parametrize(
    ("target", "allowlist", "allowed"),
    [
        # empty allowlist: any http(s) target
        ("http://example.com", [], True),
        ("ftp://example.com", [], False),
        ("not a url", [], False),
        ("http://example.com:99999", [], False),  # invalid port
        # exact host, any port, case/trailing-dot insensitive
        ("http://host.docker.internal:3000", JUICE_ALLOWLIST, True),
        ("http://LOCALHOST:8080/app", JUICE_ALLOWLIST, True),
        ("http://localhost.:3000", JUICE_ALLOWLIST, True),
        ("https://example.com", JUICE_ALLOWLIST, False),
        # look-alike hosts must not match
        ("http://localhost.evil.com", JUICE_ALLOWLIST, False),
        ("http://evil-localhost", JUICE_ALLOWLIST, False),
        ("http://localhost@evil.com", JUICE_ALLOWLIST, False),
        # host:port
        ("http://app.local:3000", ["app.local:3000"], True),
        ("http://app.local:4000", ["app.local:3000"], False),
        ("http://app.local", ["app.local:80"], True),  # default http port
        ("https://app.local", ["app.local:443"], True),  # default https port
        # wildcard subdomains
        ("https://shop.example.com", ["*.example.com"], True),
        ("https://a.b.example.com", ["*.example.com"], True),
        ("https://example.com", ["*.example.com"], False),  # apex not included
        ("https://badexample.com", ["*.example.com"], False),
        # IPs and CIDR ranges
        ("http://192.168.1.20:8080", ["192.168.1.20"], True),
        ("http://192.168.1.21", ["192.168.1.20"], False),
        ("http://10.4.5.6", ["10.0.0.0/8"], True),
        ("http://11.0.0.1", ["10.0.0.0/8"], False),
        ("http://intranet", ["10.0.0.0/8"], False),  # hostname vs CIDR: no match
        ("http://[::1]:3000", ["::1"], True),
        ("http://[::1]:3000", ["[::1]:3000"], True),
        ("http://[::1]:4000", ["[::1]:3000"], False),
        ("http://[fd00::5]", ["fd00::/8"], True),
    ],
)
def test_is_target_allowed(target, allowlist, allowed):
    assert is_target_allowed(target, allowlist) is allowed


@pytest.mark.parametrize(
    "entry",
    [
        "http://example.com",
        "example.com/admin",
        "exa mple.com",
        "*.",
        "*.*.example.com",
        "ex*ample.com",
        "example.com:0",
        "example.com:99999",
        "example.com:abc",
        "10.0.0.0/33",
    ],
)
def test_invalid_allowlist_entries(entry):
    with pytest.raises(AllowlistError):
        parse_allowlist_entry(entry)


def test_parse_allowlist_ignores_blanks_and_spaces():
    entries = parse_allowlist(" localhost , ,*.example.com,")
    assert [e.raw for e in entries] == ["localhost", "*.example.com"]
    assert parse_allowlist("") == []


def test_settings_parse_scan_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWLIST", "localhost, *.example.com")
    settings = load_settings(tmp_path / "none.env")
    assert settings.scan_allowlist == ["localhost", "*.example.com"]


def test_settings_reject_invalid_allowlist(tmp_path, monkeypatch):
    monkeypatch.setenv("SCAN_ALLOWLIST", "http://example.com")
    with pytest.raises(ConfigError, match="SCAN_ALLOWLIST"):
        load_settings(tmp_path / "none.env")


def test_example_env_allowlist_covers_the_juice_shop_setup():
    from dotenv import dotenv_values

    values = dotenv_values(Path(__file__).resolve().parent.parent / ".env.example")
    allowlist = parse_allowlist(values["SCAN_ALLOWLIST"])
    assert is_target_allowed("http://host.docker.internal:3000", allowlist)
    assert is_target_allowed("http://localhost:3000", allowlist)
    assert not is_target_allowed("https://example.com", allowlist)


# --- R045: `riskrank scan` integration --------------------------------------------------


@pytest.fixture
def scan_with_allowlist(monkeypatch):
    """Run `riskrank scan --yes <url>` with a given allowlist; ZAP is never reached
    in these tests (from_settings is replaced by a marker)."""
    zap_created = []

    def run(url, allowlist):
        settings = Settings("http://zap", "key", "", "m", "sqlite:///x.db")
        settings.scan_allowlist = allowlist
        monkeypatch.setattr(cli, "load_settings", lambda: settings)

        def fake_from_settings(cls, s):
            zap_created.append(url)
            raise cli.ConfigError("stop here")

        monkeypatch.setattr(cli.ZapClient, "from_settings", classmethod(fake_from_settings))
        return runner.invoke(app, ["scan", "--yes", url])

    run.zap_created = zap_created
    return run


def test_scan_refused_for_target_not_on_allowlist(scan_with_allowlist):
    result = scan_with_allowlist("https://example.com", ["localhost", "*.juice.local"])
    assert result.exit_code == cli.EXIT_NOT_ALLOWED
    assert "not on the scan allowlist" in result.output
    assert "localhost, *.juice.local" in result.output
    assert "SCAN_ALLOWLIST" in result.output


def test_allowlist_applies_even_with_yes(scan_with_allowlist):
    """--yes confirms ownership but can't override the allowlist."""
    result = scan_with_allowlist("https://example.com", ["localhost"])
    assert result.exit_code == cli.EXIT_NOT_ALLOWED


def test_scan_proceeds_for_allowed_target(scan_with_allowlist):
    result = scan_with_allowlist("http://host.docker.internal:3000", ["host.docker.internal"])
    assert result.exit_code != cli.EXIT_NOT_ALLOWED
    assert "not on the scan allowlist" not in result.output


def test_empty_allowlist_does_not_restrict(scan_with_allowlist):
    result = scan_with_allowlist("https://example.com", [])
    assert result.exit_code != cli.EXIT_NOT_ALLOWED


def test_non_http_target_is_refused_even_without_allowlist(scan_with_allowlist):
    result = scan_with_allowlist("ftp://example.com", [])
    assert result.exit_code == cli.EXIT_NOT_ALLOWED
    assert "(any http/https URL)" in result.output
