"""Tests for the CLI entry point.

Ticket: R015
"""

from typer.testing import CliRunner

from riskrank.cli import app

runner = CliRunner()


def test_scan_subcommand_accepts_url():
    """`riskrank scan <url>` must be accepted as a subcommand."""
    result = runner.invoke(app, ["scan", "http://localhost:3000"])
    assert result.exit_code == 0
    assert "http://localhost:3000" in result.output


def test_help_lists_scan_command():
    result = runner.invoke(app, ["--help"])
    assert result.exit_code == 0
    assert "scan" in result.output
