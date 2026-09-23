"""CLI entry point for riskrank.

Usage:
    riskrank scan <url>

Ticket: R015
"""

import typer

app = typer.Typer(help="riskrank — AI-powered vulnerability scanner and prioritizer.")


@app.command()
def scan(
    url: str = typer.Argument(
        ..., help="Target URL to scan. Must be a target you own or have permission to test."
    ),
    output: str = typer.Option(
        None, "--output", help="Path to write raw findings as JSON (Phase 1)."
    ),
    report: str = typer.Option(
        None, "--report", help="Path to write the prioritized Markdown report (Phase 2)."
    ),
):
    """Run a full scan against URL and print/save the results.

    TODO (R006-R017): wire up scanner -> normalizer -> CLI output (Phase 1)
    TODO (R018-R034): wire up triage -> ranking -> report generation (Phase 2)
    """
    typer.echo(f"[riskrank] Scanning {url} ... (not yet implemented — see docs/TICKETS.md)")


if __name__ == "__main__":
    app()
