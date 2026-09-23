"""CLI entry point for riskrank.

Usage:
    riskrank scan <url>

Tickets: R015, R016
"""

import typer
from rich.console import Console
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

from riskrank.config import ConfigError, load_settings
from riskrank.report.console import print_findings
from riskrank.scanner.models import Finding
from riskrank.scanner.normalizer import normalize_alerts
from riskrank.scanner.zap_client import ZapClient, ZapError

app = typer.Typer(help="riskrank — AI-powered vulnerability scanner and prioritizer.")
console = Console()
err_console = Console(stderr=True)

EXIT_SCAN_FAILED = 1
EXIT_CONFIG_ERROR = 2


@app.callback()
def main() -> None:
    """riskrank — AI-powered vulnerability scanner and prioritizer."""
    # An explicit callback keeps Typer in multi-command mode, so the CLI is
    # invoked as `riskrank scan <url>`. Without it, Typer collapses a
    # single-command app and `scan` would be rejected as an extra argument.


def run_scan(client: ZapClient, url: str) -> list[Finding]:
    """Spider + active-scan url with ZAP and return normalized findings."""
    version = client.check_connection()
    console.print(f"Connected to ZAP {version}")

    with Progress(
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        spider_task = progress.add_task("Crawling (spider)", total=100)
        client.run_spider(url, on_progress=lambda p: progress.update(spider_task, completed=p))

        scan_task = progress.add_task("Active scan", total=100)
        client.run_active_scan(url, on_progress=lambda p: progress.update(scan_task, completed=p))

    return normalize_alerts(client.get_alerts(url))


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

    TODO (R017): write findings to --output as JSON
    TODO (R018-R034): wire up triage -> ranking -> report generation (Phase 2)
    """
    console.print(f"[bold]riskrank[/bold] scanning {url}")

    try:
        client = ZapClient.from_settings(load_settings())
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {exc}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc

    try:
        findings = run_scan(client, url)
    except ZapError as exc:
        err_console.print(f"[red]Scan failed:[/red] {exc}")
        raise typer.Exit(EXIT_SCAN_FAILED) from exc

    print_findings(findings, console=console)


if __name__ == "__main__":
    app()
