"""CLI entry point for riskrank.

Usage:
    riskrank scan <url>

Tickets: R015, R016, R017, R019
"""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn

from riskrank.config import ConfigError, load_settings
from riskrank.report.console import print_findings
from riskrank.report.json_export import export_json
from riskrank.scanner.models import Finding
from riskrank.scanner.normalizer import normalize_alerts
from riskrank.scanner.zap_client import ZapClient, ZapError
from riskrank.triage.context import ContextConfig, ContextConfigError, load_context_config

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


def _load_target_context(path: Path | None) -> ContextConfig | None:
    """Load --context if given, exiting with a config error if it's invalid."""
    if path is None:
        return None
    try:
        config = load_context_config(path)
    except ContextConfigError as exc:
        err_console.print(f"[red]Context file error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc
    console.print(
        f"Using target context from {escape(str(path))} "
        f"({len(config.endpoints)} endpoint rule(s))",
        soft_wrap=True,
    )
    return config


@app.command()
def scan(
    url: Annotated[
        str,
        typer.Argument(
            help="Target URL to scan. Must be a target you own or have permission to test."
        ),
    ],
    output: Annotated[
        Path | None,
        typer.Option("--output", "-o", help="Also write the raw findings to this JSON file."),
    ] = None,
    report: Annotated[
        str | None,
        typer.Option(help="Path to write the prioritized Markdown report (Phase 2)."),
    ] = None,
    context: Annotated[
        Path | None,
        typer.Option(
            "--context",
            "-c",
            help=(
                "TOML file describing the target (public/sensitive/auth per endpoint). "
                "See examples/context.example.toml."
            ),
        ),
    ] = None,
):
    """Run a full scan against URL and print/save the results."""
    # TODO (R018-R034): wire up triage -> ranking -> report generation (Phase 2)
    console.print(f"[bold]riskrank[/bold] scanning {escape(url)}")

    try:
        client = ZapClient.from_settings(load_settings())
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc

    # Validate the context file before the (long) scan, so a typo fails fast.
    # R023 will keep the returned config and pass it to the triage step.
    _load_target_context(context)

    try:
        findings = run_scan(client, url)
    except ZapError as exc:
        err_console.print(f"[red]Scan failed:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_SCAN_FAILED) from exc

    print_findings(findings, console=console)

    if output is not None:
        try:
            saved_to = export_json(findings, output, target_url=url)
        except OSError as exc:
            err_console.print(
                f"[red]Could not write JSON output to {escape(str(output))}:[/red] {escape(str(exc))}"
            )
            raise typer.Exit(EXIT_SCAN_FAILED) from exc
        console.print(
            f"Saved {len(findings)} finding(s) to {escape(str(saved_to))}", soft_wrap=True
        )


if __name__ == "__main__":
    app()
