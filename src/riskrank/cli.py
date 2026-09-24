"""CLI entry point for riskrank.

Usage:
    riskrank scan <url>

Tickets: R015, R016, R017, R019, R031, R033, R034
"""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from sqlalchemy.exc import SQLAlchemyError

from riskrank.config import ConfigError, Settings, load_settings
from riskrank.report.console import print_findings
from riskrank.report.json_export import export_json
from riskrank.report.markdown import generate_markdown_report, write_report
from riskrank.report.persistence import get_engine, save_scan
from riskrank.scanner.models import Finding
from riskrank.scanner.normalizer import normalize_alerts
from riskrank.scanner.zap_client import (
    DEFAULT_SPIDER_TIMEOUT_SECONDS,
    ZapClient,
    ZapError,
    ZapScanTimeoutError,
)
from riskrank.triage.context import ContextConfig, ContextConfigError, load_context_config
from riskrank.triage.llm_client import LLMClient
from riskrank.triage.triage import triage_findings

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


DEFAULT_MAX_SCAN_MINUTES = 60


def _stop_after_timeout(
    stop: Callable[[str], None], exc: ZapScanTimeoutError, what: str, minutes: float
) -> None:
    """Stop a scan that hit the time limit and warn that results are partial."""
    try:
        stop(exc.scan_id)
    except ZapError as stop_exc:
        err_console.print(
            f"[yellow]Could not stop the {what} in ZAP ({escape(str(stop_exc))}); "
            "it may keep running in the background. Restart ZAP to clear it.[/yellow]"
        )
    err_console.print(
        f"[yellow]Warning: the {what} hit the {minutes:g}-minute limit at "
        f"{exc.progress}% and was stopped. Continuing with what was found so far, "
        "so results are partial. Use --max-scan-minutes to allow longer.[/yellow]",
        soft_wrap=True,
    )


def run_scan(
    client: ZapClient, url: str, max_scan_minutes: float = DEFAULT_MAX_SCAN_MINUTES
) -> list[Finding]:
    """Spider + active-scan url with ZAP and return normalized findings.

    If the spider or the active scan runs past its time limit, it is stopped
    in ZAP and the scan continues with the alerts found up to that point,
    instead of throwing away a long scan's results.
    """
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
        try:
            client.run_spider(url, on_progress=lambda p: progress.update(spider_task, completed=p))
        except ZapScanTimeoutError as exc:
            _stop_after_timeout(
                client.stop_spider, exc, "crawl", DEFAULT_SPIDER_TIMEOUT_SECONDS / 60
            )

        scan_task = progress.add_task("Active scan", total=100)
        try:
            client.run_active_scan(
                url,
                timeout=max_scan_minutes * 60,
                on_progress=lambda p: progress.update(scan_task, completed=p),
            )
        except ZapScanTimeoutError as exc:
            _stop_after_timeout(client.stop_active_scan, exc, "active scan", max_scan_minutes)

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


def _llm_for_scan(triage: bool | None, settings: Settings) -> LLMClient | None:
    """Decide whether this scan runs AI triage.

    --triage requires LLM_API_KEY (config error if missing); --no-triage
    skips it; by default triage runs whenever LLM_API_KEY is set.
    """
    if triage is False:
        return None
    try:
        return LLMClient.from_settings(settings)
    except ConfigError as exc:
        if triage is True:
            err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
            raise typer.Exit(EXIT_CONFIG_ERROR) from exc
        console.print(
            "[dim]AI triage skipped: set LLM_API_KEY in .env to rank findings "
            "by real-world risk.[/dim]"
        )
        return None


def run_triage(
    findings: list[Finding], llm: LLMClient, context_config: ContextConfig | None
) -> list[Finding]:
    """AI-triage findings with a progress bar; never fails the scan."""
    if not findings:
        return findings
    with Progress(
        TextColumn("{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:
        task = progress.add_task("AI triage", total=None)

        def on_progress(done: int, total: int) -> None:
            progress.update(task, completed=done, total=total)

        summary = triage_findings(findings, llm, context_config, on_progress=on_progress)

    console.print(
        f"Triaged {summary.triaged} of {len(findings)} finding(s) "
        f"using {summary.llm_calls} AI call(s) ({summary.groups} distinct issue group(s))",
        soft_wrap=True,
    )
    if summary.failed:
        err_console.print(
            f"[yellow]Warning: {summary.failed} finding(s) could not be triaged and are "
            "listed as not triaged.[/yellow]"
        )
        for error in summary.errors[:5]:
            err_console.print(f"  [yellow]-[/yellow] {escape(error)}", soft_wrap=True)
    return summary.findings


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
        Path | None,
        typer.Option(
            "--report", "-r", help="Also write a prioritized Markdown report to this file."
        ),
    ] = None,
    max_scan_minutes: Annotated[
        float,
        typer.Option(
            "--max-scan-minutes",
            min=1,
            help=(
                "Stop the active scan after this many minutes and continue with the "
                "findings so far."
            ),
        ),
    ] = DEFAULT_MAX_SCAN_MINUTES,
    triage: Annotated[
        bool | None,
        typer.Option(
            "--triage/--no-triage",
            help=(
                "Rank findings with AI triage. Default: on when LLM_API_KEY is set; "
                "--triage makes it required, --no-triage skips it."
            ),
            show_default=False,
        ),
    ] = None,
    save: Annotated[
        bool,
        typer.Option(
            "--save/--no-save",
            help="Save the scan and its findings to the database (DATABASE_URL in .env).",
        ),
    ] = True,
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
    """Scan URL with ZAP, AI-triage the findings, and print/save the results."""
    console.print(f"[bold]riskrank[/bold] scanning {escape(url)}")

    try:
        settings = load_settings()
        client = ZapClient.from_settings(settings)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc

    # Check the context file and LLM settings before the (long) scan, so a
    # typo or missing key fails fast.
    context_config = _load_target_context(context)
    llm = _llm_for_scan(triage, settings)

    try:
        findings = run_scan(client, url, max_scan_minutes)
    except ZapError as exc:
        err_console.print(f"[red]Scan failed:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_SCAN_FAILED) from exc

    if llm is not None:
        findings = run_triage(findings, llm, context_config)

    print_findings(findings, console=console)

    if output is not None:
        saved_to = _write_or_exit(
            "JSON output", output, lambda: export_json(findings, output, target_url=url)
        )
        console.print(
            f"Saved {len(findings)} finding(s) to {escape(str(saved_to))}", soft_wrap=True
        )

    if report is not None:
        saved_to = _write_or_exit(
            "Markdown report",
            report,
            lambda: write_report(generate_markdown_report(url, findings), report),
        )
        console.print(f"Saved Markdown report to {escape(str(saved_to))}", soft_wrap=True)

    if save:
        _save_to_database(settings.database_url, url, findings)


def _save_to_database(database_url: str, url: str, findings: list[Finding]) -> None:
    """Save the scan to the database. A failure here is reported as a warning
    rather than failing the command: the scan itself succeeded and any
    --output/--report files have already been written."""
    try:
        engine = get_engine(database_url)
        try:
            scan_id = save_scan(engine, url, findings)
        finally:
            engine.dispose()
    except (SQLAlchemyError, OSError) as exc:
        err_console.print(
            f"[yellow]Warning: could not save the scan to the database:[/yellow] "
            f"{escape(str(exc).splitlines()[0])}"
        )
        return
    console.print(f"Saved scan #{scan_id} to the database", soft_wrap=True)


def _write_or_exit(what: str, path: Path, write: Callable[[], Path]) -> Path:
    """Run write(); on OSError print a clear message and exit with EXIT_SCAN_FAILED."""
    try:
        return write()
    except OSError as exc:
        err_console.print(
            f"[red]Could not write {what} to {escape(str(path))}:[/red] {escape(str(exc))}"
        )
        raise typer.Exit(EXIT_SCAN_FAILED) from exc


if __name__ == "__main__":
    app()
