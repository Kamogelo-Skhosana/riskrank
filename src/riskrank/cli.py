"""CLI entry point for riskrank.

Usage:
    riskrank scan <url>     scan a target, triage and report the findings
    riskrank serve          run the web dashboard for saved scans
    riskrank demo           load sample scans for a demo (no ZAP or AI needed)

Tickets: R015, R016, R017, R019, R031, R033, R034, R035, R044, R045, R049
"""

from collections.abc import Callable
from pathlib import Path
from typing import Annotated

import typer
import uvicorn
from rich.console import Console
from rich.markup import escape
from rich.progress import BarColumn, Progress, TaskProgressColumn, TextColumn
from sqlalchemy.exc import SQLAlchemyError

from riskrank.config import ConfigError, Settings, load_settings
from riskrank.dashboard.safeguard import (
    OWNERSHIP_WARNING,
    confirm_target_ownership,
    is_target_allowed,
)
from riskrank.report.console import print_findings
from riskrank.report.json_export import export_json
from riskrank.report.markdown import generate_markdown_report, write_report
from riskrank.report.persistence import get_engine, save_scan
from riskrank.scanner.models import Finding
from riskrank.scanner.normalizer import normalize_alerts
from riskrank.scanner.zap_client import (
    DEFAULT_READY_TIMEOUT_SECONDS,
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
EXIT_NOT_CONFIRMED = 3
EXIT_NOT_ALLOWED = 4


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


def _nothing_crawled_message(url: str) -> str:
    hint = (
        " From inside Docker, 'localhost' means ZAP's own container: use "
        "http://host.docker.internal:<port> to reach an app on your computer."
        if "localhost" in url or "127.0.0.1" in url
        else ""
    )
    return (
        f"ZAP's crawl found no pages at {url}, so there is nothing to scan. Check that "
        "the app is running (docker ps) and reachable from ZAP's container." + hint
    )


def run_scan(
    client: ZapClient,
    url: str,
    max_scan_minutes: float = DEFAULT_MAX_SCAN_MINUTES,
    zap_wait_seconds: float = DEFAULT_READY_TIMEOUT_SECONDS,
    fresh_session: bool = True,
) -> list[Finding]:
    """Spider + active-scan url with ZAP and return normalized findings.

    Waits for ZAP to finish starting (up to zap_wait_seconds) and, by
    default, starts a fresh ZAP session so alerts from earlier scans can't
    leak into this one. If the spider or the active scan runs past its time
    limit, it is stopped in ZAP and the scan continues with the alerts found
    up to that point, instead of throwing away a long scan's results.
    """
    version = client.wait_until_ready(
        timeout=zap_wait_seconds,
        on_waiting=lambda: console.print("Waiting for ZAP to start..."),
    )
    console.print(f"Connected to ZAP {version}")
    if fresh_session:
        client.new_session()

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

        if client.count_urls(url) == 0:
            raise ZapError(_nothing_crawled_message(url))

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


def _require_ownership_confirmation(url: str, yes: bool) -> None:
    """Stop unless the user confirms they may scan url (R044). Runs before
    any settings are loaded or anything is sent to ZAP or the target."""
    if not yes:
        err_console.print(f"[yellow]{OWNERSHIP_WARNING}[/yellow]", soft_wrap=True)
    result = confirm_target_ownership(url, assume_yes=yes)
    if result.confirmed:
        return
    if result.method == "non-interactive":
        err_console.print(
            "[red]Scan refused:[/red] no one confirmed that you may test this target. "
            "Run interactively to answer the prompt, or pass --yes if you own it or "
            "have permission.",
            soft_wrap=True,
        )
    else:
        err_console.print("[red]Scan cancelled:[/red] target ownership not confirmed.")
    raise typer.Exit(EXIT_NOT_CONFIRMED)


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
    yes: Annotated[
        bool,
        typer.Option(
            "--yes",
            "-y",
            help=(
                "Confirm you own the target or have written permission to test it, "
                "skipping the prompt (for scripts). You are responsible for this."
            ),
        ),
    ] = False,
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
    zap_wait_seconds: Annotated[
        float,
        typer.Option(
            "--zap-wait-seconds",
            min=0,
            help="How long to wait for ZAP to finish starting (e.g. right after docker compose up).",
        ),
    ] = DEFAULT_READY_TIMEOUT_SECONDS,
    keep_zap_session: Annotated[
        bool,
        typer.Option(
            "--keep-zap-session",
            help="Reuse ZAP's current session instead of starting a fresh one (keeps old alerts).",
        ),
    ] = False,
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
    _require_ownership_confirmation(url, yes)

    try:
        settings = load_settings()
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc

    if not is_target_allowed(url, settings.scan_allowlist):
        allowed = ", ".join(settings.scan_allowlist) or "(any http/https URL)"
        err_console.print(
            f"[red]Scan refused:[/red] {escape(url)} is not on the scan allowlist. "
            f"Allowed: {escape(allowed)}. Add the host to SCAN_ALLOWLIST in .env if you "
            "own it or have permission to test it.",
            soft_wrap=True,
        )
        raise typer.Exit(EXIT_NOT_ALLOWED)

    try:
        client = ZapClient.from_settings(settings)
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc

    # Check the context file and LLM settings before the (long) scan, so a
    # typo or missing key fails fast.
    context_config = _load_target_context(context)
    llm = _llm_for_scan(triage, settings)

    try:
        findings = run_scan(
            client,
            url,
            max_scan_minutes,
            zap_wait_seconds=zap_wait_seconds,
            fresh_session=not keep_zap_session,
        )
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


LOCAL_HOSTS = {"127.0.0.1", "localhost", "::1"}


@app.command()
def serve(
    host: Annotated[
        str | None,
        typer.Option(help="Address to listen on. Default: DASHBOARD_HOST (127.0.0.1)."),
    ] = None,
    port: Annotated[
        int | None,
        typer.Option(min=1, max=65535, help="Port to listen on. Default: DASHBOARD_PORT (8000)."),
    ] = None,
    reload: Annotated[
        bool, typer.Option(help="Restart automatically when code changes (development).")
    ] = False,
):
    """Run the web dashboard for saved scans (reads DATABASE_URL)."""
    try:
        settings = load_settings()
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc

    host = host or settings.dashboard_host
    port = port or settings.dashboard_port
    if host not in LOCAL_HOSTS:
        err_console.print(
            f"[yellow]Warning: listening on {escape(host)} makes the dashboard reachable "
            "from other machines, and it has no login yet.[/yellow]",
            soft_wrap=True,
        )
    shown_host = "localhost" if host in {"127.0.0.1", "0.0.0.0", "::1", "::"} else host
    console.print(f"riskrank dashboard: http://{shown_host}:{port}  (Ctrl+C to stop)")
    uvicorn.run(
        "riskrank.dashboard.api:create_app",
        factory=True,
        host=host,
        port=port,
        reload=reload,
    )


@app.command()
def demo(
    force: Annotated[
        bool, typer.Option("--force", help="Add the demo scans again even if already loaded.")
    ] = False,
):
    """Load sample scan history for a demo (no ZAP, target or AI key needed)."""
    from riskrank.demo import DEMO_TARGET, seed_demo_data

    try:
        settings = load_settings()
    except ConfigError as exc:
        err_console.print(f"[red]Configuration error:[/red] {escape(str(exc))}")
        raise typer.Exit(EXIT_CONFIG_ERROR) from exc

    engine = get_engine(settings.database_url)
    try:
        scan_ids = seed_demo_data(engine, force=force)
    finally:
        engine.dispose()

    if not scan_ids:
        console.print(
            f"Demo scans of {escape(DEMO_TARGET)} are already loaded. "
            "Use --force to add them again.",
            soft_wrap=True,
        )
        return
    console.print(
        f"Loaded {len(scan_ids)} sample scans of {escape(DEMO_TARGET)} "
        f"(scan IDs {scan_ids[0]}-{scan_ids[-1]}). These are sample data for demos, "
        "not a real scan.",
        soft_wrap=True,
    )
    console.print("Open the dashboard with: riskrank serve")


if __name__ == "__main__":
    app()
