"""FastAPI app for the riskrank dashboard.

Served alongside the CLI with `riskrank serve` (see cli.py), which runs
this module's create_app() under uvicorn. The app shares the CLI's
configuration (.env) and database: every `riskrank scan` saves to the same
SQLite file the dashboard reads.

Tickets: R035, R036, R037, R038
"""

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from sqlalchemy import func, select, text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from riskrank import __version__
from riskrank.config import load_settings
from riskrank.dashboard.schemas import (
    FindingOut,
    IssueOut,
    PriorityTier,
    ScanDetail,
    ScanList,
    ScanSummary,
    TierCounts,
    TopFinding,
)
from riskrank.report.markdown import group_into_issues
from riskrank.report.persistence import (
    FindingRecord,
    ScanRecord,
    get_engine,
    get_session_factory,
    init_db,
    record_to_finding,
)
from riskrank.triage.triage import rank_findings

DEFAULT_PAGE_SIZE = 50
MAX_PAGE_SIZE = 200


def get_session(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one database session per request."""
    with request.app.state.session_factory() as session:
        yield session


# Route parameter type: "give this endpoint a database session".
DbSession = Annotated[Session, Depends(get_session)]


def _not_implemented(ticket: str) -> HTTPException:
    return HTTPException(status_code=501, detail=f"Not implemented yet ({ticket}).")


def create_app(database_url: str | None = None) -> FastAPI:
    """Build the dashboard app.

    Args:
        database_url: SQLite URL to read scans from. Defaults to
            DATABASE_URL from .env / the environment, i.e. the same database
            `riskrank scan` writes to.
    """

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        url = database_url or load_settings().database_url
        engine = get_engine(url)
        init_db(engine)  # a fresh install has no scans yet, but the tables exist
        app.state.engine = engine
        app.state.session_factory = get_session_factory(engine)
        try:
            yield
        finally:
            engine.dispose()

    app = FastAPI(
        title="riskrank dashboard",
        version=__version__,
        description="Scan history and AI-prioritized findings from riskrank.",
        lifespan=lifespan,
    )

    @app.get("/health", tags=["meta"])
    def health(session: DbSession) -> dict:
        """Liveness check: the app is up and can reach its database."""
        try:
            session.execute(text("SELECT 1"))
        except SQLAlchemyError as exc:
            raise HTTPException(status_code=503, detail="Database unavailable") from exc
        return {"status": "ok", "version": __version__}

    @app.get("/scans", tags=["scans"], response_model=ScanList)
    def list_scans(
        session: DbSession,
        target: Annotated[
            str | None, Query(description="Only scans of this exact target URL.")
        ] = None,
        limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
        offset: Annotated[int, Query(ge=0)] = 0,
    ) -> ScanList:
        """List past scans, newest first, with per-tier counts and the top finding."""
        return list_scan_summaries(session, target=target, limit=limit, offset=offset)

    # NOTE: /scans/trend must be registered before /scans/{scan_id}. FastAPI matches
    # routes in declaration order, so otherwise "trend" is parsed as a scan_id and
    # the request fails with a 422.
    @app.get("/scans/trend", tags=["scans"])
    def get_trend(session: DbSession) -> dict:
        """Get aggregated risk-over-time data across all scans.

        TODO (R038): aggregate scores per scan date for a trend chart.
        """
        raise _not_implemented("R038")

    @app.get(
        "/scans/{scan_id}",
        tags=["scans"],
        response_model=ScanDetail,
        responses={404: {"description": "No scan with this ID"}},
    )
    def get_scan(
        scan_id: int,
        session: DbSession,
        tier: Annotated[
            list[PriorityTier] | None,
            Query(description="Only issues/findings in these tiers (repeatable)."),
        ] = None,
    ) -> ScanDetail:
        """One scan's findings: grouped issues and individual findings, AI-ranked."""
        detail = get_scan_detail(session, scan_id, tiers=tier)
        if detail is None:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")
        return detail

    return app


# --- R036: scan history ------------------------------------------------------------


def list_scan_summaries(
    session: Session,
    target: str | None = None,
    limit: int = DEFAULT_PAGE_SIZE,
    offset: int = 0,
) -> ScanList:
    """Build one page of scan history with three queries in total (scans,
    tier counts, top findings), however many scans are on the page."""
    filters = [ScanRecord.target_url == target] if target else []

    total = session.scalar(select(func.count()).select_from(ScanRecord).where(*filters)) or 0
    scans = session.scalars(
        select(ScanRecord)
        .where(*filters)
        .order_by(ScanRecord.scanned_at.desc(), ScanRecord.id.desc())
        .limit(limit)
        .offset(offset)
    ).all()
    return ScanList(items=_summarize(session, scans), total=total, limit=limit, offset=offset)


def _summarize(session: Session, scans: list[ScanRecord]) -> list[ScanSummary]:
    """Summary rows for these scans in two queries (tier counts, top findings)."""
    scan_ids = [scan.id for scan in scans]

    tier_counts: dict[int, TierCounts] = {scan_id: TierCounts() for scan_id in scan_ids}
    if scan_ids:
        rows = session.execute(
            select(FindingRecord.scan_id, FindingRecord.priority_tier, func.count())
            .where(FindingRecord.scan_id.in_(scan_ids), FindingRecord.priority_tier.is_not(None))
            .group_by(FindingRecord.scan_id, FindingRecord.priority_tier)
        )
        for scan_id, tier, count in rows:
            setattr(tier_counts[scan_id], tier, count)

    top_findings = _top_findings(session, scan_ids)

    return [
        ScanSummary(
            id=scan.id,
            target_url=scan.target_url,
            scanned_at=scan.scanned_at,
            riskrank_version=scan.riskrank_version,
            finding_count=scan.finding_count,
            triaged_count=sum(tier_counts[scan.id].model_dump().values()),
            tier_counts=tier_counts[scan.id],
            top_finding=top_findings.get(scan.id),
        )
        for scan in scans
    ]


def _top_findings(session: Session, scan_ids: list[int]) -> dict[int, TopFinding]:
    """Highest-priority triaged finding per scan, using the same tie-breaks as
    rank_findings(): score, then exploitability, then original order."""
    if not scan_ids:
        return {}
    ranked = (
        select(
            FindingRecord.scan_id,
            FindingRecord.type,
            FindingRecord.endpoint,
            FindingRecord.priority_tier,
            FindingRecord.priority_score,
            func.row_number()
            .over(
                partition_by=FindingRecord.scan_id,
                order_by=(
                    FindingRecord.priority_score.desc(),
                    FindingRecord.exploitability_score.desc(),
                    FindingRecord.id,
                ),
            )
            .label("position"),
        )
        .where(FindingRecord.scan_id.in_(scan_ids), FindingRecord.priority_score.is_not(None))
        .subquery()
    )
    rows = session.execute(select(ranked).where(ranked.c.position == 1))
    return {
        row.scan_id: TopFinding(
            type=row.type,
            endpoint=row.endpoint,
            priority_tier=row.priority_tier,
            priority_score=row.priority_score,
        )
        for row in rows
    }


# --- R037: scan detail ---------------------------------------------------------------


def get_scan_detail(
    session: Session, scan_id: int, tiers: list[str] | None = None
) -> ScanDetail | None:
    """A scan's summary plus its issues and findings, AI-ranked.

    Uses the same ranking (rank_findings) and grouping (group_into_issues)
    as the CLI and the Markdown report, so all three always agree. tiers
    filters issues and findings to those priority tiers; the summary always
    describes the whole scan. Returns None if the scan doesn't exist.
    """
    scan = session.get(ScanRecord, scan_id)
    if scan is None:
        return None

    records = session.scalars(
        select(FindingRecord).where(FindingRecord.scan_id == scan_id).order_by(FindingRecord.id)
    ).all()
    ranked = rank_findings([record_to_finding(r) for r in records])
    issues = group_into_issues(ranked)

    wanted = set(tiers) if tiers else None
    if wanted is not None:
        ranked = [f for f in ranked if f.priority_tier in wanted]

    return ScanDetail(
        scan=_summarize(session, [scan])[0],
        issues=[
            IssueOut(
                rank=position,
                type=issue.type,
                severity_raw=issue.severity_raw,
                priority_tier=issue.tier,
                priority_score=issue.score,
                exploitability_score=issue.exploitability,
                business_impact_score=issue.impact,
                cwe_id=issue.cwe_id,
                explanation=issue.explanation,
                suggested_fix=issue.suggested_fix,
                evidence=issue.evidence,
                endpoints=issue.all_endpoints,
                occurrences=issue.occurrences,
            )
            for position, issue in enumerate(issues, start=1)
            if wanted is None or issue.tier in wanted
        ],
        findings=[FindingOut(**f.model_dump()) for f in ranked],
    )
