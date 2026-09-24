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
from sqlalchemy import func, or_, select, text
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
    Trend,
    TrendPoint,
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
DEFAULT_TREND_POINTS = 100
MAX_TREND_POINTS = 1000


def get_session(request: Request) -> Iterator[Session]:
    """FastAPI dependency: one database session per request."""
    with request.app.state.session_factory() as session:
        yield session


# Route parameter type: "give this endpoint a database session".
DbSession = Annotated[Session, Depends(get_session)]


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
    @app.get("/scans/trend", tags=["scans"], response_model=Trend)
    def get_trend(
        session: DbSession,
        target: Annotated[
            str | None, Query(description="Only scans of this exact target URL.")
        ] = None,
        limit: Annotated[
            int, Query(ge=1, le=MAX_TREND_POINTS, description="Most recent N scans.")
        ] = DEFAULT_TREND_POINTS,
    ) -> Trend:
        """Risk over time: one point per scan, oldest first, for the trend chart."""
        return get_risk_trend(session, target=target, limit=limit)

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

    # HTML pages (R039-R043) are registered after the JSON routes.
    from riskrank.dashboard.pages import router as pages_router

    app.include_router(pages_router)
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

    tier_counts = _tier_counts(session, scan_ids)

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


def _tier_counts(session: Session, scan_ids: list[int]) -> dict[int, TierCounts]:
    """Triaged findings per tier for each scan, in one query."""
    counts = {scan_id: TierCounts() for scan_id in scan_ids}
    if scan_ids:
        rows = session.execute(
            select(FindingRecord.scan_id, FindingRecord.priority_tier, func.count())
            .where(FindingRecord.scan_id.in_(scan_ids), FindingRecord.priority_tier.is_not(None))
            .group_by(FindingRecord.scan_id, FindingRecord.priority_tier)
        )
        for scan_id, tier, count in rows:
            setattr(counts[scan_id], tier, count)
    return counts


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


# --- R038: risk trend --------------------------------------------------------------------


def get_risk_trend(
    session: Session, target: str | None = None, limit: int = DEFAULT_TREND_POINTS
) -> Trend:
    """One point per scan (the most recent `limit`), oldest first.

    risk_score = sum over distinct issue types of that type's highest
    priority score, matching how the report groups findings. Three queries
    in total: scans, per-issue maxima, and tier counts.

    Scans that have findings but no AI triage (--no-triage, or no LLM key)
    are left out: they have no risk score, and plotting them as 0 would show
    a false drop. A scan with no findings at all is a genuine 0.
    """
    has_triaged_finding = (
        select(FindingRecord.id)
        .where(FindingRecord.scan_id == ScanRecord.id, FindingRecord.priority_score.is_not(None))
        .exists()
    )
    filters = [or_(ScanRecord.finding_count == 0, has_triaged_finding)]
    if target:
        filters.append(ScanRecord.target_url == target)
    newest = session.scalars(
        select(ScanRecord)
        .where(*filters)
        .order_by(ScanRecord.scanned_at.desc(), ScanRecord.id.desc())
        .limit(limit)
    ).all()
    scans = list(reversed(newest))
    scan_ids = [scan.id for scan in scans]

    # Highest score per (scan, issue type), then aggregated per scan.
    per_issue = (
        select(
            FindingRecord.scan_id.label("scan_id"),
            func.max(FindingRecord.priority_score).label("issue_score"),
        )
        .where(FindingRecord.scan_id.in_(scan_ids), FindingRecord.priority_score.is_not(None))
        .group_by(FindingRecord.scan_id, FindingRecord.type)
        .subquery()
    )
    aggregates = {
        row.scan_id: row
        for row in session.execute(
            select(
                per_issue.c.scan_id,
                func.count().label("issue_count"),
                func.sum(per_issue.c.issue_score).label("risk_score"),
                func.max(per_issue.c.issue_score).label("max_score"),
            ).group_by(per_issue.c.scan_id)
        )
    }
    tier_counts = _tier_counts(session, scan_ids)

    points: list[TrendPoint] = []
    previous: dict[str, int] = {}  # target -> last risk_score
    for scan in scans:
        agg = aggregates.get(scan.id)
        risk = int(agg.risk_score) if agg else 0
        counts = tier_counts[scan.id]
        points.append(
            TrendPoint(
                scan_id=scan.id,
                target_url=scan.target_url,
                scanned_at=scan.scanned_at,
                finding_count=scan.finding_count,
                triaged_count=sum(counts.model_dump().values()),
                issue_count=agg.issue_count if agg else 0,
                risk_score=risk,
                max_score=agg.max_score if agg else None,
                tier_counts=counts,
                change=risk - previous[scan.target_url] if scan.target_url in previous else None,
            )
        )
        previous[scan.target_url] = risk
    return Trend(target=target, points=points)
