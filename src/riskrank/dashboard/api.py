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
from riskrank.dashboard.schemas import ScanList, ScanSummary, TierCounts, TopFinding
from riskrank.report.persistence import (
    FindingRecord,
    ScanRecord,
    get_engine,
    get_session_factory,
    init_db,
)

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

    @app.get("/scans/{scan_id}", tags=["scans"])
    def get_scan(scan_id: int, session: DbSession) -> dict:
        """Get full findings detail for one scan.

        TODO (R037): query findings for scan_id, return ranked list.
        """
        raise _not_implemented("R037")

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

    items = [
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
    return ScanList(items=items, total=total, limit=limit, offset=offset)


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
