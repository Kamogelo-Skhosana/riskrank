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

from fastapi import Depends, FastAPI, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from riskrank import __version__
from riskrank.config import load_settings
from riskrank.report.persistence import get_engine, get_session_factory, init_db


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

    @app.get("/scans", tags=["scans"])
    def list_scans(session: DbSession) -> list[dict]:
        """List all past scans.

        TODO (R036): query the scans table, return summary rows
        (id, target_url, date, top_priority).
        """
        raise _not_implemented("R036")

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
