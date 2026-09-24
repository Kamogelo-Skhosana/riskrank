"""Server-rendered HTML pages for the dashboard.

The pages are built from the same query functions as the JSON API (api.py),
so what you see in the browser always matches /scans, /scans/{id} and
/scans/trend. Templates live in dashboard/templates/ and are auto-escaped:
target URLs, endpoints and AI text can't inject HTML.

Tickets: R039, R040, R041, R042, R043
"""

from datetime import datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from riskrank import __version__
from riskrank.dashboard.api import list_scan_summaries

PAGE_SIZE = 25
TEMPLATES = Jinja2Templates(directory=Path(__file__).resolve().parent / "templates")


def _format_time(value: datetime) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC")


TEMPLATES.env.filters["utc"] = _format_time
TEMPLATES.env.globals["riskrank_version"] = __version__

router = APIRouter(include_in_schema=False)  # pages aren't part of the JSON API docs


def _page_url(request: Request, target: str | None, page: int) -> str:
    """URL of another page of the scan list, keeping the target filter."""
    params = {}
    if target:
        params["target"] = target
    if page > 1:
        params["page"] = page
    return request.url.path + (f"?{urlencode(params)}" if params else "")


@router.get("/", response_class=HTMLResponse, name="scan_list_page")
def scan_list_page(
    request: Request,
    target: Annotated[str | None, Query()] = None,
    page: Annotated[int, Query(ge=1)] = 1,
) -> HTMLResponse:
    """Scan history: date, target, findings and the top-priority finding (R039)."""
    with request.app.state.session_factory() as session:
        scans = list_scan_summaries(
            session, target=target or None, limit=PAGE_SIZE, offset=(page - 1) * PAGE_SIZE
        )
    page_count = max(1, -(-scans.total // PAGE_SIZE))  # ceiling division

    return TEMPLATES.TemplateResponse(
        request,
        "scans.html",
        {
            "scans": scans,
            "target": target or "",
            "page": page,
            "page_count": page_count,
            "prev_url": _page_url(request, target=target, page=page - 1) if page > 1 else None,
            "next_url": (
                _page_url(request, target=target, page=page + 1) if page < page_count else None
            ),
        },
    )
