"""Server-rendered HTML pages for the dashboard.

The pages are built from the same query functions as the JSON API (api.py),
so what you see in the browser always matches /scans, /scans/{id} and
/scans/trend. Templates live in dashboard/templates/ and are auto-escaped:
target URLs, endpoints and AI text can't inject HTML.

Tickets: R039, R040, R041, R042, R043
"""

import math
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Annotated
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select

from riskrank import __version__
from riskrank.dashboard.api import get_risk_trend, get_scan_detail, list_scan_summaries
from riskrank.dashboard.schemas import PriorityTier, TrendPoint
from riskrank.report.persistence import ScanRecord

PAGE_SIZE = 25
ENDPOINTS_SHOWN = 10  # per issue, before "show all"
TIER_FILTERS = ["Critical", "High", "Medium", "Low"]
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


@router.get("/scan/{scan_id}", response_class=HTMLResponse, name="scan_detail_page")
def scan_detail_page(
    request: Request,
    scan_id: int,
    tier: Annotated[PriorityTier | None, Query()] = None,
) -> HTMLResponse:
    """One scan's prioritized issues with explanations and fixes (R040)."""
    with request.app.state.session_factory() as session:
        detail = get_scan_detail(session, scan_id, tiers=[tier] if tier else None)
    if detail is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    triaged = [issue for issue in detail.issues if issue.priority_tier is not None]
    untriaged = [issue for issue in detail.issues if issue.priority_tier is None]
    return TEMPLATES.TemplateResponse(
        request,
        "scan.html",
        {
            "detail": detail,
            "scan": detail.scan,
            "triaged": triaged,
            "untriaged": untriaged,
            "tier": tier,
            "tier_filters": TIER_FILTERS,
            "endpoints_shown": ENDPOINTS_SHOWN,
        },
    )


# --- R041: risk trend chart --------------------------------------------------------------

CHART_WIDTH = 720
CHART_HEIGHT = 280
MARGIN_LEFT, MARGIN_RIGHT, MARGIN_TOP, MARGIN_BOTTOM = 48, 72, 16, 32
TREND_POINTS = 100


@dataclass
class ChartDot:
    x: float
    y: float
    point: TrendPoint


@dataclass
class TrendChart:
    """Pre-computed SVG geometry for a single-series line chart (risk over time)."""

    width: int
    height: int
    plot_left: float
    plot_right: float
    plot_top: float
    plot_bottom: float
    y_ticks: list[tuple[float, int]]  # (y position, value)
    x_labels: list[tuple[float, str, str]]  # (x position, text, text-anchor)
    dots: list[ChartDot]
    line_path: str
    area_path: str


def nice_ceiling(value: float) -> int:
    """Round up to a clean axis maximum with 4 equal whole-number steps
    (e.g. 121 -> 200 in steps of 50, 90 -> 100 in 25s, 9 -> 12 in 3s, 0 -> 4)."""
    raw_step = max(value, 0) / 4
    magnitude = 10 ** math.floor(math.log10(raw_step)) if raw_step >= 1 else 1
    for multiple in (1, 2, 2.5, 3, 5, 10):
        step = multiple * magnitude
        if step == int(step) and step >= raw_step:
            return int(step) * 4
    raise AssertionError("unreachable")  # pragma: no cover


def build_trend_chart(
    points: list[TrendPoint], width: int = CHART_WIDTH, height: int = CHART_HEIGHT
) -> TrendChart | None:
    """Lay out risk_score over time. X is proportional to scan time (so gaps
    between scans are honest); Y starts at zero. None when there's no data."""
    if not points:
        return None
    left, right = MARGIN_LEFT, width - MARGIN_RIGHT
    top, bottom = MARGIN_TOP, height - MARGIN_BOTTOM

    y_max = nice_ceiling(max(p.risk_score for p in points))

    def y_of(value: float) -> float:
        return round(bottom - (value / y_max) * (bottom - top), 2)

    times = [p.scanned_at.timestamp() for p in points]
    t_min, t_max = min(times), max(times)

    def x_of(index: int) -> float:
        if len(points) == 1:
            return round((left + right) / 2, 2)
        if t_max == t_min:  # all at the same instant: fall back to even spacing
            return round(left + index * (right - left) / (len(points) - 1), 2)
        return round(left + (times[index] - t_min) / (t_max - t_min) * (right - left), 2)

    dots = [ChartDot(x_of(i), y_of(p.risk_score), p) for i, p in enumerate(points)]
    line_path = "M" + " L".join(f"{d.x},{d.y}" for d in dots)
    area_path = f"{line_path} L{dots[-1].x},{bottom} L{dots[0].x},{bottom} Z"

    step = y_max // 4
    y_ticks = [(y_of(v), v) for v in range(0, y_max + 1, step)]

    first, last = dots[0], dots[-1]
    x_labels = [(first.x, first.point.scanned_at.strftime("%d %b %Y"), "start")]
    if len(dots) > 1 and last.point.scanned_at.date() != first.point.scanned_at.date():
        x_labels.append((last.x, last.point.scanned_at.strftime("%d %b %Y"), "end"))
    if len(dots) == 1:
        x_labels = [(first.x, first.point.scanned_at.strftime("%d %b %Y"), "middle")]

    return TrendChart(
        width=width,
        height=height,
        plot_left=left,
        plot_right=right,
        plot_top=top,
        plot_bottom=bottom,
        y_ticks=y_ticks,
        x_labels=x_labels,
        dots=dots,
        line_path=line_path,
        area_path=area_path,
    )


def _targets_newest_first(session) -> list[str]:
    rows = session.execute(
        select(ScanRecord.target_url, func.max(ScanRecord.scanned_at).label("latest"))
        .group_by(ScanRecord.target_url)
        .order_by(func.max(ScanRecord.scanned_at).desc())
    )
    return [row.target_url for row in rows]


@router.get("/trend", response_class=HTMLResponse, name="trend_page")
def trend_page(
    request: Request,
    target: Annotated[str | None, Query()] = None,
) -> HTMLResponse:
    """Risk score over time for one target (R041). Defaults to the most
    recently scanned target; scores of different targets aren't comparable,
    so they are never mixed on one line."""
    with request.app.state.session_factory() as session:
        targets = _targets_newest_first(session)
        selected = target if target else (targets[0] if targets else None)
        points = (
            get_risk_trend(session, target=selected, limit=TREND_POINTS).points if selected else []
        )

    latest = points[-1] if points else None
    return TEMPLATES.TemplateResponse(
        request,
        "trend.html",
        {
            "targets": targets,
            "selected": selected,
            "points": points,
            "latest": latest,
            "chart": build_trend_chart(points),
            "tooltip_data": [
                {
                    "date": p.scanned_at.strftime("%Y-%m-%d %H:%M UTC"),
                    "risk": p.risk_score,
                    "change": p.change,
                    "issues": p.issue_count,
                    "critical": p.tier_counts.Critical,
                    "high": p.tier_counts.High,
                }
                for p in points
            ],
        },
    )
