"""Response models for the dashboard API (the JSON the frontend receives).

Tickets: R036, R037, R038
"""

from datetime import datetime

from pydantic import BaseModel, Field


class TierCounts(BaseModel):
    """Number of findings in each priority tier (triaged findings only)."""

    Critical: int = 0
    High: int = 0
    Medium: int = 0
    Low: int = 0


class TopFinding(BaseModel):
    """The highest-priority finding in a scan."""

    type: str
    endpoint: str
    priority_tier: str
    priority_score: int


class ScanSummary(BaseModel):
    """One row of the scan history list (GET /scans)."""

    id: int
    target_url: str
    scanned_at: datetime
    riskrank_version: str
    finding_count: int
    triaged_count: int
    tier_counts: TierCounts
    top_finding: TopFinding | None = Field(
        description="Highest-priority finding, or null if nothing was triaged."
    )


class ScanList(BaseModel):
    """A page of scan history, newest first."""

    items: list[ScanSummary]
    total: int = Field(description="Total scans matching the filter (for pagination).")
    limit: int
    offset: int
