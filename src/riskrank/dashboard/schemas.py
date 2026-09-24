"""Response models for the dashboard API (the JSON the frontend receives).

Tickets: R036, R037, R038
"""

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

PriorityTier = Literal["Critical", "High", "Medium", "Low"]


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


class FindingOut(BaseModel):
    """One finding with its scanner data and AI triage (null until triaged)."""

    id: str
    type: str
    severity_raw: str
    endpoint: str
    evidence: str | None
    description: str | None
    cwe_id: int | None
    exploitability_score: int | None
    business_impact_score: int | None
    priority_score: int | None
    priority_tier: PriorityTier | None
    ai_explanation: str | None
    suggested_fix: str | None


class IssueOut(BaseModel):
    """Findings of the same type merged into one issue, as in the Markdown
    report: tier, scores and advice come from its highest-scoring occurrence."""

    rank: int
    type: str
    severity_raw: str
    priority_tier: PriorityTier | None
    priority_score: int | None
    exploitability_score: int | None
    business_impact_score: int | None
    cwe_id: int | None
    explanation: str | None
    suggested_fix: str | None
    evidence: str | None
    endpoints: list[str] = Field(description="Every affected endpoint, most important first.")
    occurrences: int = Field(description="Number of distinct endpoints affected.")


class ScanDetail(BaseModel):
    """Everything about one scan (GET /scans/{scan_id})."""

    scan: ScanSummary
    issues: list[IssueOut] = Field(description="Grouped issues, highest priority first.")
    findings: list[FindingOut] = Field(description="Individual findings, AI-ranked.")


class TrendPoint(BaseModel):
    """One scan's position on the risk-over-time chart."""

    scan_id: int
    target_url: str
    scanned_at: datetime
    finding_count: int
    triaged_count: int
    issue_count: int = Field(description="Distinct triaged issues (findings grouped by type).")
    risk_score: int = Field(
        description=(
            "Sum of each distinct issue's highest priority score. Counts an issue once "
            "however many pages it appears on, so fixing one bug moves the line, and "
            "repeated scanner noise doesn't inflate it."
        )
    )
    max_score: int | None = Field(description="Highest single priority score in the scan.")
    tier_counts: TierCounts
    change: int | None = Field(
        description="risk_score minus the previous scan of the same target (null for the first)."
    )


class Trend(BaseModel):
    """Risk over time, oldest scan first (GET /scans/trend).

    Only scans with a risk score are included: untriaged scans are left out.
    """

    target: str | None
    points: list[TrendPoint]
