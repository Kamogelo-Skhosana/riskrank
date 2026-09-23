"""Internal Finding data model — the normalized shape all raw scanner
output gets converted into before it reaches the triage layer.

Ticket: R012
"""

from pydantic import BaseModel


class Finding(BaseModel):
    id: str
    type: str
    severity_raw: str
    endpoint: str
    evidence: str | None = None
    description: str | None = None
    cwe_id: int | None = None

    # Populated later by the triage layer (Phase 2) — see R024
    exploitability_score: int | None = None
    business_impact_score: int | None = None
    priority_tier: str | None = None
    ai_explanation: str | None = None
    suggested_fix: str | None = None
