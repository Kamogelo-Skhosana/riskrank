"""Internal Finding data model — the normalized shape all raw scanner
output gets converted into before it reaches the triage layer.

Ticket: R012
"""

from pydantic import BaseModel
from typing import Optional


class Finding(BaseModel):
    id: str
    type: str
    severity_raw: str
    endpoint: str
    evidence: Optional[str] = None
    description: Optional[str] = None
    cwe_id: Optional[int] = None

    # Populated later by the triage layer (Phase 2) — see R024
    exploitability_score: Optional[int] = None
    business_impact_score: Optional[int] = None
    priority_tier: Optional[str] = None
    ai_explanation: Optional[str] = None
    suggested_fix: Optional[str] = None
