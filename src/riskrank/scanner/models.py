"""Internal Finding data model — the normalized shape all raw scanner
output gets converted into before it reaches the triage layer.

Tickets: R012, R024, R026
"""

from pydantic import BaseModel, computed_field

# ZAP's severity levels, most to least severe.
SEVERITY_ORDER = ["High", "Medium", "Low", "Informational"]


def severity_rank(severity: str) -> int:
    """0 for High ... 3 for Informational; unknown labels sort after all of them."""
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


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

    @computed_field  # included in model_dump() / JSON export
    @property
    def priority_score(self) -> int | None:
        """Combined risk score: exploitability x business impact (1-100).

        Multiplying (rather than adding) means a finding only scores high
        when it is BOTH easy to exploit AND damaging. With addition, a
        trivially exploitable but harmless issue (10 + 1 = 11) would tie with
        a moderate one (5 + 6); with multiplication it scores 10, well below
        the moderate issue's 30, and 10x10 = 100 is the maximum.
        None until the finding has been triaged (both scores set).
        """
        if self.exploitability_score is None or self.business_impact_score is None:
            return None
        return self.exploitability_score * self.business_impact_score
