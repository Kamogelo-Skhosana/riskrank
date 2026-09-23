"""Target context configuration.

Captures what riskrank needs to know about the target to triage
findings meaningfully: which endpoints are public-facing, which
handle sensitive/user data, and which require authentication.

Tickets: R018, R019, R020
"""

from pydantic import BaseModel


class TargetContext(BaseModel):
    public_facing: bool = True
    handles_sensitive_data: bool = False
    requires_auth: bool = False
    notes: str = ""


def infer_default_context(endpoint: str) -> TargetContext:
    """Best-effort default context based on simple endpoint naming patterns.

    TODO (R020): flag /api/, /admin/, /login, /checkout etc. with
    sensible defaults; this is a heuristic, not a guarantee.
    """
    raise NotImplementedError
