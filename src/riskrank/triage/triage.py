"""Core triage logic — scores each Finding via the LLM and assigns
a priority tier.

Tickets: R023, R024, R026, R027
"""

from riskrank.scanner.models import Finding
from riskrank.triage.context import TargetContext
from riskrank.triage.llm_client import LLMClient


def triage_finding(finding: Finding, context: TargetContext, llm: LLMClient) -> Finding:
    """Score a single finding using the LLM and return an updated Finding.

    TODO (R023): build the prompt (prompts.py), call llm.complete(),
    parse the structured JSON response, and populate the Finding's
    exploitability_score, business_impact_score, priority_tier,
    ai_explanation, and suggested_fix fields.
    """
    raise NotImplementedError


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by combined priority score, highest risk first.

    TODO (R026): combine exploitability_score and business_impact_score
    into a single sortable priority score.
    TODO (R027): ensure priority_tier is consistent with the combined score.
    """
    raise NotImplementedError
