"""Core triage logic — scores each Finding via the LLM and assigns
a priority tier.

Tickets: R023, R024, R026, R027
"""

import json
import logging
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from riskrank.scanner.models import Finding
from riskrank.triage.context import TargetContext
from riskrank.triage.llm_client import LLMClient
from riskrank.triage.prompts import TRIAGE_PROMPT_TEMPLATE, TRIAGE_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Scanner evidence/descriptions can be huge (whole response bodies); cap what
# goes into the prompt to keep token usage and cost predictable.
MAX_FIELD_CHARS = 1500

# How many times to ask the LLM again when its reply can't be parsed.
MAX_PARSE_RETRIES = 1

PriorityTier = Literal["Critical", "High", "Medium", "Low"]


class TriageError(Exception):
    """Raised when a finding can't be triaged (e.g. the LLM's reply is unusable)."""


class TriageResult(BaseModel):
    """The structured answer expected from the LLM for one finding."""

    exploitability_score: int = Field(ge=1, le=10)
    business_impact_score: int = Field(ge=1, le=10)
    priority_tier: PriorityTier
    explanation: str = Field(min_length=1)
    suggested_fix: str = Field(min_length=1)

    @field_validator("priority_tier", mode="before")
    @classmethod
    def _normalise_tier(cls, value: object) -> object:
        # Accept "high", "HIGH", " High " etc.
        return value.strip().capitalize() if isinstance(value, str) else value

    @field_validator("explanation", "suggested_fix", mode="before")
    @classmethod
    def _strip_text(cls, value: object) -> object:
        return value.strip() if isinstance(value, str) else value


def _truncate(text: str | None, limit: int = MAX_FIELD_CHARS) -> str:
    if not text:
        return "(none)"
    return text if len(text) <= limit else text[:limit] + " …[truncated]"


def build_triage_prompt(finding: Finding, context: TargetContext) -> str:
    """Fill the triage prompt template for one finding and its context."""
    return TRIAGE_PROMPT_TEMPLATE.format(
        finding_type=finding.type,
        severity_raw=finding.severity_raw,
        cwe=f"CWE-{finding.cwe_id}" if finding.cwe_id else "unknown",
        endpoint=finding.endpoint,
        evidence=_truncate(finding.evidence),
        description=_truncate(finding.description),
        public_facing="yes" if context.public_facing else "no",
        handles_sensitive_data="yes" if context.handles_sensitive_data else "no",
        requires_auth="yes" if context.requires_auth else "no",
        context_notes=context.notes or "(none)",
    )


def _extract_json_object(text: str) -> dict:
    """Find the first JSON object in the LLM reply.

    Models sometimes wrap JSON in ```json fences or add a sentence before or
    after it, so scan for the first '{' that starts a valid JSON object.
    """
    decoder = json.JSONDecoder()
    for start, char in enumerate(text):
        if char != "{":
            continue
        try:
            value, _ = decoder.raw_decode(text, start)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict):
            return value
    raise TriageError("LLM reply did not contain a JSON object.")


def parse_triage_response(text: str) -> TriageResult:
    """Parse and validate the LLM's reply into a TriageResult.

    Raises:
        TriageError: if there's no JSON object or it fails validation
            (missing keys, scores outside 1-10, unknown tier...).
    """
    data = _extract_json_object(text)
    try:
        return TriageResult.model_validate(data)
    except ValidationError as exc:
        problems = "; ".join(
            f"{'.'.join(str(p) for p in err['loc']) or 'response'}: {err['msg']}"
            for err in exc.errors()
        )
        raise TriageError(f"LLM reply failed validation: {problems}") from exc


def triage_finding(finding: Finding, context: TargetContext, llm: LLMClient) -> Finding:
    """Score a single finding using the LLM and return an updated Finding.

    The original Finding is not modified; a copy is returned with
    exploitability_score, business_impact_score, priority_tier,
    ai_explanation and suggested_fix filled in. If the reply can't be
    parsed, the LLM is asked again (up to MAX_PARSE_RETRIES times).

    Raises:
        TriageError: if no usable reply was obtained.
        LLMError: if the LLM call itself fails (propagated from LLMClient).
    """
    prompt = build_triage_prompt(finding, context)

    last_error: TriageError | None = None
    for attempt in range(1, MAX_PARSE_RETRIES + 2):
        reply = llm.complete(prompt, system=TRIAGE_SYSTEM_PROMPT)
        try:
            result = parse_triage_response(reply)
        except TriageError as exc:
            last_error = exc
            logger.warning(
                "Could not parse triage reply for %s (attempt %d): %s", finding.id, attempt, exc
            )
            continue
        return finding.model_copy(
            update={
                "exploitability_score": result.exploitability_score,
                "business_impact_score": result.business_impact_score,
                "priority_tier": result.priority_tier,
                "ai_explanation": result.explanation,
                "suggested_fix": result.suggested_fix,
            }
        )

    raise TriageError(f"Could not triage {finding.id} ({finding.type}): {last_error}")


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by combined priority score, highest risk first.

    TODO (R026): combine exploitability_score and business_impact_score
    into a single sortable priority score.
    TODO (R027): ensure priority_tier is consistent with the combined score.
    """
    raise NotImplementedError
