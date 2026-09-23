"""Core triage logic — scores each Finding via the LLM and assigns
a priority tier.

Tickets: R023, R024, R025, R026, R027, R034
"""

import json
import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal

from pydantic import BaseModel, Field, ValidationError, field_validator

from riskrank.scanner.models import Finding, severity_rank
from riskrank.triage.context import ContextConfig, TargetContext, resolve_context
from riskrank.triage.llm_client import LLMClient, LLMError
from riskrank.triage.prompts import TRIAGE_PROMPT_TEMPLATE, TRIAGE_SYSTEM_PROMPT

logger = logging.getLogger(__name__)

# Scanner evidence/descriptions can be huge (whole response bodies); cap what
# goes into the prompt to keep token usage and cost predictable.
MAX_FIELD_CHARS = 1500

# How many times to ask the LLM again when its reply can't be parsed.
MAX_PARSE_RETRIES = 1

PriorityTier = Literal["Critical", "High", "Medium", "Low"]
TIER_ORDER: list[PriorityTier] = ["Critical", "High", "Medium", "Low"]

# Minimum combined score (exploitability x impact, 1-100) for each tier.
# The thresholds are squares, so a finding scoring evenly on both axes lands
# where you'd expect: 8x8 = 64 is Critical, 6x6 = 36 High, 4x4 = 16 Medium.
TIER_THRESHOLDS: list[tuple[PriorityTier, int]] = [
    ("Critical", 64),
    ("High", 36),
    ("Medium", 16),
    ("Low", 1),
]


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


def _untrusted(text: str | None, limit: int = MAX_FIELD_CHARS) -> str:
    """Prepare scanner text for the prompt: truncate it, and neutralise any
    <scanner_data> tags inside it so it can't close the wrapper early and
    smuggle instructions outside the untrusted-data block."""
    if not text:
        return "(none)"
    text = text if len(text) <= limit else text[:limit] + " …[truncated]"
    return text.replace("<scanner_data>", "<scanner-data>").replace(
        "</scanner_data>", "</scanner-data>"
    )


def build_triage_prompt(finding: Finding, context: TargetContext) -> str:
    """Fill the triage prompt template for one finding and its context."""
    return TRIAGE_PROMPT_TEMPLATE.format(
        finding_type=finding.type,
        severity_raw=finding.severity_raw,
        cwe=f"CWE-{finding.cwe_id}" if finding.cwe_id else "unknown",
        endpoint=finding.endpoint,
        evidence=_untrusted(finding.evidence),
        description=_untrusted(finding.description),
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


def tier_for_score(score: int) -> PriorityTier:
    """Map a combined priority score (1-100) to a priority tier.

    Critical >= 64, High >= 36, Medium >= 16, otherwise Low.
    """
    if not 1 <= score <= 100:
        raise ValueError(f"priority score must be between 1 and 100, got {score}")
    for tier, minimum in TIER_THRESHOLDS:
        if score >= minimum:
            return tier
    raise AssertionError("unreachable")  # pragma: no cover


def assign_priority_tier(finding: Finding) -> Finding:
    """Return a copy of finding with priority_tier derived from its score.

    Untriaged findings (no priority_score) come back unchanged, so their
    tier stays None.
    """
    score = finding.priority_score
    if score is None:
        return finding
    tier = tier_for_score(score)
    if tier == finding.priority_tier:
        return finding
    return finding.model_copy(update={"priority_tier": tier})


def triage_finding(finding: Finding, context: TargetContext, llm: LLMClient) -> Finding:
    """Score a single finding using the LLM and return an updated Finding.

    The original Finding is not modified; a copy is returned with
    exploitability_score, business_impact_score, priority_tier,
    ai_explanation and suggested_fix filled in. If the reply can't be
    parsed, the LLM is asked again (up to MAX_PARSE_RETRIES times).

    The tier is derived from the scores (tier_for_score), not taken from
    the LLM, so tiers are always consistent with the ranking. If the LLM's
    own tier is two or more levels away, a warning is logged, since that
    usually means its scores and its judgement don't agree.

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
        tier = tier_for_score(result.exploitability_score * result.business_impact_score)
        gap = abs(TIER_ORDER.index(tier) - TIER_ORDER.index(result.priority_tier))
        if gap >= 2:
            logger.warning(
                "LLM tier for %s (%s) disagrees with its scores (%dx%d -> %s); using %s",
                finding.id,
                result.priority_tier,
                result.exploitability_score,
                result.business_impact_score,
                tier,
                tier,
            )
        return finding.model_copy(
            update={
                "exploitability_score": result.exploitability_score,
                "business_impact_score": result.business_impact_score,
                "priority_tier": tier,
                "ai_explanation": result.explanation,
                "suggested_fix": result.suggested_fix,
            }
        )

    raise TriageError(f"Could not triage {finding.id} ({finding.type}): {last_error}")


def _ranking_key(finding: Finding) -> tuple[int, int, int, int]:
    """Sort key for rank_findings(): smaller sorts first."""
    score = finding.priority_score
    return (
        0 if score is not None else 1,  # triaged findings before untriaged ones
        -(score or 0),  # higher combined score first
        -(finding.exploitability_score or 0),  # tie-break: easier to exploit first
        severity_rank(finding.severity_raw),  # then the scanner's own severity
    )


def rank_findings(findings: list[Finding]) -> list[Finding]:
    """Sort findings by combined priority score, highest risk first.

    The combined score is exploitability x business impact (see
    Finding.priority_score). Ties are broken by exploitability, then by the
    scanner's severity label; anything still tied keeps its original order
    (the sort is stable). Findings that haven't been triaged yet (no scores)
    go last, ordered by scanner severity. Returns a new list; the input is
    not modified.

    Every triaged finding's priority_tier is (re)derived from its score, so
    the tiers in the output always agree with the ranking, even if scores
    were edited after triage.
    """
    return sorted((assign_priority_tier(f) for f in findings), key=_ranking_key)


# --- R034: triaging a whole scan ---------------------------------------------------------

# Stop calling the LLM after this many failures in a row: it's almost always
# a problem every call will hit (bad key, no credit, API down), so carrying
# on would just burn time. Findings not yet triaged stay untriaged.
MAX_CONSECUTIVE_FAILURES = 3

TriageProgress = Callable[[int, int], None]  # (groups done, total groups)


@dataclass
class TriageSummary:
    """Result of triage_findings()."""

    findings: list[Finding]
    llm_calls: int = 0
    groups: int = 0
    triaged: int = 0
    failed: int = 0
    stopped_early: bool = False
    errors: list[str] = field(default_factory=list)


def _group_key(finding: Finding, context: TargetContext) -> tuple:
    """Findings sharing this key get the same assessment from one LLM call:
    same issue (type, scanner severity, CWE) in the same kind of place
    (same public/sensitive/auth context)."""
    return (
        finding.type,
        finding.severity_raw,
        finding.cwe_id,
        context.public_facing,
        context.handles_sensitive_data,
        context.requires_auth,
    )


def triage_findings(
    findings: list[Finding],
    llm: LLMClient,
    context_config: ContextConfig | None = None,
    on_progress: TriageProgress | None = None,
) -> TriageSummary:
    """Triage every finding in a scan, using as few LLM calls as possible.

    Scanners report the same issue once per page (a Juice Shop scan gave 283
    findings but only 5 issue types), so findings are grouped by issue and
    context (_group_key) and each group is sent to the LLM once, using its
    first finding as the example. The assessment is then applied to every
    finding in the group.

    Failures never abort the scan: a group that can't be triaged is left
    untriaged (reported in errors), and after MAX_CONSECUTIVE_FAILURES in a
    row the remaining groups are skipped.

    Returns findings in their original order; use rank_findings() to sort.
    """
    groups: dict[tuple, list[int]] = {}
    contexts: dict[tuple, TargetContext] = {}
    for index, finding in enumerate(findings):
        context = resolve_context(finding.endpoint, context_config)
        key = _group_key(finding, context)
        groups.setdefault(key, []).append(index)
        contexts.setdefault(key, context)

    result = list(findings)
    summary = TriageSummary(findings=result, groups=len(groups))
    consecutive_failures = 0

    for done, (key, indexes) in enumerate(groups.items(), start=1):
        if consecutive_failures >= MAX_CONSECUTIVE_FAILURES:
            summary.stopped_early = True
            summary.failed += len(indexes)
            if on_progress:
                on_progress(done, len(groups))
            continue

        representative = findings[indexes[0]]
        summary.llm_calls += 1
        try:
            assessed = triage_finding(representative, contexts[key], llm)
        except (TriageError, LLMError) as exc:
            consecutive_failures += 1
            summary.failed += len(indexes)
            summary.errors.append(f"{representative.type}: {exc}")
            logger.warning("Triage failed for %s: %s", representative.type, exc)
        else:
            consecutive_failures = 0
            update = {
                "exploitability_score": assessed.exploitability_score,
                "business_impact_score": assessed.business_impact_score,
                "priority_tier": assessed.priority_tier,
                "ai_explanation": assessed.ai_explanation,
                "suggested_fix": assessed.suggested_fix,
            }
            for index in indexes:
                result[index] = findings[index].model_copy(update=update)
            summary.triaged += len(indexes)

        if on_progress:
            on_progress(done, len(groups))

    if summary.stopped_early:
        summary.errors.append(
            f"Stopped after {MAX_CONSECUTIVE_FAILURES} failures in a row; "
            "remaining findings were left untriaged."
        )
    return summary
