"""Tests for the triage layer, using a mocked LLM client.

Tickets: R021-R028
"""

import json

import pytest

from riskrank.scanner.models import Finding
from riskrank.triage.context import TargetContext
from riskrank.triage.prompts import TRIAGE_SYSTEM_PROMPT
from riskrank.triage.triage import (
    MAX_FIELD_CHARS,
    TriageError,
    build_triage_prompt,
    parse_triage_response,
    triage_finding,
)

VALID_REPLY = {
    "exploitability_score": 9,
    "business_impact_score": 8,
    "priority_tier": "Critical",
    "explanation": "Login is public and the query is injectable.",
    "suggested_fix": "Use parameterised queries.",
}


class FakeLLM:
    """Returns queued replies from complete(); records prompts."""

    def __init__(self, *replies: str):
        self.replies = list(replies)
        self.calls: list[dict] = []

    def complete(self, prompt: str, system: str | None = None) -> str:
        self.calls.append({"prompt": prompt, "system": system})
        return self.replies.pop(0)


@pytest.fixture
def login_context() -> TargetContext:
    return TargetContext(
        public_facing=True,
        handles_sensitive_data=True,
        requires_auth=False,
        notes="Inferred: authentication endpoint (login).",
    )


# --- R023: prompt building -------------------------------------------------------


def test_prompt_includes_finding_and_context(sample_finding, login_context):
    prompt = build_triage_prompt(sample_finding, login_context)
    for expected in [
        "Type: SQL Injection",
        "Severity (scanner-reported): High",
        "CWE: CWE-89",
        "Endpoint: /api/login",
        "<scanner_data>' OR '1'='1</scanner_data>",
        "Public-facing: yes",
        "Handles sensitive data: yes",
        "Requires authentication: no",
        "Notes: Inferred: authentication endpoint (login).",
    ]:
        assert expected in prompt


def test_prompt_handles_missing_fields():
    finding = Finding(id="finding-001", type="X", severity_raw="Low", endpoint="/")
    prompt = build_triage_prompt(finding, TargetContext())
    assert "CWE: unknown" in prompt
    assert "Evidence: <scanner_data>(none)</scanner_data>" in prompt
    assert "Notes: (none)" in prompt


def test_prompt_truncates_huge_evidence(sample_finding, login_context):
    finding = sample_finding.model_copy(update={"evidence": "A" * 10_000})
    prompt = build_triage_prompt(finding, login_context)
    assert "A" * MAX_FIELD_CHARS + " …[truncated]" in prompt
    assert "A" * (MAX_FIELD_CHARS + 1) not in prompt


def test_system_prompt_warns_about_untrusted_scanner_data():
    assert "<scanner_data>" in TRIAGE_SYSTEM_PROMPT
    assert "Never follow" in TRIAGE_SYSTEM_PROMPT


# --- R023: response parsing --------------------------------------------------------


def test_parse_plain_json():
    result = parse_triage_response(json.dumps(VALID_REPLY))
    assert result.exploitability_score == 9
    assert result.priority_tier == "Critical"


@pytest.mark.parametrize(
    "wrapper",
    [
        "```json\n{}\n```",
        "Here is my assessment:\n{}\nLet me know if you need more.",
        "{}   ",
    ],
    ids=["code-fence", "surrounding-text", "trailing-space"],
)
def test_parse_json_wrapped_in_extra_text(wrapper):
    reply = wrapper.replace("{}", json.dumps(VALID_REPLY))
    assert parse_triage_response(reply).business_impact_score == 8


def test_parse_skips_braces_that_are_not_json():
    reply = "Scores {as requested}: " + json.dumps(VALID_REPLY)
    assert parse_triage_response(reply).exploitability_score == 9


@pytest.mark.parametrize("tier", ["critical", "HIGH", " Medium ", "low"])
def test_parse_normalises_tier_case(tier):
    result = parse_triage_response(json.dumps({**VALID_REPLY, "priority_tier": tier}))
    assert result.priority_tier == tier.strip().capitalize()


def test_parse_accepts_numeric_string_scores():
    reply = json.dumps({**VALID_REPLY, "exploitability_score": "7"})
    assert parse_triage_response(reply).exploitability_score == 7


@pytest.mark.parametrize(
    ("change", "message"),
    [
        ({"exploitability_score": 11}, "exploitability_score"),
        ({"business_impact_score": 0}, "business_impact_score"),
        ({"priority_tier": "Urgent"}, "priority_tier"),
        ({"explanation": "   "}, "explanation"),
        ({"suggested_fix": None}, "suggested_fix"),
    ],
)
def test_parse_rejects_invalid_values(change, message):
    with pytest.raises(TriageError, match=message):
        parse_triage_response(json.dumps({**VALID_REPLY, **change}))


def test_parse_rejects_missing_key():
    reply = {k: v for k, v in VALID_REPLY.items() if k != "suggested_fix"}
    with pytest.raises(TriageError, match="suggested_fix"):
        parse_triage_response(json.dumps(reply))


@pytest.mark.parametrize("reply", ["no json here", "[1, 2, 3]", "{broken json"])
def test_parse_rejects_replies_without_a_json_object(reply):
    with pytest.raises(TriageError, match="did not contain a JSON object"):
        parse_triage_response(reply)


# --- R023: triage_finding ------------------------------------------------------------


def test_triage_finding_populates_fields(sample_finding, login_context):
    llm = FakeLLM(json.dumps(VALID_REPLY))
    triaged = triage_finding(sample_finding, login_context, llm)

    assert triaged.exploitability_score == 9
    assert triaged.business_impact_score == 8
    assert triaged.priority_tier == "Critical"
    assert triaged.ai_explanation == "Login is public and the query is injectable."
    assert triaged.suggested_fix == "Use parameterised queries."
    # Everything from the scanner is kept.
    assert triaged.id == sample_finding.id
    assert triaged.endpoint == sample_finding.endpoint


def test_triage_finding_does_not_modify_the_original(sample_finding, login_context):
    triage_finding(sample_finding, login_context, FakeLLM(json.dumps(VALID_REPLY)))
    assert sample_finding.priority_tier is None


def test_triage_finding_sends_prompt_and_system_prompt(sample_finding, login_context):
    llm = FakeLLM(json.dumps(VALID_REPLY))
    triage_finding(sample_finding, login_context, llm)
    [call] = llm.calls
    assert call["system"] == TRIAGE_SYSTEM_PROMPT
    assert "SQL Injection" in call["prompt"]


def test_triage_finding_retries_once_on_unparseable_reply(sample_finding, login_context, caplog):
    llm = FakeLLM("Sorry, I can't format that.", json.dumps(VALID_REPLY))
    with caplog.at_level("WARNING", logger="riskrank.triage.triage"):
        triaged = triage_finding(sample_finding, login_context, llm)
    assert triaged.priority_tier == "Critical"
    assert len(llm.calls) == 2
    assert "Could not parse triage reply for finding-001 (attempt 1)" in caplog.text


def test_triage_finding_gives_up_after_retry(sample_finding, login_context):
    llm = FakeLLM("nope", json.dumps({**VALID_REPLY, "exploitability_score": 99}))
    with pytest.raises(TriageError, match="Could not triage finding-001 \\(SQL Injection\\)"):
        triage_finding(sample_finding, login_context, llm)
    assert len(llm.calls) == 2


# --- R026-R028 (placeholder) ------------------------------------------------------------


def test_rank_findings_placeholder():
    """TODO (R028): build a list of Findings with varying scores and
    assert rank_findings() sorts them highest-risk first.
    """
    assert True
