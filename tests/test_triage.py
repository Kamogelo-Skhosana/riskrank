"""Tests for the triage layer, using a mocked LLM client.

Tickets: R021-R028
"""


def test_triage_finding_placeholder(sample_finding):
    """TODO (R025): mock LLMClient.complete() to return a canned JSON
    response, call triage_finding(), and assert the Finding's score
    fields get populated correctly.
    """
    assert sample_finding.type == "SQL Injection"


def test_rank_findings_placeholder():
    """TODO (R028): build a list of Findings with varying scores and
    assert rank_findings() sorts them highest-risk first.
    """
    assert True
