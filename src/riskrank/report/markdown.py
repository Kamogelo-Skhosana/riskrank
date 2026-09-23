"""Markdown report generation for triaged, ranked findings (Phase 2).

The report layout lives in templates/report.md.j2 (R029); this module
provides the Jinja2 environment and the Markdown-safety filters it uses.
Scanner output (endpoints, evidence) and AI text are untrusted, so every
value is escaped or fenced before it reaches the Markdown.

Tickets: R029, R030, R031
"""

import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

from jinja2 import Environment, PackageLoader, StrictUndefined

from riskrank import __version__
from riskrank.scanner.models import Finding
from riskrank.triage.triage import TIER_ORDER, rank_findings

TEMPLATE_NAME = "report.md.j2"
DEFAULT_MAX_ENDPOINTS = 5
FIX_FIRST_TIERS = {"Critical", "High"}
NOT_TRIAGED = "Not triaged"

# Characters that can change inline Markdown: emphasis (* _ ~), code (`),
# links/images ([ ]), raw HTML (< >), table cells (|) and escapes (\).
# Kept deliberately small so the raw .md file stays readable.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]<>|~])")
_BACKTICK_RUN = re.compile(r"`+")


def md(text: object) -> str:
    """Escape text for use inline in Markdown (paragraphs, headings, tables).

    Newlines are collapsed to spaces so a value can't break a table row or
    start a new block (e.g. a heading or list) of its own.
    """
    flat = " ".join(str(text).split())
    return _MD_SPECIAL.sub(r"\\\1", flat)


def _longest_backtick_run(text: str) -> int:
    return max((len(m) for m in _BACKTICK_RUN.findall(text)), default=0)


def inline_code(text: object) -> str:
    """Wrap text in a code span that its own backticks can't close early."""
    flat = " ".join(str(text).split())
    ticks = "`" * (_longest_backtick_run(flat) + 1)
    pad = " " if flat.startswith("`") or flat.endswith("`") else ""
    return f"{ticks}{pad}{flat}{pad}{ticks}"


def code_block(text: object, language: str = "text") -> str:
    """Wrap text in a fenced code block that its own backticks can't close."""
    body = str(text).rstrip("\n")
    fence = "`" * max(3, _longest_backtick_run(body) + 1)
    return f"{fence}{language}\n{body}\n{fence}"


def cwe_link(cwe_id: int) -> str:
    """89 -> [CWE-89](https://cwe.mitre.org/data/definitions/89.html)"""
    return f"[CWE-{int(cwe_id)}](https://cwe.mitre.org/data/definitions/{int(cwe_id)}.html)"


def create_environment() -> Environment:
    """Jinja2 environment for the report templates, with the Markdown filters.

    StrictUndefined makes a typo in the template (or a missing value) fail
    loudly instead of silently rendering an empty string.
    """
    env = Environment(
        loader=PackageLoader("riskrank.report", "templates"),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
        keep_trailing_newline=True,
        autoescape=False,  # Markdown, not HTML: values are escaped by the filters above
    )
    env.filters.update(md=md, inline_code=inline_code, code_block=code_block, cwe_link=cwe_link)
    return env


@dataclass
class ReportIssue:
    """One finding type, merging every place it was found (see report.md.j2)."""

    type: str
    severity_raw: str
    tier: str | None
    score: int | None
    exploitability: int | None
    impact: int | None
    cwe_id: int | None
    explanation: str | None
    suggested_fix: str | None
    evidence: str | None
    all_endpoints: list[str] = field(default_factory=list)
    rank: int | None = None
    max_endpoints: int = DEFAULT_MAX_ENDPOINTS

    @property
    def occurrences(self) -> int:
        return len(self.all_endpoints)

    @property
    def endpoints(self) -> list[str]:
        return self.all_endpoints[: self.max_endpoints]

    @property
    def more_endpoints(self) -> int:
        return max(0, self.occurrences - self.max_endpoints)


@dataclass
class ReportContext:
    """Everything templates/report.md.j2 needs (see the comment at its top)."""

    target_url: str
    scanned_at: str
    riskrank_version: str
    total_findings: int
    issue_count: int
    summary: list[dict]
    fix_first: list[ReportIssue]
    other: list[ReportIssue]
    untriaged: list[ReportIssue]


def group_into_issues(
    findings: list[Finding], max_endpoints: int = DEFAULT_MAX_ENDPOINTS
) -> list[ReportIssue]:
    """Rank findings, then merge findings of the same type into one issue.

    Findings are ranked first (rank_findings), so the first finding seen for
    each type is its highest-scoring occurrence: that one supplies the
    issue's tier, scores and advice. Endpoints are listed most important
    first, without duplicates. Issues come out in ranked order.
    """
    issues: dict[str, ReportIssue] = {}
    for finding in rank_findings(findings):
        issue = issues.get(finding.type)
        if issue is None:
            issue = issues[finding.type] = ReportIssue(
                type=finding.type,
                severity_raw=finding.severity_raw,
                tier=finding.priority_tier,
                score=finding.priority_score,
                exploitability=finding.exploitability_score,
                impact=finding.business_impact_score,
                cwe_id=finding.cwe_id,
                explanation=finding.ai_explanation,
                suggested_fix=finding.suggested_fix,
                evidence=finding.evidence,
                max_endpoints=max_endpoints,
            )
        # Fill gaps from later occurrences (e.g. the top one had no evidence).
        issue.cwe_id = issue.cwe_id or finding.cwe_id
        issue.evidence = issue.evidence or finding.evidence
        if finding.endpoint not in issue.all_endpoints:
            issue.all_endpoints.append(finding.endpoint)
    return list(issues.values())


def _format_time(scanned_at: datetime) -> str:
    if scanned_at.tzinfo is None:
        scanned_at = scanned_at.replace(tzinfo=UTC)
    return scanned_at.astimezone(UTC).strftime("%Y-%m-%d %H:%M UTC")


def build_report_context(
    target_url: str,
    findings: list[Finding],
    scanned_at: datetime | None = None,
    max_endpoints: int = DEFAULT_MAX_ENDPOINTS,
) -> ReportContext:
    """Turn findings into the context the report template renders."""
    issues = group_into_issues(findings, max_endpoints=max_endpoints)
    triaged = [issue for issue in issues if issue.tier is not None]
    untriaged = [issue for issue in issues if issue.tier is None]
    for rank, issue in enumerate(triaged + untriaged, start=1):
        issue.rank = rank

    summary = [
        {
            "tier": tier,
            "issues": sum(1 for i in triaged if i.tier == tier),
            "occurrences": sum(i.occurrences for i in triaged if i.tier == tier),
        }
        for tier in TIER_ORDER
    ]
    if untriaged:
        summary.append(
            {
                "tier": NOT_TRIAGED,
                "issues": len(untriaged),
                "occurrences": sum(i.occurrences for i in untriaged),
            }
        )

    return ReportContext(
        target_url=target_url,
        scanned_at=_format_time(scanned_at or datetime.now(UTC)),
        riskrank_version=__version__,
        total_findings=len(findings),
        issue_count=len(issues),
        summary=summary,
        fix_first=[i for i in triaged if i.tier in FIX_FIRST_TIERS],
        other=[i for i in triaged if i.tier not in FIX_FIRST_TIERS],
        untriaged=untriaged,
    )


def generate_markdown_report(
    target_url: str,
    findings: list[Finding],
    scanned_at: datetime | None = None,
    max_endpoints: int = DEFAULT_MAX_ENDPOINTS,
) -> str:
    """Render a prioritized Markdown report from findings.

    Findings don't need to be pre-sorted: they are ranked (and their tiers
    made consistent with their scores) here, then grouped by type.

    Args:
        target_url: the scanned target, shown in the title.
        findings: triaged and/or untriaged findings.
        scanned_at: scan time (defaults to now), shown in UTC.
        max_endpoints: how many endpoints to list per issue before
            summarising the rest as "...and N more".
    """
    context = build_report_context(target_url, findings, scanned_at, max_endpoints)
    template = create_environment().get_template(TEMPLATE_NAME)
    return template.render(report=context)


def write_report(content: str, path: str) -> None:
    """Write the rendered report to disk.

    TODO (R031): write content to path.
    """
    raise NotImplementedError
