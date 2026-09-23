"""Markdown report generation for triaged, ranked findings (Phase 2).

The report layout lives in templates/report.md.j2 (R029); this module
provides the Jinja2 environment and the Markdown-safety filters it uses.
Scanner output (endpoints, evidence) and AI text are untrusted, so every
value is escaped or fenced before it reaches the Markdown.

Tickets: R029, R030, R031
"""

import re

from jinja2 import Environment, PackageLoader, StrictUndefined

from riskrank.scanner.models import Finding

TEMPLATE_NAME = "report.md.j2"

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


def generate_markdown_report(target_url: str, findings: list[Finding]) -> str:
    """Render a prioritized Markdown report from ranked findings.

    TODO (R030): group findings by type into issues, build the report
    context described at the top of templates/report.md.j2, and render it.
    """
    raise NotImplementedError


def write_report(content: str, path: str) -> None:
    """Write the rendered report to disk.

    TODO (R031): write content to path.
    """
    raise NotImplementedError
