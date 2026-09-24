"""JSON export of findings.

Output shape (stable, so the Phase 3 dashboard and other tools can rely on it)::

    {
      "riskrank_version": "1.0.0",
      "target_url": "http://localhost:3000",
      "scanned_at": "2026-09-23T18:00:00+00:00",
      "finding_count": 3,
      "findings": [ { "id": "finding-001", "type": "...", ... }, ... ]
    }

Every Finding field is always present (null when unset), including the
Phase 2 triage fields, so consumers never have to guess which keys exist.

Ticket: R017
"""

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from riskrank import __version__
from riskrank.scanner.models import Finding


def build_export(
    findings: list[Finding],
    target_url: str | None = None,
    scanned_at: datetime | None = None,
) -> dict[str, Any]:
    """Build the JSON-serializable export document for findings."""
    return {
        "riskrank_version": __version__,
        "target_url": target_url,
        "scanned_at": (scanned_at or datetime.now(UTC)).isoformat(),
        "finding_count": len(findings),
        "findings": [finding.model_dump(mode="json") for finding in findings],
    }


def export_json(
    findings: list[Finding],
    path: str | Path,
    target_url: str | None = None,
    scanned_at: datetime | None = None,
) -> Path:
    """Write findings to a JSON file at path and return the resolved path.

    Parent directories are created if needed. The file is UTF-8 and
    pretty-printed so it's readable and diff-friendly.

    Raises:
        OSError: if the file can't be written.
    """
    out_path = Path(path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    document = build_export(findings, target_url=target_url, scanned_at=scanned_at)
    out_path.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return out_path.resolve()
