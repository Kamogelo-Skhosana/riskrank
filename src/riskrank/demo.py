"""Sample scan history for demos and screenshots (R049).

`riskrank demo` loads four scans of a Juice Shop-style app, three weeks apart,
into the database, so the dashboard can be shown without waiting for a live
scan or spending AI credits. The scans are clearly labelled: their target is
DEMO_TARGET, which no real scan uses, and every explanation was written for
this sample, not produced by a live AI call.

The story the four scans tell (see docs/DEMO.md):
  week 1  SQL injection on login + search, DOM XSS, an open /ftp share, noise
  week 2  login injection fixed, but search is still injectable: risk score unchanged
  week 3  search injection fixed, most of /ftp locked down: risk drops sharply
  week 4  XSS fixed, only /ftp itself and header noise left
"""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.engine import Engine

from riskrank.report.persistence import ScanRecord, init_db, save_scan
from riskrank.scanner.models import Finding

DEMO_TARGET = "http://demo.juice-shop.local"
DEMO_START = datetime(2026, 8, 24, 9, 0, tzinfo=UTC)

_Issue = Callable[[str, str], Finding]


def _issue(
    type_: str,
    severity: str,
    cwe: int,
    exploit: int,
    impact: int,
    why: str,
    fix: str,
    evidence: str | None = None,
) -> _Issue:
    def make(finding_id: str, endpoint: str) -> Finding:
        return Finding(
            id=finding_id,
            type=type_,
            severity_raw=severity,
            endpoint=endpoint,
            cwe_id=cwe,
            evidence=evidence,
            exploitability_score=exploit,
            business_impact_score=impact,
            ai_explanation=why,
            suggested_fix=fix,
        )

    return make


SQLI = _issue(
    "SQL Injection", "High", 89, 9, 9,
    "The public login endpoint builds its SQL query from user input, so an attacker can "
    "log in as any user, including the admin, or read the whole user table.",
    "Use parameterised queries (Sequelize replacements) for every database call and never "
    "concatenate request data into SQL.",
    "' OR 1=1--",
)  # fmt: skip
XSS = _issue(
    "Cross Site Scripting (DOM Based)", "High", 79, 7, 6,
    "The search term is written into the page without encoding, so a crafted link can run "
    "script in a logged-in shopper's browser and steal their session.",
    "Encode user input before rendering it (Angular's default binding, never "
    "bypassSecurityTrust*) and add a Content-Security-Policy.",
    '<iframe src="javascript:alert(`xss`)">',
)  # fmt: skip
FTP = _issue(
    "Sensitive File Exposure", "Medium", 538, 8, 6,
    "The /ftp share is browsable without logging in and serves backups and internal "
    "documents, including a password-manager database.",
    "Remove the directory listing, move confidential files out of the web root and "
    "require authentication for anything that stays.",
    "incident-support.kdbx",
)  # fmt: skip
CSP = _issue(
    "Content Security Policy (CSP) Header Not Set", "Medium", 693, 4, 5,
    "Without a CSP, any injected script runs with full access to the page, which makes "
    "cross-site scripting bugs much more damaging.",
    "Send a Content-Security-Policy header, starting with default-src 'self'.",
)  # fmt: skip
CORS = _issue(
    "Cross-Domain Misconfiguration", "Medium", 264, 3, 4,
    "The API allows any origin, so another website could read responses on behalf of a "
    "visitor; impact is limited because cookies aren't sent cross-origin.",
    "Replace Access-Control-Allow-Origin: * with an explicit list of trusted origins.",
)  # fmt: skip
TIMESTAMP = _issue(
    "Timestamp Disclosure - Unix", "Low", 497, 2, 1,
    "Unix timestamps in static bundles reveal build times, which is of little use to an "
    "attacker.",
    "No action needed unless you want to hide build metadata.",
)  # fmt: skip


def _untriaged_fuzzer(finding_id: str, endpoint: str) -> Finding:
    return Finding(
        id=finding_id, type="User Agent Fuzzer", severity_raw="Informational", endpoint=endpoint
    )


PAGES = [
    "/", "/main.js", "/polyfills.js", "/runtime.js", "/styles.css", "/vendor.js",
    "/assets/i18n/en.json", "/sitemap.xml", "/api/Products", "/rest/languages",
    "/rest/admin/application-version", "/api/Challenges",
]  # fmt: skip
FTP_FILES = [
    "/ftp", "/ftp/acquisitions.md", "/ftp/incident-support.kdbx", "/ftp/package.json.bak",
    "/ftp/coupons_2013.md.bak", "/ftp/legal.md", "/ftp/suspicious_errors.yml",
]  # fmt: skip

DEMO_SCANS: list[list[tuple[_Issue, list[str]]]] = [
    [
        (SQLI, ["/rest/user/login", "/rest/products/search"]),
        (XSS, ["/#/search"]),
        (FTP, FTP_FILES),
        (CSP, PAGES),
        (CORS, PAGES[:9]),
        (TIMESTAMP, PAGES[1:7]),
        (_untriaged_fuzzer, ["/assets", "/assets/public"]),
    ],
    [
        (SQLI, ["/rest/products/search"]),
        (XSS, ["/#/search"]),
        (FTP, FTP_FILES),
        (CSP, PAGES),
        (CORS, PAGES[:9]),
        (TIMESTAMP, PAGES[1:7]),
    ],
    [
        (XSS, ["/#/search"]),
        (FTP, FTP_FILES[:3]),
        (CSP, PAGES),
        (CORS, PAGES[:9]),
        (TIMESTAMP, PAGES[1:7]),
    ],
    [
        (FTP, FTP_FILES[:1]),
        (CSP, PAGES),
        (CORS, PAGES[:9]),
        (TIMESTAMP, PAGES[1:7]),
        (_untriaged_fuzzer, ["/assets"]),
    ],
]


def _build(parts: list[tuple[_Issue, list[str]]]) -> list[Finding]:
    findings: list[Finding] = []
    for make, endpoints in parts:
        for endpoint in endpoints:
            findings.append(make(f"finding-{len(findings) + 1:03d}", endpoint))
    return findings


def demo_scan_findings() -> list[list[Finding]]:
    """The findings of each demo scan, oldest first."""
    return [_build(parts) for parts in DEMO_SCANS]


def seed_demo_data(engine: Engine, force: bool = False) -> list[int]:
    """Save the demo scans; return their IDs.

    Does nothing (returns []) if demo scans are already in the database,
    unless force is True, so running `riskrank demo` twice doesn't duplicate
    the history.
    """
    init_db(engine)
    with engine.connect() as conn:
        existing = conn.execute(
            select(func.count()).select_from(ScanRecord).where(ScanRecord.target_url == DEMO_TARGET)
        ).scalar_one()
    if existing and not force:
        return []
    return [
        save_scan(engine, DEMO_TARGET, findings, scanned_at=DEMO_START + timedelta(weeks=week))
        for week, findings in enumerate(demo_scan_findings())
    ]
