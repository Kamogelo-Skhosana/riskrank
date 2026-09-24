"""A hand-built report context matching templates/report.md.j2 (R029).

Used to render docs/sample-report.md and to test the template before the
generator (R030) exists. Modelled on a scan of OWASP Juice Shop.
"""


def _issue(
    rank, type_, tier, exploit, impact, severity, cwe, explanation, fix, evidence, endpoints, more=0
):
    return {
        "rank": rank,
        "type": type_,
        "tier": tier,
        "score": exploit * impact if exploit else None,
        "exploitability": exploit,
        "impact": impact,
        "severity_raw": severity,
        "cwe_id": cwe,
        "explanation": explanation,
        "suggested_fix": fix,
        "evidence": evidence,
        "occurrences": len(endpoints) + more,
        "endpoints": endpoints,
        "more_endpoints": more,
    }


SAMPLE_REPORT_CONTEXT = {
    "target_url": "http://localhost:3000",
    "scanned_at": "2026-09-24 10:15 UTC",
    "riskrank_version": "1.0.0",
    "total_findings": 57,
    "issue_count": 5,
    "summary": [
        {"tier": "Critical", "issues": 1, "occurrences": 2},
        {"tier": "High", "issues": 1, "occurrences": 17},
        {"tier": "Medium", "issues": 1, "occurrences": 12},
        {"tier": "Low", "issues": 1, "occurrences": 3},
        {"tier": "Not triaged", "issues": 1, "occurrences": 23},
    ],
    "fix_first": [
        _issue(
            1,
            "SQL Injection",
            "Critical",
            9,
            9,
            "High",
            89,
            "The public login endpoint builds its SQL query from user input, so an attacker "
            "can log in as any user (including the admin) or read the whole user table.",
            "Use parameterised queries (Sequelize replacements) for every database call and "
            "never concatenate request data into SQL.",
            "' OR 1=1--",
            ["/rest/user/login", "/rest/products/search"],
        ),
        _issue(
            2,
            "Sensitive File Exposure",
            "High",
            8,
            6,
            "Medium",
            538,
            "The /ftp share is browsable without logging in and serves backups and internal "
            "documents, including a password-manager database.",
            "Remove the directory listing, move confidential files out of the web root and "
            "require authentication for anything that stays.",
            "incident-support.kdbx",
            [
                "/ftp",
                "/ftp/incident-support.kdbx",
                "/ftp/package.json.bak",
                "/ftp/coupons_2013.md.bak",
                "/ftp/acquisitions.md",
            ],
            more=12,
        ),
    ],
    "other": [
        _issue(
            3,
            "Content Security Policy (CSP) Header Not Set",
            "Medium",
            4,
            5,
            "Medium",
            693,
            "Without a CSP, any injected script runs with full access to the page, which makes "
            "cross-site scripting bugs much more damaging.",
            "Send a Content-Security-Policy header, starting with `default-src 'self'`.",
            None,
            ["/", "/main.js", "/styles.css", "/polyfills.js", "/runtime.js"],
            more=7,
        ),
        _issue(
            4,
            "Timestamp Disclosure - Unix",
            "Low",
            2,
            1,
            "Low",
            497,
            "Unix timestamps in static files reveal little on their own and are rarely useful "
            "to an attacker.",
            "No action needed unless the values are server build times you'd rather hide.",
            "1650485437",
            ["/main.js", "/vendor.js", "/sitemap.xml"],
        ),
    ],
    "untriaged": [
        _issue(
            5,
            "User Agent Fuzzer",
            None,
            None,
            None,
            "Informational",
            None,
            None,
            None,
            None,
            ["/assets", "/assets/public"],
            more=21,
        ),
    ],
}
