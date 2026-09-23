# Roadmap

riskrank is built in three phases. Each phase ends with something tangible you can actually run and demo — not just a partial pile of code. Full ticket-level breakdown is in [TICKETS.md](TICKETS.md).

---

## Phase 1 — Core Scanning Engine (17 tickets)

**Goal:** Get a real scan running end-to-end, with raw findings coming out the other side.

**You end this phase with:**
A working CLI — `riskrank scan <url>` — that triggers a real OWASP ZAP scan against a target you own, and prints/exports the raw findings (type, severity, endpoint, evidence) as console output and JSON.

**Epics covered:**
- Project setup & tooling
- ZAP integration (spider + active scan + polling)
- Finding normalization
- Basic CLI + raw report output
- Phase 1 tests + demo readiness

---

## Phase 2 — AI Triage Layer (17 tickets)

**Goal:** Turn raw findings into a prioritized, explained, human-readable report.

**You end this phase with:**
The same CLI now runs the full pipeline: scan → normalize → **AI-triaged and ranked** → a clean Markdown report showing what to fix first, why it matters, and how — plus scan results saved to a local database.

**Epics covered:**
- Target context configuration (what's public-facing, what handles sensitive data)
- LLM triage integration (exploitability + impact scoring)
- Ranking & prioritization logic
- Markdown report generation
- Scan persistence (SQLite)
- Phase 2 tests + demo readiness

---

## Phase 3 — Dashboard & History (16 tickets)

**Goal:** Make riskrank demoable as a real tool, not just a script — with a visual history of scans over time.

**You end this phase with:**
A deployed (or locally runnable) web dashboard showing past scans, their prioritized findings, and a trend view of risk posture over time. This is the portfolio-ready version.

**Epics covered:**
- FastAPI backend routes for scan history
- Dashboard frontend (scan list, finding detail view, trend chart)
- Responsible-use safeguard (target ownership confirmation)
- Deployment (Docker Compose or a simple hosted deploy)
- Documentation polish + demo script
- Phase 3 tests + final demo readiness

---

## After Phase 3 (optional, not scoped into the 50 tickets)

- Multi-target scheduled scanning
- Slack/email alerts on new critical findings
- Support for additional scanners beyond ZAP
- Auth/multi-user support for the dashboard
