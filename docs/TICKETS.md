# Tickets

50 tickets across 3 phases. Copy these into GitHub Issues (one issue per ticket) or a GitHub Project board — the IDs (R001, R002...) are meant to match your issue numbers or be used as labels for traceability.

Suggested labels: `phase-1`, `phase-2`, `phase-3`, plus an epic label per group (e.g., `epic:zap-integration`).

---

## Phase 1 — Core Scanning Engine (17 tickets)

**End state:** `riskrank scan <url>` runs a real ZAP scan and outputs raw findings to console + JSON.

### Epic: Project Setup & Tooling
- [x] **R001** — Initialize repo: folder structure, `.gitignore`, `LICENSE` (MIT)
- [x] **R002** — Set up Python project (`pyproject.toml`, `requirements.txt`), document venv setup in README
- [x] **R003** — Add linting/formatting (ruff + black) with a local pre-commit hook
- [x] **R004** — Set up `pytest` scaffold (`tests/` structure, `conftest.py`, test config)
- [x] **R005** — Add GitHub Actions CI workflow: install deps, run lint, run tests on push/PR

### Epic: ZAP Integration
- [x] **R006** — Build ZAP client wrapper module (`scanner/zap_client.py`) — connect to a running ZAP instance
- [x] **R007** — Implement spider (crawl) trigger + poll-until-complete
- [x] **R008** — Implement active scan trigger + poll-until-complete
- [x] **R009** — Implement fetching raw alerts from ZAP once the scan finishes
- [x] **R010** — Add error handling and retry logic for ZAP API calls (timeouts, connection errors)
- [x] **R011** — Add config loading for ZAP connection details (`.env`, `config.py`)

### Epic: Finding Normalization
- [x] **R012** — Define internal `Finding` data model (pydantic/dataclass): type, severity, endpoint, evidence, CWE ID
- [x] **R013** — Implement normalizer: raw ZAP alert JSON → `Finding` objects
- [x] **R014** — Add unit tests for the normalizer using sample ZAP response fixtures

### Epic: CLI & Raw Report Output
- [x] **R015** — Build CLI entry point: `riskrank scan <url>` (Typer or Click)
- [x] **R016** — Implement console output formatter for raw findings (readable table/list)
- [x] **R017** — Implement JSON export of raw findings (`--output findings.json`)

**Phase 1 checkpoint:** Run `riskrank scan` against a deliberately vulnerable local app (e.g., OWASP Juice Shop) and confirm real findings come back in both console and JSON form.

---

## Phase 2 — AI Triage Layer (17 tickets)

**End state:** The same CLI produces a prioritized, explained Markdown report, and scans are saved locally.

### Epic: Target Context Configuration
- [x] **R018** — Design target-context schema: is this endpoint public-facing? does it touch sensitive/user data? auth required?
- [x] **R019** — Add a way to supply target context per scan (CLI flags or a config file)
- [x] **R020** — Add basic default-context inference (e.g., `/api/*` paths flagged as higher default sensitivity)

### Epic: LLM Triage Integration
- [x] **R021** — Design the triage prompt template: finding + context in, structured score + explanation out
- [x] **R022** — Build LLM client wrapper (API key config, retries, basic rate limiting)
- [x] **R023** — Implement the triage call per finding and parse the structured response
- [x] **R024** — Extend `Finding` model with exploitability score, business impact score, explanation, suggested fix
- [x] **R025** — Add unit tests using mocked LLM responses (no live API calls in CI)

### Epic: Ranking & Prioritization
- [x] **R026** — Implement combined scoring/ranking algorithm (exploitability × impact → overall priority score)
- [x] **R027** — Implement priority tier assignment: Critical / High / Medium / Low
- [x] **R028** — Add tests covering ranking edge cases (ties, missing scores, conflicting signals)

### Epic: Report Generation
- [x] **R029** — Design the Markdown report template (prioritized list, explanations, remediation suggestions)
- [x] **R030** — Implement the Markdown report generator
- [x] **R031** — Add a CLI flag to write the Markdown report to file (`--report report.md`)

### Epic: Persistence
- [x] **R032** — Set up SQLite schema: `scans` table, `findings` table
- [x] **R033** — Implement save-scan-to-database logic after each scan run

### Epic: Phase 2 Wrap-up
- [x] **R034** — End-to-end test: full pipeline (scan → normalize → triage → ranked Markdown report) + demo readiness pass

**Phase 2 checkpoint:** Run a full scan against the same test target and get back a genuinely useful, prioritized Markdown report you'd be comfortable showing someone.

---

## Phase 3 — Dashboard & History (16 tickets)

**End state:** A working web dashboard showing scan history, prioritized findings, and risk trends over time.

### Epic: Backend API
- [x] **R035** — Set up FastAPI app skeleton, served alongside the existing CLI
- [x] **R036** — Implement `GET /scans` — list scan history
- [x] **R037** — Implement `GET /scans/{id}` — findings detail for one scan
- [x] **R038** — Implement `GET /scans/trend` — aggregated risk-over-time data

### Epic: Dashboard Frontend
- [x] **R039** — Build scan list page (table: date, target, top priority finding)
- [x] **R040** — Build scan detail page (prioritized findings list with explanations)
- [x] **R041** — Build a trend chart view (risk score over time, across scans)
- [x] **R042** — Add basic styling/theme to the dashboard
- [x] **R043** — Wire the frontend to the backend API endpoints

### Epic: Responsible Use Safeguard
- [x] **R044** — Add a target-ownership confirmation step before any scan runs
- [x] **R045** — Add a scan-target allowlist config (only scan approved/owned targets)

### Epic: Deployment
- [x] **R046** — Write `Dockerfile` + `docker-compose.yml` (riskrank app + ZAP container)
- [x] **R047** — Deploy the dashboard (or fully document local-run steps if hosted deploy is out of scope)

### Epic: Docs & Final Demo Readiness
- [x] **R048** — Polish full usage docs in the README (setup, screenshots, example output)
- [x] **R049** — Prepare a demo script / sample target walkthrough for presenting the project
- [x] **R050** — Final end-to-end test pass across all three phases; tag `v1.0` release

**Phase 3 checkpoint:** Open the dashboard, see real scan history with prioritized findings and a trend view — this is the version you show in your portfolio or an interview.

---

## Ticket Summary

| Phase | Tickets | Range |
|---|---|---|
| Phase 1 — Core Scanning Engine | 17 | R001–R017 |
| Phase 2 — AI Triage Layer | 17 | R018–R034 |
| Phase 3 — Dashboard & History | 16 | R035–R050 |
| **Total** | **50** | |
