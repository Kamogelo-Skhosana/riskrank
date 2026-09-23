# Architecture

## Overview

riskrank has three logical layers, built up one per phase:

```
┌─────────────────┐      ┌──────────────────┐      ┌───────────────────┐
│   Scanner Layer   │ ──> │   Triage Layer    │ ──> │   Report Layer      │
│   (OWASP ZAP)      │      │   (LLM scoring)    │      │   (output + storage) │
└─────────────────┘      └──────────────────┘      └───────────────────┘
        Phase 1                 Phase 2                   Phase 1–3
                                                                    │
                                                          ┌───────────────────┐
                                                          │  Dashboard Layer    │
                                                          │  (Phase 3, web UI)  │
                                                          └───────────────────┘
```

## 1. Scanner Layer (`src/riskrank/scanner/`)

- Talks to a running OWASP ZAP instance via its REST API
- Triggers a spider (crawl) + active scan against the target
- Polls for scan completion
- Pulls raw alerts/findings and normalizes them into riskrank's internal finding format:

```json
{
  "id": "finding-001",
  "type": "SQL Injection",
  "severity_raw": "High",
  "endpoint": "/api/login",
  "evidence": "...",
  "description": "...",
  "cwe_id": 89
}
```

### Running ZAP locally

```bash
docker run -u zap -p 8080:8080 -i zaproxy/zap-stable zap.sh -daemon \
  -host 0.0.0.0 -port 8080 \
  -config api.addrs.addr.name=.* -config api.addrs.addr.regex=true \
  -config api.key=<your-api-key>
```

## 2. Triage Layer (`src/riskrank/triage/`)

- Takes normalized findings + target context (is this endpoint public-facing? does it touch user/payment data? is this an internal tool?)
- Sends findings + context to an LLM with a structured prompt
- LLM returns, per finding:
  - **Exploitability score** (1–10)
  - **Business impact score** (1–10)
  - **Priority tier** (Critical / High / Medium / Low)
  - **Plain-English explanation** of why it matters
  - **Suggested remediation approach**
- Output is a ranked list of findings, re-sorted by combined score rather than the scanner's raw severity label

## 3. Report Layer (`src/riskrank/report/`)

- Takes the triaged, ranked findings and renders them as:
  - Console output (Phase 1)
  - Markdown report (Phase 2)
  - JSON export (Phase 1+, for the dashboard to consume)
- Stores each scan + its triaged results in SQLite for history tracking

## 4. Dashboard Layer (`src/riskrank/dashboard/`, Phase 3)

- FastAPI routes serving scan history from SQLite
- Simple frontend (server-rendered templates or a small SPA) showing:
  - List of past scans
  - Prioritized findings per scan
  - Trend view — is the app's risk posture improving over time?

## Data Flow (end-to-end)

1. User runs `riskrank scan <target-url>`
2. Scanner layer triggers ZAP, waits for completion, pulls raw findings
3. Triage layer scores and ranks findings via the LLM
4. Report layer renders the prioritized report and saves the scan to SQLite
5. *(Phase 3)* Dashboard reads from SQLite and displays scan history + trends

## Configuration

All configuration lives in `.env` (see `.env.example`):

- `ZAP_API_URL`, `ZAP_API_KEY` — connection details for the ZAP instance
- `LLM_API_KEY` — API key for the triage layer's LLM calls
- `DATABASE_URL` — SQLite path (defaults to `./riskrank.db`)
