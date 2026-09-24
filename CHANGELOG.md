# Changelog

## v1.0.0 — 2026-09-24

First complete release: all 50 tickets across the three phases in
[docs/TICKETS.md](docs/TICKETS.md).

### Phase 1 — Core scanning engine

- `riskrank scan <url>` runs an OWASP ZAP crawl + active scan and prints the findings.
- ZAP client with retries and exponential backoff; never retries *starting* a scan after
  a read timeout (no duplicate scans); waits out a busy ZAP; keeps partial results when a
  scan hits `--max-scan-minutes`; clear errors when ZAP is down, overloaded, rejects the
  API key, or its crawl finds nothing.
- Normalizer from raw ZAP alerts to findings; JSON export (`-o`).
- Validated configuration from `.env`; pre-commit hooks; CI.

### Phase 2 — AI triage layer

- Target context inferred from endpoint paths, overridable with a TOML file (`-c`).
- Anthropic LLM client with retries, `retry-after` support and client-side rate limiting.
- Triage prompt hardened against prompt injection from scanner evidence; replies validated
  and retried.
- Priority score = exploitability × business impact (1–100); tiers derived from the score
  (Critical ≥ 64, High ≥ 36, Medium ≥ 16); ranking with documented tie-breaks.
- Findings grouped by issue and context, so a scan needs one AI call per issue, not per finding.
- Prioritized Markdown report (`-r`) with Markdown-safe escaping.
- Every scan saved to SQLite (UTC timestamps, constraints, cascades).

### Phase 3 — Dashboard and history

- `riskrank serve`: FastAPI JSON API (`/scans`, `/scans/{id}`, `/scans/trend`, `/health`,
  OpenAPI at `/docs`) and web pages: scan history, scan detail with tier filters, risk-trend
  chart; light/dark theme; live "new scan" banner.
- Safeguards: target-ownership confirmation before every scan (`-y` for scripts), a
  `SCAN_ALLOWLIST` that `-y` can't override, localhost-only dashboard.
- Docker image and Docker Compose setup (ZAP, dashboard, CLI, Juice Shop demo target);
  riskrank waits for ZAP and uses a fresh ZAP session per scan.
- Docs: README with screenshots and example output, deployment guide with troubleshooting,
  demo script, `riskrank demo` sample data.

### Known limitations

- ZAP's standard crawler can't reach JavaScript-driven APIs (e.g. Juice Shop's), so those
  endpoints aren't attacked. An AJAX spider option is the next planned feature.
- No authenticated scanning, no dashboard login, no database migrations yet.
