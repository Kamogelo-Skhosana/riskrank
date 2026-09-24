# Running riskrank

This guide covers running riskrank on your own computer, with Docker Compose
(recommended) or directly with Python.

**Why there's no public hosted deployment:** riskrank sends real attack payloads
to the targets it scans, the dashboard has no login yet, and the scan database
lists every weakness found. Hosting it on the internet would put all three in
reach of strangers. It is designed to run locally, next to the apps you are
testing. If you need to share it, see [Sharing on a trusted network](#sharing-on-a-trusted-network).

**Only scan applications you own or have explicit, written permission to test.**

---

## Option A: Docker Compose (recommended)

Needs [Docker Desktop](https://www.docker.com/products/docker-desktop/) (or Docker Engine
with the Compose plugin). Nothing else to install.

### 1. Configure

```bash
cp .env.example .env
```

Edit `.env`:

- `ZAP_API_KEY`: any random string. It protects ZAP's API; riskrank and ZAP both
  read it from `.env`. To generate one: `python -c "import secrets; print(secrets.token_hex(16))"`
- `LLM_API_KEY`: your Anthropic API key, to rank findings with AI triage.
  Optional: without it, scans still run and findings are listed by scanner severity.

### 2. Start ZAP and the dashboard

```bash
docker compose up -d --build
```

- Dashboard: <http://localhost:8000>
- ZAP API: <http://localhost:8080> (used by riskrank; you don't need to open it)

Add `--profile demo` to also start the OWASP Juice Shop practice target:

```bash
docker compose --profile demo up -d --build
```

### 3. Run a scan

```bash
docker compose run --rm riskrank scan http://juice-shop:3000 -y -r report.md -o findings.json
```

- Inside Compose, targets are reached by **service name** (`http://juice-shop:3000`).
  For an app running on your computer, use `http://host.docker.internal:<port>`.
- `report.md` and `findings.json` are written to the `scans/` folder of the repo.
- The scan is saved to the database, so it appears in the dashboard straight away
  (an open dashboard page shows a "new scan" banner).
- riskrank waits for ZAP to finish starting and gives each scan a fresh ZAP session.

A full Juice Shop scan takes 20-60 minutes. For a quicker run add `--max-scan-minutes 15`
(riskrank stops the active scan at the limit and keeps what it found).

### 4. Stop / clean up

```bash
docker compose --profile demo down        # stop (scan history is kept)
docker compose --profile demo down -v     # stop and DELETE the scan history volume
```

---

## Option B: Python on your computer

Needs Python 3.11+ and ZAP running (e.g. `docker compose up -d zap`, or the
`docker run` command in [ARCHITECTURE.md](ARCHITECTURE.md#running-zap-locally)).

```bash
python -m venv .venv
source .venv/bin/activate          # macOS / Linux
# source .venv/Scripts/activate    # Windows (Git Bash)
# .venv\Scripts\activate           # Windows (PowerShell / cmd)

pip install -r requirements.txt
pip install -e .

cp .env.example .env               # then fill in ZAP_API_KEY and LLM_API_KEY
```

Scan, then open the dashboard:

```bash
riskrank scan http://localhost:3000 -y -r report.md
riskrank serve                     # http://localhost:8000
```

When ZAP runs in Docker and the target runs on your computer, ZAP must reach it as
`http://host.docker.internal:<port>`, not `localhost` (inside ZAP's container,
`localhost` is ZAP itself).

---

## Configuration reference

All settings come from `.env` or environment variables (environment wins).

| Variable | Default | Purpose |
|---|---|---|
| `ZAP_API_URL` | `http://localhost:8080` | Where riskrank reaches ZAP (Compose sets `http://zap:8080`) |
| `ZAP_API_KEY` | *(required)* | Key for ZAP's API; must match the key ZAP was started with |
| `LLM_API_KEY` | *(empty)* | Anthropic API key for AI triage; triage is skipped without it |
| `LLM_MODEL` | `claude-sonnet-4-6` | Model used for triage |
| `SCAN_ALLOWLIST` | *(empty = no restriction)* | Comma-separated hosts riskrank may scan: `host`, `host:port`, `*.example.com`, IP or CIDR. Refused targets can't be forced with `--yes` |
| `DATABASE_URL` | `sqlite:///./riskrank.db` | SQLite database for scan history (Compose: `/data` volume) |
| `DASHBOARD_HOST` | `127.0.0.1` | Address `riskrank serve` listens on |
| `DASHBOARD_PORT` | `8000` | Port `riskrank serve` listens on (Compose: host port) |

Common `riskrank scan` options (`riskrank scan --help` lists all):

| Option | Purpose |
|---|---|
| `-y`, `--yes` | Confirm you may test the target (skips the prompt; required in scripts/CI) |
| `-o`, `--output FILE` | Write findings as JSON |
| `-r`, `--report FILE` | Write the prioritized Markdown report |
| `-c`, `--context FILE` | Describe the target (public / sensitive / login per endpoint); see `examples/context.example.toml` |
| `--triage` / `--no-triage` | Require or skip AI triage (default: on when `LLM_API_KEY` is set) |
| `--save` / `--no-save` | Save to the database (default: save) |
| `--max-scan-minutes N` | Stop the active scan after N minutes and keep partial results (default 60) |
| `--zap-wait-seconds N` | How long to wait for ZAP to start (default 120) |
| `--keep-zap-session` | Don't reset ZAP before scanning (keeps alerts from earlier scans) |

Exit codes: `0` success, `1` scan failed, `2` configuration error,
`3` ownership not confirmed, `4` target not on the allowlist.

---

## Data, backups and upgrades

- **Where scans live:** `riskrank.db` (Python) or the `riskrank-data` Docker volume (Compose).
- **Back up (Compose):**
  `docker compose run --rm --entrypoint sh -v "$PWD/scans:/backup" riskrank -c "cp /data/riskrank.db /backup/"`
- **Upgrading before v1.0:** there are no database migrations yet. If a new version
  changes the schema, move the old `riskrank.db` aside (or `docker compose down -v`)
  and scan again.

---

## Sharing on a trusted network

The dashboard has **no login**, so by default it only listens on `127.0.0.1` and
Compose publishes every port on `127.0.0.1` only.

If you must share it (e.g. with a teammate on the same private network), put it behind
a reverse proxy that adds authentication and HTTPS, and never expose ZAP or Juice
Shop. `riskrank serve --host 0.0.0.0` prints a warning as a reminder. Never publish
riskrank on the public internet.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `Configuration error: Missing required configuration: ZAP_API_KEY` | No `.env`, or the key is still the placeholder. `cp .env.example .env` and set `ZAP_API_KEY` |
| `ZAP rejected the API key` | The key in `.env` differs from the one ZAP was started with. Restart ZAP with the same key (`docker compose up -d zap` reads it from `.env`) |
| `Could not reach ZAP ... Is it running?` / `did not become ready` | ZAP isn't running or is still starting: `docker ps`, `docker compose logs zap`. Raise `--zap-wait-seconds` on slow machines |
| `ZAP's crawl found no pages` | ZAP can't reach the target. Check the target is up (`docker ps`, open it in a browser). From Docker, use `host.docker.internal` or the Compose service name, not `localhost` |
| `ZAP ... is running but did not respond` / many "still waiting" warnings | ZAP is overloaded by the scan. Give Docker more memory (4 GB+) and CPU in Docker Desktop settings |
| Scan stopped at the time limit | Expected on big apps: results are partial. Use a larger `--max-scan-minutes` |
| `AI triage skipped: set LLM_API_KEY` | Add your Anthropic key to `.env` to rank findings by real-world risk |
| `Scan refused: ... not on the scan allowlist` | Add the host to `SCAN_ALLOWLIST` in `.env` (only if you own it or have permission) |
| `Scan refused: no one confirmed ...` | Non-interactive run (script/CI): add `-y` if you own the target |
| Port 8000/8080/3000 already in use | Another container or app uses it (e.g. an old `docker run` ZAP): `docker rm -f zap juice-shop`, or change `DASHBOARD_PORT` |
| Juice Shop scan finds no High issues | ZAP's standard crawler can't see Juice Shop's JavaScript-driven API, so its injection bugs aren't reached. Expected with the default crawler |
