# riskrank

**AI-powered vulnerability scanner and prioritizer.** riskrank wraps an established security scanner (OWASP ZAP), then uses an LLM to triage the raw findings by real-world exploitability and business impact — turning a wall of low-value alerts into a short, prioritized "fix this first" list.

> Cybersecurity Testing track.

---

## Why riskrank

Raw vulnerability scanner output is famously noisy. A single scan against a moderately complex app can produce hundreds of findings, most of them low-value or irrelevant to the actual risk. riskrank adds a reasoning layer on top of an existing scanner: it looks at *what* was found, *where* it was found (a public login endpoint vs. an internal admin tool), and *what kind of data* is at risk — then ranks findings the way a human security reviewer would, and explains why.

## What It Does

1. **Scans** a target application using OWASP ZAP
2. **Collects** raw findings (vulnerability type, severity, affected endpoint, evidence)
3. **Triages** each finding with an LLM — scoring exploitability and business impact in context, not just by the scanner's default severity label
4. **Reports** a prioritized, human-readable remediation report: what to fix first, why it matters, and roughly how
5. **Tracks** scans over time via a lightweight dashboard, so you can see whether your risk posture is improving

## Project Phases

riskrank is built in three phases, each ending in something tangible and demoable. See [docs/ROADMAP.md](docs/ROADMAP.md) for the full breakdown and [docs/TICKETS.md](docs/TICKETS.md) for the complete ticket list (50 tickets total).

| Phase | Goal | You end this phase with... |
|---|---|---|
| **Phase 1 — Core Scanning Engine** | Wrap ZAP, run a scan, get raw findings | A working CLI: `riskrank scan <url>` → JSON/console report of raw findings |
| **Phase 2 — AI Triage Layer** | Add the reasoning layer on top of raw findings | The same CLI now outputs a **prioritized, plain-English remediation report**, ranked and explained |
| **Phase 3 — Dashboard & History** | Make it demoable and track scans over time | A deployed web dashboard showing scan history, trends, and prioritized findings per scan |

## Tech Stack

- **Scanning engine:** [OWASP ZAP](https://www.zaproxy.org/) (via its REST API)
- **Backend / CLI:** Python (FastAPI for the API layer, Typer/Click for the CLI)
- **AI triage:** LLM API call for scoring and explaining findings
- **Storage:** SQLite (local, zero-setup) for scan history
- **Dashboard:** Lightweight web frontend (Phase 3) served by the FastAPI backend
- **CI:** GitHub Actions — lint + test on every push/PR

## Quick Start

**Requires Python 3.11+** (check with `python --version`).

```bash
# Clone
git clone https://github.com/Kamogelo-Skhosana/riskrank.git
cd riskrank

# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # macOS / Linux
# .venv\Scripts\activate         # Windows (PowerShell / cmd)

# Install riskrank (editable) plus dev tools
pip install -r requirements.txt -r requirements-dev.txt
pip install -e .

# Configure
cp .env.example .env
# edit .env with your ZAP instance details and LLM API key

# Run a scan (Phase 1+)
riskrank scan https://example-target.com
```

`pip install -e .` installs the `riskrank` command and makes the `src/` package importable. Without it, `python -m riskrank.cli` fails with `ModuleNotFoundError` unless you set `PYTHONPATH=src`.

Full setup instructions (including running OWASP ZAP locally via Docker) are in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Project Structure

```
riskrank/
├── .github/
│   └── workflows/
│       └── ci.yml            # Lint + test pipeline
├── src/
│   └── riskrank/
│       ├── scanner/          # ZAP integration — triggers scans, pulls raw findings
│       ├── triage/           # AI prioritization layer — scores + explains findings
│       ├── report/           # Report generation (console, markdown, JSON)
│       ├── dashboard/        # Phase 3 — web dashboard + API routes
│       ├── cli.py            # CLI entry point
│       └── config.py         # Configuration loading (.env, target profiles)
├── tests/                    # Unit + integration tests, mirrors src/ layout
├── docs/
│   ├── ARCHITECTURE.md       # System design, data flow, setup details
│   ├── ROADMAP.md            # Phase breakdown + tangible deliverables
│   └── TICKETS.md            # All 50 tickets, grouped by phase and epic
├── examples/                 # Sample target configs / sample findings for testing
├── .env.example
├── .gitignore
├── requirements.txt
├── pyproject.toml
├── CONTRIBUTING.md
└── LICENSE
```

## Responsible Use

riskrank is intended for scanning applications you own or have explicit permission to test. Never point it at third-party systems without authorization. Phase 3 will include a target-ownership confirmation step before any scan runs.

## Code

WTC-GJ5N4C9C

## License

MIT — see [LICENSE](LICENSE).
