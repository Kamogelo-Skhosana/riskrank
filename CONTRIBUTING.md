# Contributing

This is a personal portfolio project, built ticket-by-ticket across three phases. See [docs/ROADMAP.md](docs/ROADMAP.md) for the phase overview and [docs/TICKETS.md](docs/TICKETS.md) for the full list of 50 tickets.

## One-time setup

Install the dev tools and the git pre-commit hook, which runs ruff and black
automatically on every commit:

```bash
pip install -r requirements-dev.txt
pre-commit install
```

To run the hooks against the whole repo manually: `pre-commit run --all-files`.

## Workflow

1. Pick the next open ticket from `docs/TICKETS.md` (work roughly in order within a phase — later tickets often depend on earlier ones).
2. Create a branch: `git checkout -b R0XX-short-description`
3. Implement the ticket, replacing the relevant `TODO` / `raise NotImplementedError` in the code.
4. Add/update tests for the ticket's scope.
5. Run locally before pushing:
   ```bash
   ruff check src tests
   black --check src tests
   pytest
   ```
6. Open a PR referencing the ticket ID (e.g., `Implements R013 — normalize ZAP alerts`).
7. Check the box for that ticket in `docs/TICKETS.md` once merged.

## Code Style

- Formatted with `black`, linted with `ruff`
- Type hints on all public functions
- Every module has a docstring stating which ticket(s) it belongs to (keeps traceability between code and the ticket list)
