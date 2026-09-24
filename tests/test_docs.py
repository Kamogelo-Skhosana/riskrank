"""Keep the run/deploy guide in sync with the code (R047)."""

from pathlib import Path

import pytest
from dotenv import dotenv_values
from typer.main import get_command

from riskrank import cli

ROOT = Path(__file__).resolve().parent.parent
GUIDE = (ROOT / "docs" / "DEPLOYMENT.md").read_text(encoding="utf-8")


@pytest.mark.parametrize("variable", list(dotenv_values(ROOT / ".env.example")))
def test_every_setting_is_documented(variable):
    assert f"`{variable}`" in GUIDE


def scan_options():
    command = get_command(cli.app).commands["scan"]
    for param in command.params:
        if param.param_type_name == "option" and param.name != "help":
            yield max(param.opts, key=len)


@pytest.mark.parametrize("option", list(scan_options()))
def test_every_scan_option_is_documented(option):
    assert f"`{option}" in GUIDE, f"{option} is missing from docs/DEPLOYMENT.md"


@pytest.mark.parametrize(
    ("name", "code"),
    [
        ("EXIT_SCAN_FAILED", 1),
        ("EXIT_CONFIG_ERROR", 2),
        ("EXIT_NOT_CONFIRMED", 3),
        ("EXIT_NOT_ALLOWED", 4),
    ],
)
def test_exit_codes_are_documented(name, code):
    assert getattr(cli, name) == code
    assert f"`{code}`" in GUIDE


def test_guide_links_resolve():
    assert (ROOT / "docs" / "ARCHITECTURE.md").is_file()
    assert (ROOT / "examples" / "context.example.toml").is_file()
    assert "#running-zap-locally" in GUIDE
    assert "### Running ZAP locally" in (ROOT / "docs" / "ARCHITECTURE.md").read_text("utf-8")


# --- R048: README ----------------------------------------------------------------------

README = (ROOT / "README.md").read_text(encoding="utf-8")


def readme_links():
    import re

    for target in re.findall(r"\]\(([^)#]+)(?:#[^)]*)?\)", README):
        if not target.startswith(("http://", "https://")):
            yield target


@pytest.mark.parametrize("target", sorted(set(readme_links())))
def test_readme_local_links_and_images_exist(target):
    assert (ROOT / target).exists(), f"README links to missing {target}"


def test_readme_documents_both_commands_and_the_dashboard_api():
    for text in ("riskrank scan", "riskrank serve", "GET /scans", "GET /scans/trend", "/health"):
        assert text in README


def test_readme_shows_screenshots():
    assert README.count("](docs/images/") >= 3
