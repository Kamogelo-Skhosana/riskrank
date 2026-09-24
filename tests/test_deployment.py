"""Checks on the Docker deployment files (R046).

CI also builds the image and runs it (see the `docker` job in ci.yml); these
tests catch configuration mistakes earlier, without needing Docker.
"""

from pathlib import Path

import pytest
import yaml
from dotenv import dotenv_values

from riskrank.dashboard.safeguard import is_target_allowed, parse_allowlist

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="module")
def compose():
    return yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def dockerfile():
    return (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_compose_defines_the_expected_services(compose):
    services = compose["services"]
    assert set(services) == {"zap", "dashboard", "riskrank", "juice-shop"}
    assert services["riskrank"]["profiles"] == ["cli"]  # not started by `up`
    assert services["juice-shop"]["profiles"] == ["demo"]


def test_published_ports_are_localhost_only(compose):
    """No login yet, and Juice Shop is deliberately vulnerable: never expose them."""
    for name, service in compose["services"].items():
        for port in service.get("ports", []):
            assert port.startswith("127.0.0.1:"), f"{name} publishes {port} on all interfaces"


def test_zap_api_key_comes_from_env_and_is_required(compose):
    command = compose["services"]["zap"]["command"]
    assert "api.key=${ZAP_API_KEY:?" in command
    assert "api.addrs.addr.name=.*" in command


def test_cli_waits_for_a_healthy_zap(compose):
    assert compose["services"]["riskrank"]["depends_on"]["zap"]["condition"] == "service_healthy"
    assert "healthcheck" in compose["services"]["zap"]


def test_cli_and_dashboard_share_the_database(compose):
    for name in ("dashboard", "riskrank"):
        service = compose["services"][name]
        assert "riskrank-data:/data" in service["volumes"]
        assert service["environment"]["DATABASE_URL"] == "sqlite:////data/riskrank.db"
        assert service["environment"]["ZAP_API_URL"] == "http://zap:8080"
    assert "./scans:/scans" in compose["services"]["riskrank"]["volumes"]


def test_default_allowlist_permits_the_compose_demo_target(compose):
    value = compose["services"]["riskrank"]["environment"]["SCAN_ALLOWLIST"]
    default = value.split(":-", 1)[1].rstrip("}")
    allowlist = parse_allowlist(default)
    assert is_target_allowed("http://juice-shop:3000", allowlist)
    assert not is_target_allowed("https://example.com", allowlist)


def test_env_example_has_every_variable_compose_needs():
    env = dotenv_values(ROOT / ".env.example")
    assert env.get("ZAP_API_KEY")
    assert env.get("DASHBOARD_PORT")


def test_image_runs_as_a_non_root_user(dockerfile):
    assert "USER riskrank" in dockerfile
    assert "useradd" in dockerfile


def test_image_entrypoint_and_defaults(dockerfile):
    assert 'ENTRYPOINT ["riskrank"]' in dockerfile
    assert 'CMD ["serve"]' in dockerfile
    assert "DATABASE_URL=sqlite:////data/riskrank.db" in dockerfile
    assert "FROM python:3.11" in dockerfile  # matches requires-python and CI


def test_secrets_and_local_state_stay_out_of_the_image():
    ignored = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    for pattern in (".env", "*.db", ".git", ".venv", "findings.json", "report.md"):
        assert pattern in ignored
    assert "!README.md" in ignored  # needed by pyproject's readme field


def test_ci_builds_and_smoke_tests_the_image():
    ci = yaml.safe_load((ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8"))
    steps = " ".join(step.get("run", "") for step in ci["jobs"]["docker"]["steps"])
    assert "docker build" in steps
    assert "/health" in steps
    assert "docker compose config" in steps
