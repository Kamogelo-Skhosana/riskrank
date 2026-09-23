"""Tests for configuration loading and validation.

Ticket: R011
"""

import pytest

from riskrank.config import ConfigError, load_settings

ALL_VARS = ["ZAP_API_URL", "ZAP_API_KEY", "LLM_API_KEY", "LLM_MODEL", "DATABASE_URL"]


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Isolate each test from the real environment."""
    for var in ALL_VARS:
        monkeypatch.delenv(var, raising=False)


@pytest.fixture
def no_env_file(tmp_path):
    return tmp_path / "does-not-exist.env"


def test_defaults_when_nothing_configured(no_env_file):
    settings = load_settings(no_env_file)
    assert settings.zap_api_url == "http://localhost:8080"
    assert settings.llm_model == "claude-sonnet-4-6"
    assert settings.database_url == "sqlite:///./riskrank.db"
    assert settings.zap_api_key == ""


def test_reads_values_from_env_file(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("ZAP_API_URL=http://zap:8090\nZAP_API_KEY=abc123\n")
    settings = load_settings(env_file)
    assert settings.zap_api_url == "http://zap:8090"
    assert settings.zap_api_key == "abc123"


def test_environment_overrides_env_file(tmp_path, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("ZAP_API_KEY=from-file\n")
    monkeypatch.setenv("ZAP_API_KEY", "from-env")
    assert load_settings(env_file).zap_api_key == "from-env"


def test_require_reports_all_missing_vars(no_env_file):
    settings = load_settings(no_env_file)
    with pytest.raises(ConfigError) as exc:
        settings.require("zap_api_key", "llm_api_key")
    message = str(exc.value)
    assert "ZAP_API_KEY" in message
    assert "LLM_API_KEY" in message
    assert ".env.example" in message


def test_require_treats_example_placeholders_as_missing(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text("ZAP_API_KEY=your-zap-api-key\n")
    with pytest.raises(ConfigError, match="ZAP_API_KEY"):
        load_settings(env_file).require("zap_api_key")


def test_llm_key_not_required_for_zap_only(no_env_file, monkeypatch):
    """A Phase 1 raw scan must not demand an LLM key."""
    monkeypatch.setenv("ZAP_API_KEY", "abc123")
    load_settings(no_env_file).require("zap_api_key")


@pytest.mark.parametrize("bad_url", ["localhost:8080", "ftp://zap:21", "not a url"])
def test_invalid_zap_url_raises(no_env_file, monkeypatch, bad_url):
    monkeypatch.setenv("ZAP_API_URL", bad_url)
    with pytest.raises(ConfigError, match="ZAP_API_URL"):
        load_settings(no_env_file)


def test_invalid_database_url_raises(no_env_file, monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgres://db/riskrank")
    with pytest.raises(ConfigError, match="DATABASE_URL"):
        load_settings(no_env_file)
