"""Configuration loading for riskrank.

Loads settings from a .env file (see .env.example) and the process
environment, and exposes them as a single Settings object used across
the scanner, triage, and report layers.

Values set in the real environment take precedence over the .env file.

Ticket: R011
"""

import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from dotenv import dotenv_values

DEFAULT_ENV_FILE = ".env"

# Placeholder values shipped in .env.example. If one of these is still set,
# the user hasn't configured that setting yet, so treat it as missing.
PLACEHOLDER_VALUES = {"your-zap-api-key", "your-llm-api-key"}

# Settings field -> environment variable name (used in error messages).
ENV_VAR_NAMES = {
    "zap_api_url": "ZAP_API_URL",
    "zap_api_key": "ZAP_API_KEY",
    "llm_api_key": "LLM_API_KEY",
    "llm_model": "LLM_MODEL",
    "database_url": "DATABASE_URL",
}


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


@dataclass
class Settings:
    zap_api_url: str
    zap_api_key: str
    llm_api_key: str
    llm_model: str
    database_url: str

    def require(self, *fields: str) -> None:
        """Ensure each named field is set to a real (non-placeholder) value.

        Callers state what they need, so a Phase 1 raw scan doesn't demand
        an LLM key: e.g. ``settings.require("zap_api_key")``.

        Raises:
            ConfigError: listing every missing variable and pointing the
                user at .env.example.
        """
        missing = [
            ENV_VAR_NAMES[f]
            for f in fields
            if not getattr(self, f) or getattr(self, f) in PLACEHOLDER_VALUES
        ]
        if missing:
            raise ConfigError(
                f"Missing required configuration: {', '.join(missing)}. "
                "Copy .env.example to .env and fill in these values "
                "(or set them as environment variables)."
            )


def _validate_url(name: str, value: str, schemes: tuple[str, ...]) -> None:
    parsed = urlparse(value)
    if parsed.scheme not in schemes or not (parsed.netloc or parsed.path):
        raise ConfigError(
            f"Invalid {name}: {value!r}. Expected a URL starting with "
            f"{' or '.join(s + '://' for s in schemes)} (see .env.example)."
        )


def load_settings(env_file: str | Path = DEFAULT_ENV_FILE) -> Settings:
    """Load settings from the environment and an optional .env file.

    Only format is validated here (URLs must be well-formed). Whether a
    given key is *required* depends on the command being run — use
    Settings.require() for that.

    Raises:
        ConfigError: if ZAP_API_URL or DATABASE_URL is malformed.
    """
    file_values = dotenv_values(env_file) if Path(env_file).is_file() else {}

    def get(key: str, default: str = "") -> str:
        value = os.environ.get(key)
        if value is None:
            value = file_values.get(key)
        return (value if value is not None else default).strip()

    settings = Settings(
        zap_api_url=get("ZAP_API_URL", "http://localhost:8080"),
        zap_api_key=get("ZAP_API_KEY"),
        llm_api_key=get("LLM_API_KEY"),
        llm_model=get("LLM_MODEL", "claude-sonnet-4-6"),
        database_url=get("DATABASE_URL", "sqlite:///./riskrank.db"),
    )

    _validate_url("ZAP_API_URL", settings.zap_api_url, ("http", "https"))
    _validate_url("DATABASE_URL", settings.database_url, ("sqlite",))
    return settings
