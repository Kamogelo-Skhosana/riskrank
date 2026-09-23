"""Configuration loading for riskrank.

Loads settings from a .env file (see .env.example) and exposes them
as a single Settings object used across the scanner, triage, and
report layers.

Ticket: R011
"""

from dataclasses import dataclass
from dotenv import load_dotenv
import os


@dataclass
class Settings:
    zap_api_url: str
    zap_api_key: str
    llm_api_key: str
    llm_model: str
    database_url: str


def load_settings() -> Settings:
    """Load settings from environment / .env file.

    TODO (R011): validate required fields are present and raise a
    clear error pointing the user at .env.example if not.
    """
    load_dotenv()
    return Settings(
        zap_api_url=os.getenv("ZAP_API_URL", "http://localhost:8080"),
        zap_api_key=os.getenv("ZAP_API_KEY", ""),
        llm_api_key=os.getenv("LLM_API_KEY", ""),
        llm_model=os.getenv("LLM_MODEL", "claude-sonnet-4-6"),
        database_url=os.getenv("DATABASE_URL", "sqlite:///./riskrank.db"),
    )
