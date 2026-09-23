"""SQLite persistence for scans and findings.

Tickets: R032, R033
"""

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base

Base = declarative_base()

# TODO (R032): define Scan and Finding ORM models/tables here.


def get_engine(database_url: str):
    return create_engine(database_url)


def save_scan(engine, target_url: str, findings: list) -> None:
    """Persist a completed scan and its findings.

    TODO (R033): insert a Scan row and related Finding rows.
    """
    raise NotImplementedError
