"""SQLite persistence for scans and findings.

Schema (R032):

    scans                         findings
    -----                         --------
    id           PK               id                     PK
    target_url                    scan_id                FK -> scans.id (ON DELETE CASCADE)
    scanned_at   (UTC)            finding_id             e.g. "finding-001", unique per scan
    riskrank_version              type, severity_raw, endpoint
    finding_count                 evidence, description, cwe_id
                                  exploitability_score, business_impact_score (1-10)
                                  priority_score (1-100), priority_tier
                                  ai_explanation, suggested_fix

priority_score is stored (not just computed) so the dashboard can sort and
aggregate in SQL (R036-R038). Tables are created with init_db(); there is
no migration tool yet, so schema changes before v1.0 mean deleting the
local riskrank.db.

Tickets: R032, R033
"""

from datetime import UTC, datetime
from pathlib import Path

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Engine,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    TypeDecorator,
    UniqueConstraint,
    create_engine,
    event,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
    relationship,
    sessionmaker,
)

from riskrank import __version__
from riskrank.scanner.models import Finding
from riskrank.triage.triage import assign_priority_tier


class UTCDateTime(TypeDecorator):
    """Timestamps stored as UTC and always read back timezone-aware.

    SQLite has no timezone support, so a plain DateTime(timezone=True) comes
    back naive. This converts to UTC on the way in and re-attaches UTC on the
    way out, so scan times compare and sort correctly everywhere.
    """

    impl = DateTime
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)  # treat naive times as UTC
        return value.astimezone(UTC).replace(tzinfo=None)

    def process_result_value(self, value: datetime | None, dialect) -> datetime | None:
        return value.replace(tzinfo=UTC) if value is not None else None


class Base(DeclarativeBase):
    pass


class ScanRecord(Base):
    """One run of `riskrank scan` against a target."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target_url: Mapped[str] = mapped_column(String(2048), nullable=False)
    scanned_at: Mapped[datetime] = mapped_column(
        UTCDateTime, nullable=False, default=lambda: datetime.now(UTC)
    )
    riskrank_version: Mapped[str] = mapped_column(String(32), nullable=False)
    finding_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    findings: Mapped[list["FindingRecord"]] = relationship(
        back_populates="scan",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="FindingRecord.id",
    )

    __table_args__ = (
        CheckConstraint("finding_count >= 0", name="ck_scans_finding_count"),
        # Scan history per target, newest first (dashboard list + trend views).
        Index("ix_scans_target_scanned_at", "target_url", "scanned_at"),
    )


class FindingRecord(Base):
    """One (possibly triaged) finding belonging to a scan."""

    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    finding_id: Mapped[str] = mapped_column(String(64), nullable=False)

    type: Mapped[str] = mapped_column(String(512), nullable=False)
    severity_raw: Mapped[str] = mapped_column(String(32), nullable=False)
    endpoint: Mapped[str] = mapped_column(String(2048), nullable=False)
    evidence: Mapped[str | None] = mapped_column(Text)
    description: Mapped[str | None] = mapped_column(Text)
    cwe_id: Mapped[int | None] = mapped_column(Integer)

    exploitability_score: Mapped[int | None] = mapped_column(Integer)
    business_impact_score: Mapped[int | None] = mapped_column(Integer)
    priority_score: Mapped[int | None] = mapped_column(Integer)
    priority_tier: Mapped[str | None] = mapped_column(String(16))
    ai_explanation: Mapped[str | None] = mapped_column(Text)
    suggested_fix: Mapped[str | None] = mapped_column(Text)

    scan: Mapped[ScanRecord] = relationship(back_populates="findings")

    __table_args__ = (
        UniqueConstraint("scan_id", "finding_id", name="uq_findings_scan_finding"),
        CheckConstraint(
            "exploitability_score IS NULL OR exploitability_score BETWEEN 1 AND 10",
            name="ck_findings_exploitability",
        ),
        CheckConstraint(
            "business_impact_score IS NULL OR business_impact_score BETWEEN 1 AND 10",
            name="ck_findings_impact",
        ),
        CheckConstraint(
            "priority_score IS NULL OR priority_score BETWEEN 1 AND 100",
            name="ck_findings_priority_score",
        ),
        CheckConstraint(
            "priority_tier IS NULL OR priority_tier IN ('Critical', 'High', 'Medium', 'Low')",
            name="ck_findings_priority_tier",
        ),
        # Scan detail view: a scan's findings, highest priority first.
        Index("ix_findings_scan_priority", "scan_id", "priority_score"),
    )


def _enable_sqlite_foreign_keys(dbapi_connection, _record) -> None:
    """SQLite ignores foreign keys (and ON DELETE CASCADE) unless asked."""
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


def get_engine(database_url: str) -> Engine:
    """Create an engine for database_url.

    For a file-based SQLite URL the parent directory is created if needed,
    and foreign-key enforcement is switched on for every connection.
    """
    if database_url.startswith("sqlite:///") and not database_url.endswith(":memory:"):
        db_path = database_url.removeprefix("sqlite:///")
        if db_path:
            Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    engine = create_engine(database_url)
    if engine.dialect.name == "sqlite":
        event.listen(engine, "connect", _enable_sqlite_foreign_keys)
    return engine


def init_db(engine: Engine) -> None:
    """Create the scans and findings tables if they don't exist yet."""
    Base.metadata.create_all(engine)


def get_session_factory(engine: Engine) -> sessionmaker:
    """Session factory bound to engine (expire_on_commit=False so records
    stay readable after the session that saved them closes)."""
    return sessionmaker(bind=engine, expire_on_commit=False)


# --- R033: saving and loading scans ------------------------------------------------


def finding_to_record(finding: Finding) -> FindingRecord:
    """Convert a Finding into a row. The tier is re-derived from the scores
    first, so what's stored always matches the ranking."""
    finding = assign_priority_tier(finding)
    return FindingRecord(
        finding_id=finding.id,
        type=finding.type,
        severity_raw=finding.severity_raw,
        endpoint=finding.endpoint,
        evidence=finding.evidence,
        description=finding.description,
        cwe_id=finding.cwe_id,
        exploitability_score=finding.exploitability_score,
        business_impact_score=finding.business_impact_score,
        priority_score=finding.priority_score,
        priority_tier=finding.priority_tier,
        ai_explanation=finding.ai_explanation,
        suggested_fix=finding.suggested_fix,
    )


def record_to_finding(record: FindingRecord) -> Finding:
    """Convert a stored row back into a Finding (priority_score is recomputed)."""
    return Finding(
        id=record.finding_id,
        type=record.type,
        severity_raw=record.severity_raw,
        endpoint=record.endpoint,
        evidence=record.evidence,
        description=record.description,
        cwe_id=record.cwe_id,
        exploitability_score=record.exploitability_score,
        business_impact_score=record.business_impact_score,
        priority_tier=record.priority_tier,
        ai_explanation=record.ai_explanation,
        suggested_fix=record.suggested_fix,
    )


def save_scan(
    engine: Engine,
    target_url: str,
    findings: list[Finding],
    scanned_at: datetime | None = None,
) -> int:
    """Persist a completed scan and its findings; return the new scan's ID.

    Creates the tables first if needed, and writes the scan and all its
    findings in one transaction: either everything is saved or nothing is.

    Raises:
        sqlalchemy.exc.SQLAlchemyError: if the database can't be written.
    """
    init_db(engine)
    scan = ScanRecord(
        target_url=target_url,
        scanned_at=scanned_at or datetime.now(UTC),
        riskrank_version=__version__,
        finding_count=len(findings),
        findings=[finding_to_record(f) for f in findings],
    )
    with get_session_factory(engine).begin() as session:
        session.add(scan)
        session.flush()  # assigns scan.id
        return scan.id


def load_scan(engine: Engine, scan_id: int) -> tuple[ScanRecord, list[Finding]] | None:
    """Load a saved scan and its findings (in saved order), or None if unknown."""
    with get_session_factory(engine)() as session:
        scan = session.get(ScanRecord, scan_id)
        if scan is None:
            return None
        return scan, [record_to_finding(r) for r in scan.findings]
