"""Tests for the SQLite persistence layer (in-memory / temp-file databases).

Tickets: R032, R033
"""

from datetime import UTC, datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError

from riskrank.report.persistence import (
    FindingRecord,
    ScanRecord,
    get_engine,
    get_session_factory,
    init_db,
)


@pytest.fixture
def engine():
    engine = get_engine("sqlite:///:memory:")
    init_db(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def session(engine):
    with get_session_factory(engine)() as session:
        yield session


def make_scan(**overrides) -> ScanRecord:
    values = {
        "target_url": "http://localhost:3000",
        "scanned_at": datetime(2026, 9, 24, 10, 15, tzinfo=UTC),
        "riskrank_version": "0.1.0",
        "finding_count": 1,
    }
    values.update(overrides)
    return ScanRecord(**values)


def make_finding(**overrides) -> FindingRecord:
    values = {
        "finding_id": "finding-001",
        "type": "SQL Injection",
        "severity_raw": "High",
        "endpoint": "/rest/user/login",
        "cwe_id": 89,
        "exploitability_score": 9,
        "business_impact_score": 9,
        "priority_score": 81,
        "priority_tier": "Critical",
    }
    values.update(overrides)
    return FindingRecord(**values)


# --- R032: schema ----------------------------------------------------------------


def test_init_db_creates_both_tables(engine):
    assert set(inspect(engine).get_table_names()) == {"scans", "findings"}


def test_findings_columns_cover_every_finding_field(engine):
    from riskrank.scanner.models import Finding

    columns = {c["name"] for c in inspect(engine).get_columns("findings")}
    for field in Finding.model_fields:
        expected = "finding_id" if field == "id" else field
        assert expected in columns, f"missing column for Finding.{field}"
    assert "priority_score" in columns  # stored for SQL sorting/aggregation
    assert "scan_id" in columns


def test_indexes_exist(engine):
    scan_indexes = {i["name"] for i in inspect(engine).get_indexes("scans")}
    finding_indexes = {i["name"] for i in inspect(engine).get_indexes("findings")}
    assert "ix_scans_target_scanned_at" in scan_indexes
    assert "ix_findings_scan_priority" in finding_indexes


def test_init_db_is_idempotent(engine):
    init_db(engine)  # second call must not fail or wipe anything
    assert set(inspect(engine).get_table_names()) == {"scans", "findings"}


def test_scan_with_findings_round_trips(session):
    scan = make_scan()
    scan.findings.append(make_finding())
    scan.findings.append(
        make_finding(
            finding_id="finding-002",
            priority_score=None,
            exploitability_score=None,
            business_impact_score=None,
            priority_tier=None,
            type="Info",
            severity_raw="Low",
        )
    )
    session.add(scan)
    session.commit()

    loaded = session.scalars(select(ScanRecord)).one()
    assert loaded.target_url == "http://localhost:3000"
    assert [f.finding_id for f in loaded.findings] == ["finding-001", "finding-002"]
    assert loaded.findings[0].scan is loaded
    assert loaded.findings[1].priority_tier is None


def test_scanned_at_and_finding_count_have_defaults(session):
    session.add(ScanRecord(target_url="t", riskrank_version="0.1.0"))
    session.commit()
    stored = session.scalars(select(ScanRecord)).one()
    assert abs((datetime.now(UTC) - stored.scanned_at).total_seconds()) < 60
    assert stored.finding_count == 0


def _reload_scanned_at(engine, scanned_at):
    with get_session_factory(engine)() as session:
        session.add(make_scan(scanned_at=scanned_at))
        session.commit()
    with get_session_factory(engine)() as session:  # fresh session: read from the DB
        return session.scalars(select(ScanRecord.scanned_at)).one()


def test_scanned_at_is_read_back_as_utc(engine):
    loaded = _reload_scanned_at(engine, datetime(2026, 9, 24, 10, 15, tzinfo=UTC))
    assert loaded == datetime(2026, 9, 24, 10, 15, tzinfo=UTC)
    assert loaded.tzinfo is UTC


def test_scanned_at_in_another_timezone_is_converted_to_utc(engine):
    sast = timezone(timedelta(hours=2))
    loaded = _reload_scanned_at(engine, datetime(2026, 9, 24, 12, 15, tzinfo=sast))
    assert loaded == datetime(2026, 9, 24, 10, 15, tzinfo=UTC)


def test_naive_scanned_at_is_treated_as_utc(engine):
    naive = datetime(2026, 9, 24, 10, 15)  # noqa: DTZ001 - naive on purpose
    assert _reload_scanned_at(engine, naive) == datetime(2026, 9, 24, 10, 15, tzinfo=UTC)


def test_deleting_a_scan_deletes_its_findings(session):
    scan = make_scan()
    scan.findings.extend([make_finding(), make_finding(finding_id="finding-002")])
    session.add(scan)
    session.commit()

    session.delete(scan)
    session.commit()
    assert session.scalars(select(FindingRecord)).all() == []


def test_database_level_cascade_via_foreign_keys(engine):
    """ON DELETE CASCADE works even for raw SQL, because FKs are switched on."""
    with get_session_factory(engine)() as session:
        scan = make_scan()
        scan.findings.append(make_finding())
        session.add(scan)
        session.commit()
    with engine.begin() as conn:
        conn.exec_driver_sql("DELETE FROM scans")
        assert conn.exec_driver_sql("SELECT COUNT(*) FROM findings").scalar() == 0


def test_finding_requires_an_existing_scan(engine):
    with engine.begin() as conn, pytest.raises(IntegrityError):
        conn.exec_driver_sql(
            "INSERT INTO findings (scan_id, finding_id, type, severity_raw, endpoint) "
            "VALUES (999, 'f', 't', 'Low', '/')"
        )


def test_finding_ids_are_unique_within_a_scan(session):
    scan = make_scan()
    scan.findings.extend([make_finding(), make_finding()])
    session.add(scan)
    with pytest.raises(IntegrityError):
        session.commit()


def test_same_finding_id_allowed_in_different_scans(session):
    for _ in range(2):
        scan = make_scan()
        scan.findings.append(make_finding())
        session.add(scan)
    session.commit()
    assert len(session.scalars(select(FindingRecord)).all()) == 2


@pytest.mark.parametrize(
    "bad",
    [
        {"exploitability_score": 0},
        {"business_impact_score": 11},
        {"priority_score": 101},
        {"priority_tier": "Urgent"},
    ],
)
def test_check_constraints_reject_invalid_values(session, bad):
    scan = make_scan()
    scan.findings.append(make_finding(**bad))
    session.add(scan)
    with pytest.raises(IntegrityError):
        session.commit()


def test_negative_finding_count_rejected(session):
    session.add(make_scan(finding_count=-1))
    with pytest.raises(IntegrityError):
        session.commit()


def test_file_database_creates_parent_directory(tmp_path):
    db_file = tmp_path / "data" / "nested" / "riskrank.db"
    engine = get_engine(f"sqlite:///{db_file}")
    init_db(engine)
    engine.dispose()
    assert db_file.is_file()


def test_utc_datetime_passes_none_through():
    from riskrank.report.persistence import UTCDateTime

    column_type = UTCDateTime()
    assert column_type.process_bind_param(None, None) is None
    assert column_type.process_result_value(None, None) is None
