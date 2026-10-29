"""Versioned SQLite persistence for AutoPen assessments and evidence."""

from __future__ import annotations

import re
import sqlite3
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_DATABASE_PATH = Path("data/autopen.db")
CURRENT_SCHEMA_VERSION = 2

# running: in progress; completed: all required stages succeeded; partial: useful
# evidence exists but a stage failed; failed: no complete host result; interrupted:
# cancelled; legacy_unknown: migrated evidence cannot prove the historical outcome.
EXECUTION_STATUSES = (
    "running", "completed", "partial", "failed", "interrupted", "legacy_unknown"
)
PHASE_STATUSES = (
    "running", "completed", "partial", "failed", "interrupted", "skipped", "timed_out"
)
CREDENTIAL_OUTCOMES = ("matched", "no_match", "skipped", "failed", "timed_out")
ARTIFACT_STATUSES = ("pending", "available", "incomplete", "failed")


class DatabaseError(RuntimeError):
    """Raised when AutoPen cannot migrate or persist assessment data."""


class NewerSchemaError(DatabaseError):
    """Raised when a database was created by a newer AutoPen version."""


def utc_timestamp() -> str:
    """Return a precise, timezone-aware UTC timestamp for phase correlation."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def sanitize_error_summary(message: object | None, limit: int = 500) -> str | None:
    """Return a short single-line error with credential-like values redacted."""
    if message is None:
        return None
    text = " ".join(str(message).split())
    text = re.sub(
        r"(?i)\b(password|passwd|credential)\s*[:=]\s*\S+",
        r"\1=[REDACTED]",
        text,
    )
    return text[:limit] or None


@contextmanager
def _connection(database_path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        yield connection
    finally:
        connection.close()


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone() is not None


def _migration_1(connection: sqlite3.Connection) -> None:
    """Create the original single-target schema for a fresh database."""
    statements = (
        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)",
        """CREATE TABLE assessments (
            id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL,
            started_at TEXT NOT NULL, finished_at TEXT)""",
        """CREATE TABLE services (
            id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
            port INTEGER NOT NULL, protocol TEXT NOT NULL, state TEXT NOT NULL,
            service TEXT NOT NULL, version TEXT NOT NULL DEFAULT '',
            FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE)""",
        """CREATE TABLE packets (
            id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
            timestamp TEXT, src_ip TEXT, dst_ip TEXT, protocol TEXT NOT NULL,
            src_port INTEGER, dst_port INTEGER, length INTEGER,
            FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE)""",
        """CREATE TABLE credential_results (
            id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
            service TEXT NOT NULL, port INTEGER NOT NULL, username TEXT NOT NULL,
            credential_found INTEGER NOT NULL CHECK (credential_found IN (0, 1)),
            FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE)""",
        "CREATE INDEX idx_services_assessment ON services(assessment_id)",
        "CREATE INDEX idx_packets_assessment ON packets(assessment_id)",
        "CREATE INDEX idx_packets_ports ON packets(assessment_id, src_port, dst_port)",
        "CREATE INDEX idx_credential_results_assessment ON credential_results(assessment_id)",
    )
    for statement in statements:
        connection.execute(statement)


def _migration_2(connection: sqlite3.Connection) -> None:
    """Add host, outcome, phase, and artifact foundations without losing legacy data."""
    execution_values = ", ".join(f"'{value}'" for value in EXECUTION_STATUSES)
    phase_values = ", ".join(f"'{value}'" for value in PHASE_STATUSES)
    credential_values = ", ".join(f"'{value}'" for value in CREDENTIAL_OUTCOMES)
    artifact_values = ", ".join(f"'{value}'" for value in ARTIFACT_STATUSES)

    connection.execute(f"""ALTER TABLE assessments ADD COLUMN status TEXT NOT NULL
        DEFAULT 'legacy_unknown' CHECK (status IN ({execution_values}))""")
    connection.execute(f"""CREATE TABLE assessment_hosts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
        target TEXT NOT NULL, interface TEXT,
        status TEXT NOT NULL CHECK (status IN ({execution_values})),
        started_at TEXT NOT NULL, finished_at TEXT, error_summary TEXT,
        UNIQUE (assessment_id, target), UNIQUE (id, assessment_id),
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE)""")
    connection.execute("""INSERT INTO assessment_hosts
        (assessment_id, target, interface, status, started_at, finished_at)
        SELECT id, target, NULL, 'legacy_unknown', started_at, finished_at FROM assessments""")

    connection.execute("DROP INDEX IF EXISTS idx_services_assessment")
    connection.execute("ALTER TABLE services RENAME TO services_legacy_v1")
    connection.execute("""CREATE TABLE services (
        id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
        host_id INTEGER, port INTEGER NOT NULL, protocol TEXT NOT NULL,
        state TEXT NOT NULL, service TEXT NOT NULL, version TEXT NOT NULL DEFAULT '',
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
        FOREIGN KEY (host_id, assessment_id)
            REFERENCES assessment_hosts(id, assessment_id) ON DELETE CASCADE)""")
    connection.execute("""INSERT INTO services
        (id, assessment_id, host_id, port, protocol, state, service, version)
        SELECT s.id, s.assessment_id, h.id, s.port, s.protocol, s.state,
               s.service, s.version FROM services_legacy_v1 AS s
        JOIN assessment_hosts AS h ON h.assessment_id = s.assessment_id""")
    connection.execute("DROP TABLE services_legacy_v1")
    connection.execute("CREATE INDEX idx_services_assessment ON services(assessment_id)")
    connection.execute("CREATE INDEX idx_services_host ON services(host_id)")

    connection.execute("DROP INDEX IF EXISTS idx_credential_results_assessment")
    connection.execute("ALTER TABLE credential_results RENAME TO credential_results_legacy_v1")
    connection.execute(f"""CREATE TABLE credential_results (
        id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
        host_id INTEGER, service TEXT NOT NULL, port INTEGER, username TEXT,
        outcome TEXT NOT NULL CHECK (outcome IN ({credential_values})),
        credential_found INTEGER CHECK (credential_found IN (0, 1)),
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
        FOREIGN KEY (host_id, assessment_id)
            REFERENCES assessment_hosts(id, assessment_id) ON DELETE CASCADE)""")
    connection.execute("""INSERT INTO credential_results
        (id, assessment_id, host_id, service, port, username, outcome, credential_found)
        SELECT c.id, c.assessment_id, h.id, c.service, c.port, c.username,
               CASE WHEN c.credential_found = 1 THEN 'matched' ELSE 'no_match' END,
               c.credential_found FROM credential_results_legacy_v1 AS c
        JOIN assessment_hosts AS h ON h.assessment_id = c.assessment_id""")
    connection.execute("DROP TABLE credential_results_legacy_v1")
    connection.execute(
        "CREATE INDEX idx_credential_results_assessment ON credential_results(assessment_id)"
    )
    connection.execute("CREATE INDEX idx_credential_results_host ON credential_results(host_id)")

    connection.execute(f"""CREATE TABLE assessment_phases (
        id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
        host_id INTEGER, phase_name TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ({phase_values})),
        started_at TEXT NOT NULL, finished_at TEXT, error_summary TEXT,
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE,
        FOREIGN KEY (host_id, assessment_id)
            REFERENCES assessment_hosts(id, assessment_id) ON DELETE CASCADE)""")
    connection.execute(
        "CREATE INDEX idx_assessment_phases_assessment ON assessment_phases(assessment_id)"
    )
    connection.execute("CREATE INDEX idx_assessment_phases_host ON assessment_phases(host_id)")
    connection.execute(f"""CREATE TABLE artifacts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, assessment_id INTEGER NOT NULL,
        artifact_type TEXT NOT NULL, path TEXT NOT NULL,
        status TEXT NOT NULL CHECK (status IN ({artifact_values})),
        UNIQUE (assessment_id, artifact_type),
        FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE)""")
    connection.execute("CREATE INDEX idx_artifacts_assessment ON artifacts(assessment_id)")


MIGRATIONS: dict[int, Callable[[sqlite3.Connection], None]] = {
    1: _migration_1,
    2: _migration_2,
}


def _backup_before_migration(connection: sqlite3.Connection, database_path: Path) -> Path:
    backup_path = database_path.with_suffix(
        database_path.suffix + f".pre-v{CURRENT_SCHEMA_VERSION}.backup"
    )
    if not backup_path.exists():
        with sqlite3.connect(backup_path) as destination:
            connection.backup(destination)
    return backup_path


def _current_version(connection: sqlite3.Connection) -> tuple[int, bool]:
    """Return schema version and whether an unversioned legacy schema was found."""
    if _table_exists(connection, "schema_migrations"):
        row = connection.execute("SELECT MAX(version) FROM schema_migrations").fetchone()
        return int(row[0] or 0), False
    known_tables = {
        row[0] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
        )
    }
    legacy = {"assessments", "services", "packets", "credential_results"}
    if known_tables:
        if not legacy.issubset(known_tables):
            raise DatabaseError("Database has an unknown unversioned schema.")
        return 1, True
    return 0, False


def _apply_migration(
    connection: sqlite3.Connection,
    version: int,
    migration: Callable[[sqlite3.Connection], None],
) -> None:
    try:
        connection.execute("BEGIN IMMEDIATE")
        migration(connection)
        connection.execute(
            "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
            (version, utc_timestamp()),
        )
        connection.commit()
    except Exception:
        connection.rollback()
        raise


def initialize_database(database_path: Path = DEFAULT_DATABASE_PATH) -> Path:
    """Back up and transactionally migrate a fresh or historical database."""
    database_path = Path(database_path)
    try:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(database_path) as connection:
            current_version, is_legacy = _current_version(connection)
            if current_version > CURRENT_SCHEMA_VERSION:
                raise NewerSchemaError(
                    f"Database schema version {current_version} is newer than supported "
                    f"version {CURRENT_SCHEMA_VERSION}."
                )
            if current_version < CURRENT_SCHEMA_VERSION and database_path.stat().st_size > 0:
                _backup_before_migration(connection, database_path)
            if is_legacy:
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    connection.execute(
                        "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
                    )
                    connection.execute(
                        "INSERT INTO schema_migrations (version, applied_at) VALUES (1, ?)",
                        (utc_timestamp(),),
                    )
                    connection.commit()
                except Exception:
                    connection.rollback()
                    raise
            for version in range(current_version + 1, CURRENT_SCHEMA_VERSION + 1):
                migration = MIGRATIONS.get(version)
                if migration is None:
                    raise DatabaseError(f"Missing database migration {version}.")
                _apply_migration(connection, version, migration)
    except NewerSchemaError:
        raise
    except (OSError, sqlite3.Error, DatabaseError) as exc:
        if isinstance(exc, DatabaseError):
            raise
        raise DatabaseError(f"Unable to initialize database {database_path}: {exc}") from exc
    except Exception as exc:
        raise DatabaseError(f"Database migration failed: {exc}") from exc
    return database_path


def create_assessment(
    target: str,
    started_at: str | None = None,
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Create a running assessment; target remains the legacy primary-target field."""
    initialize_database(database_path)
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                "INSERT INTO assessments (target, started_at, status) VALUES (?, ?, 'running')",
                (target, started_at or utc_timestamp()),
            )
            connection.commit()
            assessment_id = cursor.lastrowid
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to create assessment: {exc}") from exc
    if assessment_id is None:
        raise DatabaseError("SQLite did not return an assessment ID.")
    return assessment_id


def finish_assessment(
    assessment_id: int,
    finished_at: str | None = None,
    database_path: Path = DEFAULT_DATABASE_PATH,
    status: str = "completed",
) -> None:
    """Finalize an assessment with an explicit overall outcome."""
    if status not in EXECUTION_STATUSES or status == "running":
        raise DatabaseError(f"Invalid final assessment status: {status}")
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                "UPDATE assessments SET status=?, finished_at=? WHERE id=?",
                (status, finished_at or utc_timestamp(), assessment_id),
            )
            connection.commit()
            if cursor.rowcount != 1:
                raise DatabaseError(f"Assessment {assessment_id} does not exist.")
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to finish assessment: {exc}") from exc


def update_assessment_status(
    assessment_id: int, status: str, database_path: Path = DEFAULT_DATABASE_PATH
) -> None:
    """Update status without changing the established completion timestamp."""
    if status not in EXECUTION_STATUSES:
        raise DatabaseError(f"Invalid assessment status: {status}")
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                "UPDATE assessments SET status=? WHERE id=?", (status, assessment_id)
            )
            connection.commit()
            if cursor.rowcount != 1:
                raise DatabaseError(f"Assessment {assessment_id} does not exist.")
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to update assessment status: {exc}") from exc


def create_assessment_host(
    assessment_id: int,
    target: str,
    interface: str | None,
    database_path: Path = DEFAULT_DATABASE_PATH,
    started_at: str | None = None,
) -> int:
    """Create one explicitly supplied host within an assessment."""
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                """INSERT INTO assessment_hosts
                (assessment_id,target,interface,status,started_at)
                VALUES (?,?,?,'running',?)""",
                (assessment_id, target, interface, started_at or utc_timestamp()),
            )
            connection.commit()
            host_id = cursor.lastrowid
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to create assessment host: {exc}") from exc
    if host_id is None:
        raise DatabaseError("SQLite did not return a host ID.")
    return host_id


def finish_assessment_host(
    host_id: int,
    status: str,
    error_summary: object | None = None,
    database_path: Path = DEFAULT_DATABASE_PATH,
    finished_at: str | None = None,
) -> None:
    """Finalize a host independently from report or artifact outcomes."""
    if status not in EXECUTION_STATUSES or status == "running":
        raise DatabaseError(f"Invalid final host status: {status}")
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                """UPDATE assessment_hosts SET status=?,finished_at=?,error_summary=?
                WHERE id=?""",
                (status, finished_at or utc_timestamp(), sanitize_error_summary(error_summary), host_id),
            )
            connection.commit()
            if cursor.rowcount != 1:
                raise DatabaseError(f"Assessment host {host_id} does not exist.")
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to finish assessment host: {exc}") from exc


def start_phase(
    assessment_id: int,
    phase_name: str,
    host_id: int | None = None,
    database_path: Path = DEFAULT_DATABASE_PATH,
    started_at: str | None = None,
) -> int:
    """Start an independently timed assessment or host phase."""
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                """INSERT INTO assessment_phases
                (assessment_id,host_id,phase_name,status,started_at)
                VALUES (?,?,?,'running',?)""",
                (assessment_id, host_id, phase_name, started_at or utc_timestamp()),
            )
            connection.commit()
            phase_id = cursor.lastrowid
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to start phase {phase_name}: {exc}") from exc
    if phase_id is None:
        raise DatabaseError("SQLite did not return a phase ID.")
    return phase_id


def finish_phase(
    phase_id: int,
    status: str,
    error_summary: object | None = None,
    database_path: Path = DEFAULT_DATABASE_PATH,
    finished_at: str | None = None,
) -> None:
    """Finish a phase with a precise timestamp and sanitized error."""
    if status not in PHASE_STATUSES or status == "running":
        raise DatabaseError(f"Invalid final phase status: {status}")
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                """UPDATE assessment_phases SET status=?,finished_at=?,error_summary=?
                WHERE id=?""",
                (status, finished_at or utc_timestamp(), sanitize_error_summary(error_summary), phase_id),
            )
            connection.commit()
            if cursor.rowcount != 1:
                raise DatabaseError(f"Assessment phase {phase_id} does not exist.")
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to finish phase: {exc}") from exc


def insert_services(
    assessment_id: int,
    services: Iterable[Mapping[str, Any]],
    database_path: Path = DEFAULT_DATABASE_PATH,
    host_id: int | None = None,
) -> int:
    """Insert services, optionally linked to a host in the same assessment."""
    rows = [(
        assessment_id, host_id, service["port"], service["protocol"],
        service["state"], service["service"], service.get("version", "")
    ) for service in services]
    if not rows:
        return 0
    try:
        with _connection(Path(database_path)) as connection:
            connection.executemany("""INSERT INTO services
                (assessment_id,host_id,port,protocol,state,service,version)
                VALUES (?,?,?,?,?,?,?)""", rows)
            connection.commit()
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to store services: {exc}") from exc
    return len(rows)


def insert_packets(
    assessment_id: int,
    packets: Iterable[Mapping[str, Any]],
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Batch-insert packets; correlation remains timestamp/address based."""
    rows = [(
        assessment_id, packet.get("timestamp"), packet.get("src_ip"),
        packet.get("dst_ip"), packet.get("protocol", "UNKNOWN"),
        packet.get("src_port"), packet.get("dst_port"), packet.get("length")
    ) for packet in packets]
    if not rows:
        return 0
    try:
        with _connection(Path(database_path)) as connection:
            connection.executemany("""INSERT INTO packets
                (assessment_id,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length)
                VALUES (?,?,?,?,?,?,?,?)""", rows)
            connection.commit()
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to store packets: {exc}") from exc
    return len(rows)


def _credential_outcome(result: Mapping[str, Any]) -> str:
    outcome = result.get("outcome")
    if outcome is None and "credential_found" in result:
        outcome = "matched" if bool(result["credential_found"]) else "no_match"
    if outcome not in CREDENTIAL_OUTCOMES:
        raise DatabaseError(f"Invalid credential outcome: {outcome}")
    return str(outcome)


def insert_credential_result(
    assessment_id: int,
    result: Mapping[str, Any],
    database_path: Path = DEFAULT_DATABASE_PATH,
    host_id: int | None = None,
) -> int:
    """Store an explicit credential outcome without a plaintext password."""
    outcome = _credential_outcome(result)
    credential_found = 1 if outcome == "matched" else 0 if outcome == "no_match" else None
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute("""INSERT INTO credential_results
                (assessment_id,host_id,service,port,username,outcome,credential_found)
                VALUES (?,?,?,?,?,?,?)""", (
                    assessment_id, host_id, result.get("service", "ssh"),
                    result.get("port"), result.get("username"), outcome, credential_found,
                ))
            connection.commit()
            result_id = cursor.lastrowid
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to store credential result: {exc}") from exc
    if result_id is None:
        raise DatabaseError("SQLite did not return a credential-result ID.")
    return result_id


def register_artifact(
    assessment_id: int,
    artifact_type: str,
    path: Path,
    status: str = "pending",
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Register an intended path before producing an artifact."""
    if status not in ARTIFACT_STATUSES:
        raise DatabaseError(f"Invalid artifact status: {status}")
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                "INSERT INTO artifacts (assessment_id,artifact_type,path,status) VALUES (?,?,?,?)",
                (assessment_id, artifact_type, str(path), status),
            )
            connection.commit()
            artifact_id = cursor.lastrowid
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to register artifact: {exc}") from exc
    if artifact_id is None:
        raise DatabaseError("SQLite did not return an artifact ID.")
    return artifact_id


def update_artifact_status(
    artifact_id: int,
    status: str,
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> None:
    """Update an artifact only after its producer outcome is known."""
    if status not in ARTIFACT_STATUSES:
        raise DatabaseError(f"Invalid artifact status: {status}")
    try:
        with _connection(Path(database_path)) as connection:
            row = connection.execute(
                "SELECT path FROM artifacts WHERE id=?", (artifact_id,)
            ).fetchone()
            if row is None:
                raise DatabaseError(f"Artifact {artifact_id} does not exist.")
            if status == "available" and not Path(row[0]).is_file():
                raise DatabaseError(
                    f"Artifact cannot be marked available before it exists: {row[0]}"
                )
            cursor = connection.execute(
                "UPDATE artifacts SET status=? WHERE id=?", (status, artifact_id)
            )
            connection.commit()
            if cursor.rowcount != 1:
                raise DatabaseError(f"Artifact {artifact_id} does not exist.")
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to update artifact: {exc}") from exc
