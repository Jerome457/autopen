"""SQLite persistence for AutoPen assessments and forensic metadata."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterable, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DEFAULT_DATABASE_PATH = Path("data/autopen.db")


class DatabaseError(RuntimeError):
    """Raised when AutoPen cannot persist assessment data."""


SCHEMA = """
CREATE TABLE IF NOT EXISTS assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);

CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    timestamp TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    length INTEGER,
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS credential_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    credential_found INTEGER NOT NULL CHECK (credential_found IN (0, 1)),
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_services_assessment
    ON services(assessment_id);
CREATE INDEX IF NOT EXISTS idx_packets_assessment
    ON packets(assessment_id);
CREATE INDEX IF NOT EXISTS idx_packets_ports
    ON packets(assessment_id, src_port, dst_port);
CREATE INDEX IF NOT EXISTS idx_credential_results_assessment
    ON credential_results(assessment_id);
"""


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def _connection(database_path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database_path)
    try:
        connection.execute("PRAGMA foreign_keys = ON")
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database(database_path: Path = DEFAULT_DATABASE_PATH) -> Path:
    """Create the database directory and schema without removing existing data."""
    database_path = Path(database_path)
    try:
        database_path.parent.mkdir(parents=True, exist_ok=True)
        with _connection(database_path) as connection:
            connection.executescript(SCHEMA)
    except (OSError, sqlite3.Error) as exc:
        raise DatabaseError(f"Unable to initialize database {database_path}: {exc}") from exc
    return database_path


def create_assessment(
    target: str,
    started_at: str | None = None,
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Create an assessment and return its generated ID."""
    initialize_database(database_path)
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                "INSERT INTO assessments (target, started_at) VALUES (?, ?)",
                (target, started_at or _timestamp()),
            )
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
) -> None:
    """Record successful completion time for an assessment."""
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                "UPDATE assessments SET finished_at = ? WHERE id = ?",
                (finished_at or _timestamp(), assessment_id),
            )
            if cursor.rowcount != 1:
                raise DatabaseError(f"Assessment {assessment_id} does not exist.")
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to finish assessment: {exc}") from exc


def insert_services(
    assessment_id: int,
    services: Iterable[Mapping[str, Any]],
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Insert discovered services in one transaction."""
    rows = [
        (
            assessment_id,
            service["port"],
            service["protocol"],
            service["state"],
            service["service"],
            service.get("version", ""),
        )
        for service in services
    ]
    if not rows:
        return 0

    try:
        with _connection(Path(database_path)) as connection:
            connection.executemany(
                """
                INSERT INTO services
                    (assessment_id, port, protocol, state, service, version)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to store services: {exc}") from exc
    return len(rows)


def insert_packets(
    assessment_id: int,
    packets: Iterable[Mapping[str, Any]],
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Batch-insert parsed packet metadata in one transaction."""
    rows = [
        (
            assessment_id,
            packet.get("timestamp"),
            packet.get("src_ip"),
            packet.get("dst_ip"),
            packet.get("protocol", "UNKNOWN"),
            packet.get("src_port"),
            packet.get("dst_port"),
            packet.get("length"),
        )
        for packet in packets
    ]
    if not rows:
        return 0

    try:
        with _connection(Path(database_path)) as connection:
            connection.executemany(
                """
                INSERT INTO packets
                    (assessment_id, timestamp, src_ip, dst_ip, protocol,
                     src_port, dst_port, length)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                rows,
            )
    except sqlite3.Error as exc:
        raise DatabaseError(f"Unable to store packets: {exc}") from exc
    return len(rows)


def insert_credential_result(
    assessment_id: int,
    result: Mapping[str, Any],
    database_path: Path = DEFAULT_DATABASE_PATH,
) -> int:
    """Store a credential-test outcome without retaining a plaintext password."""
    try:
        with _connection(Path(database_path)) as connection:
            cursor = connection.execute(
                """
                INSERT INTO credential_results
                    (assessment_id, service, port, username, credential_found)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    assessment_id,
                    result["service"],
                    result["port"],
                    result["username"],
                    int(bool(result["credential_found"])),
                ),
            )
            result_id = cursor.lastrowid
    except (KeyError, sqlite3.Error) as exc:
        raise DatabaseError(f"Unable to store credential result: {exc}") from exc

    if result_id is None:
        raise DatabaseError("SQLite did not return a credential-result ID.")
    return result_id
