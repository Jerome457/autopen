"""Tests for versioned migrations and host-aware SQLite persistence."""

import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import modules.database as database
from modules.database import (
    CURRENT_SCHEMA_VERSION,
    DatabaseError,
    NewerSchemaError,
    create_assessment,
    create_assessment_host,
    finish_assessment,
    finish_assessment_host,
    initialize_database,
    insert_credential_result,
    insert_findings,
    insert_packets,
    insert_services,
    register_artifact,
    sanitize_error_summary,
    update_artifact_status,
)


LEGACY_SCHEMA = """
CREATE TABLE assessments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT
);
CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    port INTEGER NOT NULL,
    protocol TEXT NOT NULL,
    state TEXT NOT NULL,
    service TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);
CREATE TABLE packets (
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
CREATE TABLE credential_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    assessment_id INTEGER NOT NULL,
    service TEXT NOT NULL,
    port INTEGER NOT NULL,
    username TEXT NOT NULL,
    credential_found INTEGER NOT NULL CHECK (credential_found IN (0, 1)),
    FOREIGN KEY (assessment_id) REFERENCES assessments(id) ON DELETE CASCADE
);
CREATE INDEX idx_services_assessment ON services(assessment_id);
CREATE INDEX idx_packets_assessment ON packets(assessment_id);
CREATE INDEX idx_packets_ports ON packets(assessment_id, src_port, dst_port);
CREATE INDEX idx_credential_results_assessment ON credential_results(assessment_id);
"""


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "nested" / "autopen.db"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _create_populated_legacy_database(self, path: Path | None = None) -> Path:
        path = path or self.database_path
        path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(path) as connection:
            connection.executescript(LEGACY_SCHEMA)
            connection.execute(
                """INSERT INTO assessments (id,target,started_at,finished_at)
                VALUES (7,'127.0.0.1','2026-10-03T10:00:00+00:00',
                        '2026-10-03T10:00:04+00:00')"""
            )
            connection.execute(
                """INSERT INTO services
                (id,assessment_id,port,protocol,state,service,version)
                VALUES (11,7,22,'tcp','open','ssh','OpenSSH')"""
            )
            connection.execute(
                """INSERT INTO credential_results
                (id,assessment_id,service,port,username,credential_found)
                VALUES (13,7,'ssh',22,'autopen-test',1)"""
            )
            connection.execute(
                """INSERT INTO packets
                (id,assessment_id,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length)
                VALUES (17,7,'2026-10-03T10:00:01','127.0.0.1','127.0.0.1',
                        'TCP',40000,22,74)"""
            )
        return path

    def test_fresh_initialization_and_repeated_initialization(self) -> None:
        initialize_database(self.database_path)
        initialize_database(self.database_path)

        with sqlite3.connect(self.database_path) as connection:
            versions = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }

        self.assertEqual(versions, [(1,), (2,), (3,)])
        self.assertTrue(
            {"assessment_hosts", "assessment_phases", "artifacts", "findings"}.issubset(tables)
        )

    def test_populated_legacy_migration_preserves_and_backfills(self) -> None:
        self._create_populated_legacy_database()

        initialize_database(self.database_path)

        backup = self.database_path.with_suffix(".db.pre-v3.backup")
        with sqlite3.connect(self.database_path) as connection:
            assessment = connection.execute(
                "SELECT id,target,status FROM assessments WHERE id=7"
            ).fetchone()
            host = connection.execute(
                """SELECT id,assessment_id,target,status FROM assessment_hosts
                WHERE assessment_id=7"""
            ).fetchone()
            service = connection.execute(
                "SELECT id,assessment_id,host_id FROM services WHERE id=11"
            ).fetchone()
            credential = connection.execute(
                """SELECT id,host_id,outcome,credential_found
                FROM credential_results WHERE id=13"""
            ).fetchone()
            packet = connection.execute(
                "SELECT id,assessment_id FROM packets WHERE id=17"
            ).fetchone()
            finding_count = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

        self.assertTrue(backup.is_file())
        self.assertEqual(assessment, (7, "127.0.0.1", "legacy_unknown"))
        self.assertEqual(host[1:], (7, "127.0.0.1", "legacy_unknown"))
        self.assertEqual(service, (11, 7, host[0]))
        self.assertEqual(credential, (13, host[0], "matched", 1))
        self.assertEqual(packet, (17, 7))
        self.assertEqual(finding_count, 0)

    def test_repeated_legacy_initialization_does_not_duplicate_backfill(self) -> None:
        self._create_populated_legacy_database()
        initialize_database(self.database_path)
        initialize_database(self.database_path)

        with sqlite3.connect(self.database_path) as connection:
            hosts = connection.execute(
                "SELECT COUNT(*) FROM assessment_hosts WHERE assessment_id=7"
            ).fetchone()[0]
        self.assertEqual(hosts, 1)

    def test_version_two_migration_preserves_records_without_fabricating_findings(self) -> None:
        assessment_id = create_assessment("127.0.0.1", database_path=self.database_path)
        host_id = create_assessment_host(
            assessment_id, "127.0.0.1", "lo", self.database_path
        )
        insert_services(
            assessment_id,
            [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}],
            self.database_path,
            host_id,
        )
        with sqlite3.connect(self.database_path) as connection:
            service_before = connection.execute(
                "SELECT id,assessment_id,host_id,port,service FROM services"
            ).fetchall()
            connection.execute("DROP TABLE findings")
            connection.execute("DROP INDEX idx_services_identity_assessment")
            connection.execute("DELETE FROM schema_migrations WHERE version=3")

        initialize_database(self.database_path)

        with sqlite3.connect(self.database_path) as connection:
            service_after = connection.execute(
                "SELECT id,assessment_id,host_id,port,service FROM services"
            ).fetchall()
            findings = connection.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
            versions = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        self.assertEqual(service_after, service_before)
        self.assertEqual(findings, 0)
        self.assertEqual(versions, [(1,), (2,), (3,)])
        self.assertTrue(self.database_path.with_suffix(".db.pre-v3.backup").is_file())

    def test_migration_failure_rolls_back_failed_version(self) -> None:
        self._create_populated_legacy_database()

        def failing_migration(connection: sqlite3.Connection) -> None:
            connection.execute("ALTER TABLE assessments ADD COLUMN rollback_probe TEXT")
            raise RuntimeError("injected migration failure")

        with patch.dict(database.MIGRATIONS, {2: failing_migration}):
            with self.assertRaisesRegex(DatabaseError, "migration failed"):
                initialize_database(self.database_path)

        with sqlite3.connect(self.database_path) as connection:
            columns = {
                row[1] for row in connection.execute("PRAGMA table_info(assessments)")
            }
            versions = connection.execute(
                "SELECT version FROM schema_migrations ORDER BY version"
            ).fetchall()
        self.assertNotIn("rollback_probe", columns)
        self.assertEqual(versions, [(1,)])

    def test_newer_schema_is_rejected(self) -> None:
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(self.database_path) as connection:
            connection.execute(
                "CREATE TABLE schema_migrations (version INTEGER PRIMARY KEY, applied_at TEXT)"
            )
            connection.execute(
                "INSERT INTO schema_migrations VALUES (?, 'future')",
                (CURRENT_SCHEMA_VERSION + 1,),
            )

        with self.assertRaises(NewerSchemaError):
            initialize_database(self.database_path)

    def test_assessment_services_packets_and_outcomes_are_stored(self) -> None:
        assessment_id = create_assessment(
            "127.0.0.1", "2026-10-03T10:00:00+00:00", self.database_path
        )
        host_id = create_assessment_host(
            assessment_id, "127.0.0.1", "lo", self.database_path
        )
        insert_services(
            assessment_id,
            [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}],
            self.database_path,
            host_id,
        )
        insert_credential_result(
            assessment_id,
            {"service": "ssh", "port": 22, "username": "lab", "outcome": "skipped"},
            self.database_path,
            host_id,
        )
        insert_packets(assessment_id, [{"protocol": "TCP"}], self.database_path)
        finish_assessment_host(host_id, "completed", database_path=self.database_path)
        finish_assessment(assessment_id, database_path=self.database_path)

        with sqlite3.connect(self.database_path) as connection:
            outcome = connection.execute(
                "SELECT outcome,credential_found FROM credential_results"
            ).fetchone()
            status = connection.execute("SELECT status FROM assessments").fetchone()[0]
        self.assertEqual(outcome, ("skipped", None))
        self.assertEqual(status, "completed")

    def test_cross_assessment_host_associations_are_rejected(self) -> None:
        first = create_assessment("127.0.0.1", database_path=self.database_path)
        second = create_assessment("127.0.0.2", database_path=self.database_path)
        first_host = create_assessment_host(first, "127.0.0.1", "lo", self.database_path)
        second_host = create_assessment_host(second, "127.0.0.2", "lo", self.database_path)

        with self.assertRaisesRegex(DatabaseError, "FOREIGN KEY"):
            insert_services(
                first,
                [{"port": 22, "protocol": "tcp", "state": "open", "service": "ssh"}],
                self.database_path,
                second_host,
            )
        with self.assertRaisesRegex(DatabaseError, "FOREIGN KEY"):
            insert_credential_result(
                first,
                {"service": "ssh", "outcome": "failed"},
                self.database_path,
                second_host,
            )
        insert_services(
            second,
            [{"port": 80, "protocol": "tcp", "state": "open", "service": "http"}],
            self.database_path,
            second_host,
        )
        with sqlite3.connect(self.database_path) as connection:
            second_service = connection.execute(
                "SELECT id FROM services WHERE assessment_id=?", (second,)
            ).fetchone()[0]
        with self.assertRaisesRegex(DatabaseError, "FOREIGN KEY"):
            insert_findings(
                first,
                [{
                    "host_id": first_host,
                    "service_id": second_service,
                    "rule_id": "TEST.CROSS_ASSESSMENT",
                    "dedupe_key": "test",
                    "title": "test",
                    "severity": "low",
                    "confidence": "low",
                    "evidence_state": "potential_issue",
                    "description": "test",
                    "evidence": {},
                    "impact": "test",
                    "remediation": "test",
                }],
                self.database_path,
            )

    def test_nonmatch_is_reserved_for_evidenced_no_match(self) -> None:
        assessment_id = create_assessment("127.0.0.1", database_path=self.database_path)
        host_id = create_assessment_host(
            assessment_id, "127.0.0.1", "lo", self.database_path
        )
        for outcome in ("skipped", "failed", "timed_out", "no_match"):
            insert_credential_result(
                assessment_id,
                {"service": "ssh", "outcome": outcome},
                self.database_path,
                host_id,
            )

        with sqlite3.connect(self.database_path) as connection:
            rows = connection.execute(
                "SELECT outcome,credential_found FROM credential_results ORDER BY id"
            ).fetchall()
        self.assertEqual(
            rows,
            [("skipped", None), ("failed", None), ("timed_out", None), ("no_match", 0)],
        )

    def test_error_summaries_are_sanitized(self) -> None:
        summary = sanitize_error_summary("password: SuperSecret\nconnection failed")
        self.assertNotIn("SuperSecret", summary)
        self.assertIn("[REDACTED]", summary)

        assessment_id = create_assessment("127.0.0.1", database_path=self.database_path)
        host_id = create_assessment_host(
            assessment_id, "127.0.0.1", "lo", self.database_path
        )
        finish_assessment_host(
            host_id,
            "failed",
            "password: SuperSecret connection failed",
            self.database_path,
        )
        with sqlite3.connect(self.database_path) as connection:
            persisted = connection.execute(
                "SELECT error_summary FROM assessment_hosts WHERE id=?", (host_id,)
            ).fetchone()[0]
        self.assertNotIn("SuperSecret", persisted)
        self.assertIn("[REDACTED]", persisted)

    def test_artifact_is_available_only_after_file_exists(self) -> None:
        assessment_id = create_assessment("127.0.0.1", database_path=self.database_path)
        artifact_path = Path(self.temporary_directory.name) / "artifacts" / "capture.pcap"
        artifact_id = register_artifact(
            assessment_id, "pcap", artifact_path, database_path=self.database_path
        )

        with self.assertRaisesRegex(DatabaseError, "before it exists"):
            update_artifact_status(
                artifact_id, "available", database_path=self.database_path
            )

        artifact_path.parent.mkdir()
        artifact_path.write_bytes(b"pcap")
        update_artifact_status(
            artifact_id, "available", database_path=self.database_path
        )
        with sqlite3.connect(self.database_path) as connection:
            status = connection.execute(
                "SELECT status FROM artifacts WHERE id=?", (artifact_id,)
            ).fetchone()[0]
        self.assertEqual(status, "available")


if __name__ == "__main__":
    unittest.main()
