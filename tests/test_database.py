"""Tests for the SQLite forensic store."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from modules.database import (
    DatabaseError,
    create_assessment,
    finish_assessment,
    initialize_database,
    insert_credential_result,
    insert_packets,
    insert_services,
)


class DatabaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.database_path = Path(self.temporary_directory.name) / "nested" / "autopen.db"
        initialize_database(self.database_path)

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_initialization_creates_all_tables(self) -> None:
        with sqlite3.connect(self.database_path) as connection:
            tables = {
                row[0]
                for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type = 'table'"
                )
            }
        self.assertTrue(
            {"assessments", "services", "packets", "credential_results"}.issubset(
                tables
            )
        )

    def test_assessment_services_and_packets_are_stored(self) -> None:
        assessment_id = create_assessment(
            "127.0.0.1", "2026-10-03T10:00:00+00:00", self.database_path
        )
        service_count = insert_services(
            assessment_id,
            [{
                "port": 22,
                "protocol": "tcp",
                "state": "open",
                "service": "ssh",
                "version": "OpenSSH",
            }],
            self.database_path,
        )
        packet_count = insert_packets(
            assessment_id,
            [{
                "timestamp": "2026-10-03T10:00:01+00:00",
                "src_ip": "127.0.0.1",
                "dst_ip": "127.0.0.1",
                "protocol": "TCP",
                "src_port": 40000,
                "dst_port": 22,
                "length": 74,
            }],
            self.database_path,
        )
        finish_assessment(
            assessment_id, "2026-10-03T10:00:02+00:00", self.database_path
        )

        with sqlite3.connect(self.database_path) as connection:
            assessment = connection.execute(
                "SELECT target, finished_at FROM assessments WHERE id = ?",
                (assessment_id,),
            ).fetchone()
            service = connection.execute(
                "SELECT port, service FROM services WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()
            packet = connection.execute(
                "SELECT protocol, dst_port FROM packets WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()

        self.assertEqual(service_count, 1)
        self.assertEqual(packet_count, 1)
        self.assertEqual(assessment, ("127.0.0.1", "2026-10-03T10:00:02+00:00"))
        self.assertEqual(service, (22, "ssh"))
        self.assertEqual(packet, ("TCP", 22))

    def test_multiple_assessments_coexist(self) -> None:
        first_id = create_assessment("127.0.0.1", database_path=self.database_path)
        second_id = create_assessment("::1", database_path=self.database_path)

        with sqlite3.connect(self.database_path) as connection:
            count = connection.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]

        self.assertNotEqual(first_id, second_id)
        self.assertEqual(count, 2)

    def test_foreign_keys_reject_unknown_assessment(self) -> None:
        with self.assertRaisesRegex(DatabaseError, "FOREIGN KEY"):
            insert_packets(
                999,
                [{"protocol": "ARP", "src_ip": None, "dst_ip": None}],
                self.database_path,
            )

    def test_credential_result_is_stored_without_plaintext_password(self) -> None:
        assessment_id = create_assessment("127.0.0.1", database_path=self.database_path)
        result_id = insert_credential_result(
            assessment_id,
            {
                "service": "ssh",
                "port": 2222,
                "username": "autopen-test",
                "credential_found": True,
                "matched_password": "not-persisted",
            },
            self.database_path,
        )

        with sqlite3.connect(self.database_path) as connection:
            columns = {
                row[1]
                for row in connection.execute("PRAGMA table_info(credential_results)")
            }
            stored = connection.execute(
                """
                SELECT service, port, username, credential_found
                FROM credential_results WHERE id = ?
                """,
                (result_id,),
            ).fetchone()

        self.assertNotIn("matched_password", columns)
        self.assertEqual(stored, ("ssh", 2222, "autopen-test", 1))

    def test_schema_migration_preserves_existing_assessments(self) -> None:
        legacy_path = Path(self.temporary_directory.name) / "legacy.db"
        with sqlite3.connect(legacy_path) as connection:
            connection.execute(
                """
                CREATE TABLE assessments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    finished_at TEXT
                )
                """
            )
            connection.execute(
                "INSERT INTO assessments (target, started_at) VALUES (?, ?)",
                ("127.0.0.1", "2026-10-03T10:00:00+00:00"),
            )

        initialize_database(legacy_path)

        with sqlite3.connect(legacy_path) as connection:
            target = connection.execute(
                "SELECT target FROM assessments WHERE id = 1"
            ).fetchone()[0]
            credential_table = connection.execute(
                """
                SELECT name FROM sqlite_master
                WHERE type = 'table' AND name = 'credential_results'
                """
            ).fetchone()

        self.assertEqual(target, "127.0.0.1")
        self.assertEqual(credential_table, ("credential_results",))


if __name__ == "__main__":
    unittest.main()
