"""Tests for standalone SQLite-backed HTML report generation."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from modules.database import (
    create_assessment,
    finish_assessment,
    insert_credential_result,
    insert_packets,
    insert_services,
)
from modules.report import ReportError, generate_report


class ReportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.database_path = root / "data" / "autopen.db"
        self.report_path = root / "reports" / "report.html"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _create_complete_assessment(self) -> int:
        create_assessment(
            "old-target", "2026-10-03T08:00:00+00:00", self.database_path
        )
        assessment_id = create_assessment(
            "127.0.0.1 & <lab>",
            "2026-10-03T09:00:00+00:00",
            self.database_path,
        )
        insert_services(
            assessment_id,
            [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh<script>",
                    "version": "OpenSSH & Ubuntu",
                },
                {
                    "port": 631,
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ipp",
                    "version": "CUPS 2.4",
                },
            ],
            self.database_path,
        )
        insert_credential_result(
            assessment_id,
            {
                "service": "ssh",
                "port": 22,
                "username": "<autopen-test>",
                "credential_found": True,
            },
            self.database_path,
        )
        insert_packets(
            assessment_id,
            [
                {
                    "timestamp": "2026-10-03T09:00:01+00:00",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                    "protocol": "TCP",
                    "src_port": 40000,
                    "dst_port": 22,
                    "length": 74,
                },
                {
                    "timestamp": "2026-10-03T09:00:02+00:00",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                    "protocol": "TCP",
                    "src_port": 22,
                    "dst_port": 40000,
                    "length": 74,
                },
                {
                    "timestamp": "2026-10-03T09:00:03+00:00",
                    "src_ip": "127.0.0.1",
                    "dst_ip": "127.0.0.1",
                    "protocol": "UDP",
                    "src_port": 50000,
                    "dst_port": 53,
                    "length": 60,
                },
            ],
            self.database_path,
        )
        finish_assessment(
            assessment_id, "2026-10-03T09:00:04+00:00", self.database_path
        )
        return assessment_id

    def test_complete_report_uses_selected_assessment_and_escapes_html(self) -> None:
        assessment_id = self._create_complete_assessment()

        result = generate_report(
            self.database_path, assessment_id, self.report_path
        )
        document = self.report_path.read_text(encoding="utf-8")

        self.assertEqual(result, self.report_path)
        self.assertTrue(self.report_path.is_file())
        self.assertIn("AutoPen Assessment Report", document)
        self.assertIn("127.0.0.1 &amp; &lt;lab&gt;", document)
        self.assertNotIn("old-target", document)
        self.assertIn("ssh&lt;script&gt;", document)
        self.assertNotIn("<script>", document)
        self.assertIn("OpenSSH &amp; Ubuntu", document)
        self.assertIn("&lt;autopen-test&gt;", document)
        self.assertIn("Credential matched", document)
        self.assertIn("<td>TCP</td><td>2</td>", document)
        self.assertIn("<td>UDP</td><td>1</td>", document)
        self.assertIn("Total packets", document)
        self.assertIn(">3</span>", document)
        self.assertIn("Top Connections", document)

    def test_empty_credentials_and_packets_are_handled(self) -> None:
        assessment_id = create_assessment(
            "127.0.0.1", "2026-10-03T10:00:00+00:00", self.database_path
        )
        finish_assessment(
            assessment_id, "2026-10-03T10:00:01+00:00", self.database_path
        )

        generate_report(self.database_path, assessment_id, self.report_path)
        document = self.report_path.read_text(encoding="utf-8")

        self.assertIn("No credential testing results were recorded.", document)
        self.assertIn("No packet metadata was recorded", document)
        self.assertIn("No connections were available", document)
        self.assertIn("0 packets were captured", document)

    def test_nonexistent_assessment_fails_cleanly(self) -> None:
        create_assessment("127.0.0.1", database_path=self.database_path)

        with self.assertRaisesRegex(ReportError, "does not exist"):
            generate_report(self.database_path, 999, self.report_path)

    def test_report_generation_does_not_modify_history(self) -> None:
        assessment_id = self._create_complete_assessment()
        with sqlite3.connect(self.database_path) as connection:
            before = connection.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]

        generate_report(self.database_path, assessment_id, self.report_path)

        with sqlite3.connect(self.database_path) as connection:
            after = connection.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
        self.assertEqual(before, 2)
        self.assertEqual(after, before)


if __name__ == "__main__":
    unittest.main()
