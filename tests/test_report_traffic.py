"""Traffic-correlation and coverage tests for the consolidated report."""

import re
import sqlite3
import tempfile
import unittest
from pathlib import Path

from modules.database import (
    create_assessment,
    create_assessment_host,
    finish_assessment,
    finish_assessment_host,
    finish_phase,
    insert_credential_result,
    insert_packets,
    insert_services,
    register_artifact,
    start_phase,
    update_artifact_status,
)
from modules.report import _host_traffic, generate_report
from modules.security_analysis import analyze_assessment


class ReportTrafficTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        root = Path(self.temporary_directory.name)
        self.database = root / "data" / "autopen.db"
        self.report = root / "reports" / "assessments" / "1" / "report.html"

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _packets(self, assessment_id: int) -> list[sqlite3.Row]:
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                "SELECT * FROM packets WHERE assessment_id=? ORDER BY id", (assessment_id,)
            ).fetchall()

    def test_host_packet_matching_normalizes_ipv6_and_allows_overlap(self) -> None:
        assessment_id = create_assessment("192.168.56.20", database_path=self.database)
        create_assessment_host(assessment_id, "192.168.56.20", "lab0", self.database)
        create_assessment_host(assessment_id, "2001:db8::1", "lab0", self.database)
        insert_packets(assessment_id, [
            {"src_ip": "192.168.56.20", "dst_ip": "2001:0db8:0:0:0:0:0:1", "protocol": "TCP", "length": 100},
            {"src_ip": "192.168.56.10", "dst_ip": "192.168.56.20", "protocol": "UDP", "length": 50},
            {"src_ip": "2001:db8::1", "dst_ip": "2001:db8::2", "protocol": "TCP", "length": 70},
            {"src_ip": None, "dst_ip": "not-an-ip", "protocol": "ARP", "length": 30},
        ], self.database)
        packets = self._packets(assessment_id)

        first = _host_traffic("192.168.56.20", packets)
        second = _host_traffic("2001:db8::1", packets)

        self.assertEqual((first["packets"], first["bytes"], first["sent"], first["received"]), (2, 150, 1, 1))
        self.assertEqual((second["packets"], second["bytes"], second["sent"], second["received"]), (2, 170, 1, 1))
        self.assertEqual(len(packets), 4)

    def _matched_ssh_assessment(self, missing_timestamp: bool = False) -> tuple[int, int]:
        assessment_id = create_assessment("192.168.56.20", database_path=self.database)
        host_id = create_assessment_host(assessment_id, "192.168.56.20", "lab0", self.database)
        insert_services(assessment_id, [{
            "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH",
        }], self.database, host_id)
        insert_credential_result(assessment_id, {
            "service": "ssh", "port": 22, "username": "lab", "outcome": "matched",
        }, self.database, host_id)
        credential_phase = start_phase(
            assessment_id, "credential_testing", host_id, self.database,
            "2026-10-03T10:00:01+00:00",
        )
        finish_phase(
            credential_phase, "completed", database_path=self.database,
            finished_at="2026-10-03T10:00:03+00:00",
        )
        if missing_timestamp:
            packet_rows = [{
                "timestamp": None, "src_ip": "192.168.56.10", "dst_ip": "192.168.56.20",
                "protocol": "TCP", "src_port": 40000, "dst_port": 22, "length": 60,
            }]
        else:
            packet_rows = [
                {"timestamp": "2026-10-03T10:00:00+00:00", "src_ip": "192.168.56.10", "dst_ip": "192.168.56.20", "protocol": "TCP", "src_port": 40000, "dst_port": 22, "length": 60},
                {"timestamp": "2026-10-03T10:00:01+00:00", "src_ip": "192.168.56.10", "dst_ip": "192.168.56.20", "protocol": "TCP", "src_port": 40001, "dst_port": 22, "length": 60},
                {"timestamp": "2026-10-03T10:00:03+00:00", "src_ip": "192.168.56.20", "dst_ip": "192.168.56.10", "protocol": "TCP", "src_port": 22, "dst_port": 40001, "length": 60},
                {"timestamp": "2026-10-03T10:00:04+00:00", "src_ip": "192.168.56.20", "dst_ip": "192.168.56.10", "protocol": "TCP", "src_port": 22, "dst_port": 40002, "length": 60},
                {"timestamp": "2026-10-03T10:00:02+00:00", "src_ip": "192.168.56.10", "dst_ip": "192.168.56.20", "protocol": "TCP", "src_port": 22, "dst_port": 8080, "length": 999},
            ]
        insert_packets(assessment_id, packet_rows, self.database)
        analysis = start_phase(assessment_id, "security_analysis", database_path=self.database)
        analyze_assessment(self.database, assessment_id)
        finish_phase(analysis, "completed", database_path=self.database)
        finish_assessment_host(host_id, "completed", database_path=self.database)
        finish_assessment(assessment_id, database_path=self.database)
        return assessment_id, host_id

    def test_service_traffic_uses_target_side_port_and_phase_boundaries(self) -> None:
        assessment_id, _ = self._matched_ssh_assessment()
        generate_report(self.database, assessment_id, self.report)
        document = self.report.read_text(encoding="utf-8")

        self.assertIn("Traffic observed during the credential-test phase: 2 packets / 120 bytes.", document)
        self.assertNotIn("1,119 bytes", document)
        self.assertIn("credential tool result establishes the accepted login", document)
        self.assertIn("packet metadata only corroborates traffic", document)
        self.assertNotIn("packet metadata proves", document.lower())

    def test_missing_packet_timestamp_uses_assessment_wide_fallback(self) -> None:
        assessment_id, _ = self._matched_ssh_assessment(missing_timestamp=True)
        generate_report(self.database, assessment_id, self.report)
        document = self.report.read_text(encoding="utf-8")

        self.assertIn("Assessment-wide service traffic: 1 packets / 60 bytes.", document)
        self.assertIn("timestamps were unavailable or unsuitable", document)

    def test_incomplete_analysis_is_distinct_from_completed_no_findings(self) -> None:
        failed_id = create_assessment("192.168.56.20", database_path=self.database)
        failed_host = create_assessment_host(failed_id, "192.168.56.20", "lab0", self.database)
        failed_phase = start_phase(failed_id, "security_analysis", database_path=self.database)
        finish_phase(failed_phase, "failed", "analysis error", self.database)
        finish_assessment_host(failed_host, "partial", database_path=self.database)
        finish_assessment(failed_id, database_path=self.database, status="partial")
        failed_report = self.report.with_name("failed.html")
        generate_report(self.database, failed_id, failed_report)
        failed_document = failed_report.read_text(encoding="utf-8")

        complete_id = create_assessment("192.168.56.21", database_path=self.database)
        complete_host = create_assessment_host(complete_id, "192.168.56.21", "lab0", self.database)
        complete_phase = start_phase(complete_id, "security_analysis", database_path=self.database)
        finish_phase(complete_phase, "completed", database_path=self.database)
        finish_assessment_host(complete_host, "completed", database_path=self.database)
        finish_assessment(complete_id, database_path=self.database)
        complete_report = self.report.with_name("complete.html")
        generate_report(self.database, complete_id, complete_report)
        complete_document = complete_report.read_text(encoding="utf-8")

        self.assertIn("Analysis unavailable or incomplete", failed_document)
        self.assertIn("No non-informational findings generated", complete_document)
        self.assertIn("Assessment status</span><span class=\"value\">completed", complete_document)

    def test_artifact_links_are_relative_and_escaped(self) -> None:
        assessment_id = create_assessment("192.168.56.20", database_path=self.database)
        host_id = create_assessment_host(assessment_id, "192.168.56.20", "lab0", self.database)
        finish_assessment_host(host_id, "completed", database_path=self.database)
        finish_assessment(assessment_id, database_path=self.database)
        pcap = Path(self.temporary_directory.name) / "data" / "captures & evidence" / "capture.pcap"
        pcap.parent.mkdir(parents=True)
        pcap.write_bytes(b"pcap")
        artifact_id = register_artifact(assessment_id, "pcap", pcap, database_path=self.database)
        update_artifact_status(artifact_id, "available", self.database)

        generate_report(self.database, assessment_id, self.report)
        document = self.report.read_text(encoding="utf-8")
        hrefs = re.findall(r'href="([^"]+)"', document)

        self.assertTrue(hrefs)
        self.assertTrue(all(not href.startswith(("/", "file:")) for href in hrefs))
        self.assertIn("captures &amp; evidence", document)


if __name__ == "__main__":
    unittest.main()
