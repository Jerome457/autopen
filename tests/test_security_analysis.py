"""Tests for deterministic, evidence-based stored-data analysis."""

import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from modules.database import (
    create_assessment,
    create_assessment_host,
    finish_assessment_host,
    insert_credential_result,
    insert_services,
)
from modules.report import generate_report
from modules.security_analysis import (
    CLEARTEXT_REMOTE_ACCESS,
    HTTP_TRANSPORT_REVIEW,
    SERVICE_EXPOSURE,
    SSH_CREDENTIAL_ACCEPTED,
    analyze_assessment,
)


class SecurityAnalysisTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        self.database = root / "data" / "autopen.db"
        self.report = root / "reports" / "report.html"

    def tearDown(self) -> None:
        self.temp.cleanup()

    def _assessment(self, *targets: str) -> tuple[int, list[int]]:
        assessment_id = create_assessment(targets[0], database_path=self.database)
        hosts = [
            create_assessment_host(assessment_id, target, "lab0", self.database)
            for target in targets
        ]
        return assessment_id, hosts

    def _services(self, assessment_id: int, host_id: int, services: list[dict]) -> None:
        insert_services(assessment_id, services, self.database, host_id)

    def _findings(self, assessment_id: int) -> list[sqlite3.Row]:
        with sqlite3.connect(self.database) as connection:
            connection.row_factory = sqlite3.Row
            return connection.execute(
                "SELECT * FROM findings WHERE assessment_id=? ORDER BY id",
                (assessment_id,),
            ).fetchall()

    def test_matched_ssh_result_produces_confirmed_high_finding(self) -> None:
        assessment_id, (host_id,) = self._assessment("192.168.56.20")
        self._services(assessment_id, host_id, [{
            "port": 22, "protocol": "tcp", "state": "open",
            "service": "ssh", "version": "OpenSSH",
        }])
        result_id = insert_credential_result(
            assessment_id,
            {"service": "ssh", "port": 22, "username": "lab-user", "outcome": "matched"},
            self.database,
            host_id,
        )

        self.assertEqual(analyze_assessment(self.database, assessment_id), 1)
        finding = self._findings(assessment_id)[0]
        evidence = json.loads(finding["evidence"])
        self.assertEqual(finding["rule_id"], SSH_CREDENTIAL_ACCEPTED)
        self.assertEqual(finding["title"], "SSH login succeeded using supplied test credentials")
        self.assertEqual((finding["severity"], finding["confidence"]), ("high", "high"))
        self.assertEqual(finding["evidence_state"], "confirmed_observation")
        self.assertEqual(evidence["credential_result_id"], result_id)
        self.assertEqual(evidence["username"], "lab-user")
        self.assertNotIn("password", finding["evidence"].lower())

    def test_nonmatch_and_execution_outcomes_do_not_create_success_findings(self) -> None:
        assessment_id, (host_id,) = self._assessment("192.168.56.20")
        self._services(assessment_id, host_id, [{
            "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "",
        }])
        for outcome in ("no_match", "skipped", "failed", "timed_out"):
            insert_credential_result(
                assessment_id,
                {"service": "ssh", "port": 22, "username": "lab", "outcome": outcome},
                self.database,
                host_id,
            )

        analyze_assessment(self.database, assessment_id)
        findings = self._findings(assessment_id)
        self.assertFalse(any(row["rule_id"] == SSH_CREDENTIAL_ACCEPTED for row in findings))
        self.assertEqual([row["rule_id"] for row in findings], [SERVICE_EXPOSURE])

    def test_protocol_rules_use_service_identity_and_exclude_tls_variants(self) -> None:
        assessment_id, (host_id,) = self._assessment("192.168.56.20")
        self._services(assessment_id, host_id, [
            {"port": 21, "protocol": "tcp", "state": "open", "service": "ssh", "version": ""},
            {"port": 2121, "protocol": "tcp", "state": "open", "service": "ftp", "version": ""},
            {"port": 2323, "protocol": "tcp", "state": "open", "service": "telnet", "version": ""},
            {"port": 990, "protocol": "tcp", "state": "open", "service": "ftps", "version": ""},
            {"port": 80, "protocol": "tcp", "state": "open", "service": "https", "version": ""},
            {"port": 8080, "protocol": "tcp", "state": "open", "service": "http", "version": ""},
        ])

        analyze_assessment(self.database, assessment_id)
        findings = self._findings(assessment_id)
        by_port = {json.loads(row["evidence"])["port"]: row for row in findings}
        self.assertEqual(by_port[2121]["rule_id"], CLEARTEXT_REMOTE_ACCESS)
        self.assertEqual(by_port[2323]["rule_id"], CLEARTEXT_REMOTE_ACCESS)
        self.assertEqual(by_port[2121]["severity"], "medium")
        self.assertIn("TLS may be available or required", by_port[2121]["description"])
        self.assertEqual(by_port[8080]["rule_id"], HTTP_TRANSPORT_REVIEW)
        self.assertEqual(by_port[8080]["severity"], "low")
        self.assertIn("were not tested", by_port[8080]["description"])
        self.assertEqual(by_port[21]["rule_id"], SERVICE_EXPOSURE)
        self.assertEqual(by_port[990]["rule_id"], SERVICE_EXPOSURE)
        self.assertEqual(by_port[80]["rule_id"], SERVICE_EXPOSURE)

    def test_versions_and_open_services_do_not_create_high_or_cve_claims(self) -> None:
        assessment_id, (host_id,) = self._assessment("192.168.56.20")
        self._services(assessment_id, host_id, [
            {"port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "CVE-2099-9999"},
            {"port": 631, "protocol": "tcp", "state": "open", "service": "ipp", "version": "CUPS"},
        ])

        analyze_assessment(self.database, assessment_id)
        findings = self._findings(assessment_id)
        self.assertEqual({row["severity"] for row in findings}, {"informational"})
        self.assertTrue(all(row["rule_id"] == SERVICE_EXPOSURE for row in findings))
        claims = " ".join(row["description"] + row["impact"] for row in findings)
        self.assertNotIn("CVE-2099-9999", claims)
        self.assertNotIn("vulnerable", claims.lower())

    def test_host_separation_partial_data_and_rerun_deduplication(self) -> None:
        assessment_id, (first, second) = self._assessment(
            "192.168.56.20", "192.168.56.21"
        )
        self._services(assessment_id, first, [{
            "port": 80, "protocol": "tcp", "state": "open", "service": "http", "version": "",
        }])
        finish_assessment_host(first, "completed", database_path=self.database)
        finish_assessment_host(second, "failed", "recon failed", self.database)

        self.assertEqual(analyze_assessment(self.database, assessment_id), 1)
        self.assertEqual(analyze_assessment(self.database, assessment_id), 0)
        findings = self._findings(assessment_id)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["host_id"], first)

    def test_report_escapes_findings_and_contains_no_candidate_password(self) -> None:
        assessment_id, (host_id,) = self._assessment("192.168.56.20")
        self._services(assessment_id, host_id, [{
            "port": 22, "protocol": "tcp", "state": "open", "service": "ssh", "version": "OpenSSH",
        }])
        insert_credential_result(
            assessment_id,
            {"service": "ssh", "port": 22, "username": "<lab-user>", "outcome": "matched"},
            self.database,
            host_id,
        )
        analyze_assessment(self.database, assessment_id)

        generate_report(self.database, assessment_id, self.report)
        document = self.report.read_text(encoding="utf-8")
        self.assertIn("SSH login succeeded using supplied test credentials", document)
        self.assertIn("&lt;lab-user&gt;", document)
        self.assertNotIn("<lab-user>", document)
        self.assertNotIn("SyntheticCandidateSecret", document)
        self.assertIn("not CVSS scores", document)


if __name__ == "__main__":
    unittest.main()
