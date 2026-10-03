"""Orchestration tests for optional SSH credential testing."""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import autopen


SSH_SERVICE = {
    "port": 22,
    "protocol": "tcp",
    "state": "open",
    "service": "ssh",
    "version": "OpenSSH",
}
IPP_SERVICE = {
    "port": 631,
    "protocol": "tcp",
    "state": "open",
    "service": "ipp",
    "version": "CUPS",
}


class AutoPenTests(unittest.TestCase):
    def test_credential_test_is_not_invoked_without_discovered_ssh(self) -> None:
        hydra = Mock()
        with (
            patch("builtins.print"),
            patch("autopen.create_assessment", return_value=1),
            patch("autopen.start_capture", return_value=Mock()),
            patch("autopen.run_recon", return_value=[IPP_SERVICE]),
            patch("autopen.run_ssh_credential_test", hydra),
            patch("autopen.stop_capture", return_value=Path("data/capture.pcap")),
            patch("autopen.parse_pcap", return_value=[]),
            patch("autopen.insert_services"),
            patch("autopen.insert_packets"),
            patch("autopen.finish_assessment"),
            patch("autopen.generate_report", return_value=Path("reports/report.html")),
        ):
            status = autopen.main(
                [
                    "--target",
                    "127.0.0.1",
                    "--interface",
                    "lo",
                    "--ssh-user",
                    "autopen-test",
                    "--password-list",
                    "data/credentials.txt",
                ]
            )

        self.assertEqual(status, 0)
        hydra.assert_not_called()

    def test_capture_stops_after_credential_test(self) -> None:
        events: list[str] = []
        result = {
            "service": "ssh",
            "port": 22,
            "username": "autopen-test",
            "credential_found": True,
            "matched_password": "not-printed",
        }

        with (
            patch("builtins.print"),
            patch(
                "autopen.create_assessment",
                side_effect=lambda _target: events.append("assessment") or 1,
            ),
            patch(
                "autopen.start_capture",
                side_effect=lambda _interface: events.append("capture-start") or Mock(),
            ),
            patch(
                "autopen.run_recon",
                side_effect=lambda _target: events.append("recon") or [SSH_SERVICE],
            ),
            patch(
                "autopen.run_ssh_credential_test",
                side_effect=lambda *_args: events.append("credential-test") or result,
            ),
            patch(
                "autopen.stop_capture",
                side_effect=lambda _capture: events.append("capture-stop")
                or Path("data/capture.pcap"),
            ),
            patch("autopen.parse_pcap", return_value=[]),
            patch("autopen.insert_services"),
            patch("autopen.insert_credential_result"),
            patch("autopen.insert_packets"),
            patch("autopen.finish_assessment"),
            patch("autopen.generate_report", return_value=Path("reports/report.html")),
        ):
            status = autopen.main(
                [
                    "--target",
                    "127.0.0.1",
                    "--interface",
                    "lo",
                    "--ssh-user",
                    "autopen-test",
                    "--password-list",
                    "data/credentials.txt",
                ]
            )

        self.assertEqual(status, 0)
        self.assertLess(events.index("capture-start"), events.index("recon"))
        self.assertLess(events.index("recon"), events.index("credential-test"))
        self.assertLess(events.index("credential-test"), events.index("capture-stop"))


if __name__ == "__main__":
    unittest.main()
