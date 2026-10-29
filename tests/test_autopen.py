"""Orchestration tests for persisted outcomes and unconditional cleanup."""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import autopen
from modules.capture import CaptureError
from modules.credential_test import CredentialTestError
from modules.report import ReportError


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


def common_mocks() -> dict[str, Mock]:
    phase_ids = iter(range(100, 120))
    return {
        "create_assessment": Mock(return_value=1),
        "create_assessment_host": Mock(return_value=10),
        "register_artifact": Mock(side_effect=[20, 21]),
        "start_phase": Mock(side_effect=lambda *_args, **_kwargs: next(phase_ids)),
        "finish_phase": Mock(),
        "start_capture": Mock(return_value=Mock()),
        "stop_capture": Mock(return_value=Path("data/assessments/1/capture.pcap")),
        "insert_services": Mock(),
        "insert_credential_result": Mock(),
        "insert_packets": Mock(),
        "finish_assessment_host": Mock(),
        "finish_assessment": Mock(),
        "update_assessment_status": Mock(),
        "update_artifact_status": Mock(),
        "parse_pcap": Mock(return_value=[]),
        "generate_report": Mock(return_value=Path("reports/assessments/1/report.html")),
    }


class AutoPenTests(unittest.TestCase):
    def test_credential_test_is_not_invoked_without_discovered_ssh(self) -> None:
        mocks = common_mocks()
        mocks["run_recon"] = Mock(return_value=[IPP_SERVICE])
        mocks["run_ssh_credential_test"] = Mock()

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(
                [
                    "--target", "127.0.0.1", "--interface", "lo",
                    "--ssh-user", "autopen-test",
                    "--password-list", "data/credentials.txt",
                ]
            )

        self.assertEqual(status, 0)
        mocks["run_ssh_credential_test"].assert_not_called()
        stored = mocks["insert_credential_result"].call_args.args[1]
        self.assertEqual(stored["outcome"], "skipped")

    def test_capture_stops_after_credential_test(self) -> None:
        events: list[str] = []
        mocks = common_mocks()
        mocks["start_capture"] = Mock(
            side_effect=lambda *_args: events.append("capture-start") or Mock()
        )
        mocks["run_recon"] = Mock(
            side_effect=lambda *_args: events.append("recon") or [SSH_SERVICE]
        )
        mocks["run_ssh_credential_test"] = Mock(
            side_effect=lambda *_args: events.append("credential-test") or {
                "service": "ssh", "port": 22, "username": "autopen-test",
                "outcome": "matched", "credential_found": True,
            }
        )
        mocks["stop_capture"] = Mock(
            side_effect=lambda *_args: events.append("capture-stop")
            or Path("data/assessments/1/capture.pcap")
        )

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(
                [
                    "--target", "127.0.0.1", "--interface", "lo",
                    "--ssh-user", "autopen-test",
                    "--password-list", "data/credentials.txt",
                ]
            )

        self.assertEqual(status, 0)
        self.assertLess(events.index("capture-start"), events.index("recon"))
        self.assertLess(events.index("recon"), events.index("credential-test"))
        self.assertLess(events.index("credential-test"), events.index("capture-stop"))

    def test_interrupt_cleans_capture_and_persists_interrupted_outcome(self) -> None:
        mocks = common_mocks()
        mocks["run_recon"] = Mock(side_effect=KeyboardInterrupt)
        mocks["run_ssh_credential_test"] = Mock()

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(["--target", "127.0.0.1", "--interface", "lo"])

        self.assertEqual(status, 130)
        mocks["stop_capture"].assert_called_once()
        self.assertEqual(mocks["finish_assessment_host"].call_args.args[1], "interrupted")
        mocks["finish_assessment"].assert_called_with(1, status="interrupted")

    def test_timed_out_credential_test_is_partial_not_no_match(self) -> None:
        mocks = common_mocks()
        mocks["run_recon"] = Mock(return_value=[SSH_SERVICE])
        mocks["run_ssh_credential_test"] = Mock(
            side_effect=CredentialTestError("Hydra timed out.", outcome="timed_out")
        )

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(
                [
                    "--target", "127.0.0.1", "--interface", "lo",
                    "--ssh-user", "autopen-test",
                    "--password-list", "data/credentials.txt",
                ]
            )

        self.assertEqual(status, 1)
        stored = mocks["insert_credential_result"].call_args.args[1]
        self.assertEqual(stored["outcome"], "timed_out")
        self.assertIsNone(stored["credential_found"])
        self.assertEqual(mocks["finish_assessment_host"].call_args.args[1], "partial")
        mocks["stop_capture"].assert_called_once()

    def test_capture_failure_records_skipped_phases_and_failed_host(self) -> None:
        mocks = common_mocks()
        mocks["start_capture"] = Mock(side_effect=CaptureError("capture denied"))
        mocks["run_recon"] = Mock()
        mocks["run_ssh_credential_test"] = Mock()

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(["--target", "127.0.0.1", "--interface", "lo"])

        self.assertEqual(status, 1)
        mocks["run_recon"].assert_not_called()
        mocks["stop_capture"].assert_not_called()
        stored = mocks["insert_credential_result"].call_args.args[1]
        self.assertEqual(stored["outcome"], "skipped")
        self.assertEqual(mocks["finish_assessment_host"].call_args.args[1], "failed")
        mocks["finish_assessment"].assert_called_with(1, status="failed")

    def test_report_failure_does_not_change_completed_host_outcome(self) -> None:
        mocks = common_mocks()
        mocks["run_recon"] = Mock(return_value=[IPP_SERVICE])
        mocks["run_ssh_credential_test"] = Mock()
        mocks["generate_report"] = Mock(side_effect=ReportError("render failed"))

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(["--target", "127.0.0.1", "--interface", "lo"])

        self.assertEqual(status, 1)
        self.assertEqual(mocks["finish_assessment_host"].call_args.args[1], "completed")
        mocks["update_assessment_status"].assert_called_with(1, "partial")


if __name__ == "__main__":
    unittest.main()
