"""Orchestration tests for persisted outcomes and unconditional cleanup."""

import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import autopen
from modules.capture import CaptureError
from modules.credential_test import CredentialTestError
from modules.report import ReportError
from modules.security_analysis import SecurityAnalysisError


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
        "analyze_assessment": Mock(return_value=0),
        "generate_report": Mock(return_value=Path("reports/assessments/1/report.html")),
    }


class AutoPenTests(unittest.TestCase):
    def test_target_normalization_and_ordered_deduplication(self) -> None:
        self.assertEqual(
            autopen.normalize_targets(
                ["192.168.56.20", "2001:0db8::1", "192.168.56.20", "2001:db8::1"]
            ),
            ["192.168.56.20", "2001:db8::1"],
        )

    def test_invalid_target_is_rejected_before_assessment_creation(self) -> None:
        with patch.object(autopen, "create_assessment") as create_assessment:
            with self.assertRaises(SystemExit):
                autopen.main(["--target", "lab-host", "--interface", "lab0"])
        create_assessment.assert_not_called()

    def test_mixed_loopback_targets_are_rejected_before_external_execution(self) -> None:
        with patch.object(autopen, "create_assessment") as create_assessment, \
             patch.object(autopen, "start_capture") as start_capture:
            with self.assertRaises(SystemExit):
                autopen.main(
                    ["--target", "127.0.0.1", "--target", "192.168.56.20", "--interface", "lab0"]
                )
        create_assessment.assert_not_called()
        start_capture.assert_not_called()

    def test_multi_host_continues_after_recon_failure_and_uses_one_capture(self) -> None:
        mocks = common_mocks()
        mocks["create_assessment_host"] = Mock(side_effect=[10, 11])
        mocks["run_recon"] = Mock(
            side_effect=[autopen.ReconError("host A failed"), [IPP_SERVICE]]
        )
        mocks["run_ssh_credential_test"] = Mock()

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(
                [
                    "--target", "192.168.56.20", "--target", "192.168.56.21",
                    "--interface", "lab0",
                ]
            )

        self.assertEqual(status, 1)
        mocks["create_assessment"].assert_called_once_with("192.168.56.20")
        self.assertEqual(
            [call.args[1] for call in mocks["create_assessment_host"].call_args_list],
            ["192.168.56.20", "192.168.56.21"],
        )
        self.assertEqual(mocks["run_recon"].call_count, 2)
        mocks["start_capture"].assert_called_once()
        mocks["stop_capture"].assert_called_once()
        mocks["parse_pcap"].assert_called_once()
        capture_filter = mocks["start_capture"].call_args.kwargs["capture_filter"]
        self.assertEqual(
            capture_filter,
            "(host 192.168.56.20 or host 192.168.56.21)",
        )
        service_call = mocks["insert_services"].call_args
        self.assertEqual(service_call.kwargs["host_id"], 11)
        final_hosts = {
            call.args[0]: call.args[1]
            for call in mocks["finish_assessment_host"].call_args_list
        }
        self.assertEqual(final_hosts, {10: "failed", 11: "completed"})
        mocks["finish_assessment"].assert_called_with(1, status="partial")

    def test_interrupt_marks_current_and_unprocessed_hosts(self) -> None:
        mocks = common_mocks()
        mocks["create_assessment_host"] = Mock(side_effect=[10, 11, 12])
        mocks["run_recon"] = Mock(side_effect=[[IPP_SERVICE], KeyboardInterrupt])
        mocks["run_ssh_credential_test"] = Mock()

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(
                [
                    "--target", "192.168.56.20", "--target", "192.168.56.21",
                    "--target", "192.168.56.22", "--interface", "lab0",
                ]
            )

        self.assertEqual(status, 130)
        self.assertEqual(mocks["run_recon"].call_count, 2)
        mocks["stop_capture"].assert_called_once()
        final_hosts = {
            call.args[0]: (call.args[1], call.args[2] if len(call.args) > 2 else None)
            for call in mocks["finish_assessment_host"].call_args_list
        }
        self.assertEqual(final_hosts[10][0], "completed")
        self.assertEqual(final_hosts[11][0], "interrupted")
        self.assertEqual(final_hosts[12][0], "interrupted")
        self.assertIn("Not processed", final_hosts[12][1])

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
            side_effect=lambda *_args, **_kwargs: events.append("capture-start") or Mock()
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

    def test_analysis_failure_preserves_host_results_and_marks_assessment_partial(self) -> None:
        mocks = common_mocks()
        mocks["run_recon"] = Mock(return_value=[IPP_SERVICE])
        mocks["run_ssh_credential_test"] = Mock()
        mocks["analyze_assessment"] = Mock(
            side_effect=SecurityAnalysisError("analysis unavailable")
        )

        with patch("builtins.print"), patch.multiple(autopen, **mocks):
            status = autopen.main(["--target", "127.0.0.1", "--interface", "lo"])

        self.assertEqual(status, 1)
        self.assertEqual(mocks["finish_assessment_host"].call_args.args[1], "completed")
        mocks["finish_assessment"].assert_called_with(1, status="partial")
        self.assertTrue(
            any(call.args[1] == "failed" for call in mocks["finish_phase"].call_args_list)
        )
        mocks["generate_report"].assert_called_once()


if __name__ == "__main__":
    unittest.main()
