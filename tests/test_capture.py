"""Unit tests for TShark capture lifecycle management."""

import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from modules.capture import CaptureError, CaptureSession, start_capture, stop_capture


class CaptureTests(unittest.TestCase):
    @patch("modules.capture.time.sleep")
    @patch("modules.capture.subprocess.Popen")
    @patch("modules.capture.shutil.which", return_value="/usr/bin/tshark")
    def test_start_capture_builds_safe_command(
        self, _which: Mock, popen: Mock, _sleep: Mock
    ) -> None:
        process = popen.return_value
        process.poll.return_value = None

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture.pcap"
            session = start_capture("lo", output)

        self.assertEqual(session.interface, "lo")
        popen.assert_called_once_with(
            ["/usr/bin/tshark", "-i", "lo", "-F", "pcap", "-w", str(output), "-q"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )

    @patch("modules.capture.shutil.which", return_value=None)
    def test_start_capture_requires_tshark(self, _which: Mock) -> None:
        with self.assertRaisesRegex(CaptureError, "not installed"):
            start_capture("lo", startup_delay=0)

    def test_stop_capture_uses_sigint_and_returns_nonempty_file(self) -> None:
        process = Mock()
        process.poll.return_value = None
        process.returncode = 0
        process.communicate.return_value = ("", "")

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture.pcap"
            output.write_bytes(b"pcap data")
            result = stop_capture(CaptureSession(process, output, "lo"))

        process.send_signal.assert_called_once_with(signal.SIGINT)
        self.assertEqual(result, output)

    def test_stop_capture_terminates_after_timeout(self) -> None:
        process = Mock()
        process.poll.return_value = None
        process.returncode = 0
        process.communicate.side_effect = [
            subprocess.TimeoutExpired("tshark", 1),
            ("", ""),
        ]

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "capture.pcap"
            output.write_bytes(b"pcap data")
            stop_capture(CaptureSession(process, output, "lo"), timeout=1)

        process.terminate.assert_called_once_with()
        process.kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
