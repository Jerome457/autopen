"""Tests for controlled, SSH-only Hydra integration."""

import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from modules.credential_test import (
    CredentialTestError,
    find_ssh_port,
    parse_hydra_output,
    run_ssh_credential_test,
    validate_password_list,
)


SUCCESS_OUTPUT = """Hydra starting
[22][ssh] host: 127.0.0.1   login: autopen-test   password: lab-secret
1 of 1 target successfully completed, 1 valid password found
"""


class CredentialTestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.password_list = Path(self.temporary_directory.name) / "credentials.txt"
        self.password_list.write_text("wrong-password\nlab-secret\n")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def test_hydra_unavailable(self) -> None:
        with patch("modules.credential_test.shutil.which", return_value=None):
            with self.assertRaisesRegex(CredentialTestError, "not installed"):
                run_ssh_credential_test(
                    "127.0.0.1", 22, "autopen-test", self.password_list
                )

    @patch("modules.credential_test.subprocess.run")
    def test_ssh_not_discovered_does_not_invoke_hydra(self, run: Mock) -> None:
        services = [
            {
                "port": 631,
                "protocol": "tcp",
                "state": "open",
                "service": "ipp",
            }
        ]

        self.assertIsNone(find_ssh_port(services))
        run.assert_not_called()

    def test_successful_match_parsing(self) -> None:
        result = parse_hydra_output(SUCCESS_OUTPUT, 22, "autopen-test")

        self.assertTrue(result["credential_found"])
        self.assertEqual(result["matched_password"], "lab-secret")

    def test_no_match_parsing(self) -> None:
        result = parse_hydra_output(
            "0 valid passwords found", 22, "autopen-test"
        )

        self.assertFalse(result["credential_found"])
        self.assertIsNone(result["matched_password"])

    def test_unexpected_output_is_rejected(self) -> None:
        with self.assertRaisesRegex(CredentialTestError, "unexpected output"):
            parse_hydra_output("unrecognized output", 22, "autopen-test")

    def test_password_list_validation(self) -> None:
        empty_list = Path(self.temporary_directory.name) / "empty.txt"
        empty_list.touch()

        with self.assertRaisesRegex(CredentialTestError, "empty"):
            validate_password_list(empty_list)
        with self.assertRaisesRegex(CredentialTestError, "does not exist"):
            validate_password_list(Path(self.temporary_directory.name) / "missing.txt")

    @patch("modules.credential_test.subprocess.run")
    @patch("modules.credential_test.shutil.which", return_value="/usr/bin/hydra")
    def test_custom_ssh_port_is_passed_safely(self, _which: Mock, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess(
            [], 0, stdout=SUCCESS_OUTPUT.replace("[22]", "[2222]"), stderr=""
        )

        result = run_ssh_credential_test(
            "127.0.0.1", 2222, "autopen-test", self.password_list
        )

        command = run.call_args.args[0]
        self.assertEqual(result["port"], 2222)
        self.assertEqual(command[command.index("-s") + 1], "2222")
        self.assertNotIn("shell", run.call_args.kwargs)

    @patch("modules.credential_test.subprocess.run")
    @patch("modules.credential_test.shutil.which", return_value="/usr/bin/hydra")
    def test_subprocess_failure_is_reported(self, _which: Mock, run: Mock) -> None:
        run.return_value = subprocess.CompletedProcess([], 2, stdout="", stderr="failed")

        with self.assertRaisesRegex(CredentialTestError, "status 2"):
            run_ssh_credential_test(
                "127.0.0.1", 22, "autopen-test", self.password_list
            )


if __name__ == "__main__":
    unittest.main()
