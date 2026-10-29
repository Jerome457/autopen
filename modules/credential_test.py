"""Controlled SSH credential testing for an explicitly supplied lab target."""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, TypedDict

from modules.recon import validate_target


MAX_TEST_PASSWORDS = 20


class CredentialTestError(RuntimeError):
    """Raised when the controlled credential test cannot be completed."""

    def __init__(self, message: str, outcome: str = "failed") -> None:
        super().__init__(message)
        self.outcome = outcome


class CredentialResult(TypedDict):
    """Structured outcome of one controlled SSH credential test."""

    service: str
    port: int
    username: str
    outcome: str
    credential_found: bool | None


_MATCH_PATTERN = re.compile(
    r"\[(?P<port>\d+)\]\[ssh\]\s+host:\s+\S+\s+"
    r"login:\s+(?P<username>\S+)\s+password:\s*(?P<password>.*)$",
    re.IGNORECASE | re.MULTILINE,
)
_NO_MATCH_PATTERN = re.compile(r"\b0 valid passwords? found\b", re.IGNORECASE)


def find_ssh_port(services: Sequence[Mapping[str, Any]]) -> int | None:
    """Return the first open TCP SSH port discovered by reconnaissance."""
    for service in services:
        if (
            str(service.get("service", "")).lower() == "ssh"
            and str(service.get("protocol", "")).lower() == "tcp"
            and str(service.get("state", "")).lower() == "open"
        ):
            try:
                return int(service["port"])
            except (KeyError, TypeError, ValueError):
                return None
    return None


def validate_password_list(password_list: Path) -> Path:
    """Validate that the explicitly supplied list is readable and deliberately small."""
    password_list = Path(password_list)
    if not password_list.is_file():
        raise CredentialTestError(f"Password list does not exist: {password_list}")
    try:
        passwords = [line for line in password_list.read_text().splitlines() if line]
    except OSError as exc:
        raise CredentialTestError(f"Unable to read password list {password_list}: {exc}") from exc
    if not passwords:
        raise CredentialTestError(f"Password list is empty: {password_list}")
    if len(passwords) > MAX_TEST_PASSWORDS:
        raise CredentialTestError(
            f"Password list contains {len(passwords)} entries; the lab limit is "
            f"{MAX_TEST_PASSWORDS}."
        )
    return password_list


def parse_hydra_output(output: str, port: int, username: str) -> CredentialResult:
    """Parse a Hydra SSH match without retaining its full raw output."""
    for match in _MATCH_PATTERN.finditer(output):
        if int(match.group("port")) == port and match.group("username") == username:
            return {
                "service": "ssh",
                "port": port,
                "username": username,
                "outcome": "matched",
                "credential_found": True,
            }

    if _NO_MATCH_PATTERN.search(output):
        return {
            "service": "ssh",
            "port": port,
            "username": username,
            "outcome": "no_match",
            "credential_found": False,
        }

    raise CredentialTestError("Hydra returned unexpected output that could not be parsed.")


def run_ssh_credential_test(
    target: str,
    port: int,
    username: str,
    password_list: Path,
    timeout: int = 120,
) -> CredentialResult:
    """Run a small, explicit Hydra password-list test against discovered SSH."""
    try:
        target = validate_target(target)
    except ValueError as exc:
        raise CredentialTestError(str(exc)) from exc
    if not 1 <= port <= 65535:
        raise CredentialTestError("SSH port must be between 1 and 65535.")
    if not username or username != username.strip() or any(char.isspace() for char in username):
        raise CredentialTestError("SSH username must be non-empty and contain no whitespace.")

    password_list = validate_password_list(password_list)
    hydra_binary = shutil.which("hydra")
    if hydra_binary is None:
        raise CredentialTestError("Hydra is not installed or not available in PATH.")

    command = [
        hydra_binary,
        "-I",
        "-l",
        username,
        "-P",
        str(password_list),
        "-s",
        str(port),
        "-t",
        "2",
        "-w",
        "5",
        "-f",
        target,
        "ssh",
    ]
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise CredentialTestError(
            f"Hydra timed out after {timeout} seconds.", outcome="timed_out"
        ) from exc
    except OSError as exc:
        raise CredentialTestError(f"Unable to start Hydra: {exc}") from exc

    if completed.returncode != 0:
        raise CredentialTestError(f"Hydra exited with status {completed.returncode}.")

    return parse_hydra_output(
        f"{completed.stdout}\n{completed.stderr}", port, username
    )
