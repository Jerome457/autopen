"""TShark packet-capture lifecycle management."""

from __future__ import annotations

import shutil
import signal
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path


DEFAULT_CAPTURE_PATH = Path("data/capture.pcap")


class CaptureError(RuntimeError):
    """Raised when packet capture cannot be started or saved."""


@dataclass
class CaptureSession:
    """A running TShark process and its capture metadata."""

    process: subprocess.Popen[str]
    output_path: Path
    interface: str


def _process_error(process: subprocess.Popen[str]) -> str:
    """Collect TShark's error output after it has exited."""
    try:
        _, stderr = process.communicate(timeout=1)
    except subprocess.TimeoutExpired:
        stderr = ""
    return (stderr or "").strip() or "TShark exited unexpectedly."


def start_capture(
    interface: str,
    output_path: Path = DEFAULT_CAPTURE_PATH,
    startup_delay: float = 1.0,
) -> CaptureSession:
    """Start TShark on an explicit interface and write a PCAP file."""
    if not interface.strip():
        raise CaptureError("A non-empty capture interface is required.")

    tshark_binary = shutil.which("tshark")
    if tshark_binary is None:
        raise CaptureError("TShark is not installed or not available in PATH.")

    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.unlink(missing_ok=True)

    command = [
        tshark_binary,
        "-i",
        interface,
        "-F",
        "pcap",
        "-w",
        str(output_path),
        "-q",
    ]
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
        )
    except OSError as exc:
        raise CaptureError(f"Unable to start TShark: {exc}") from exc

    time.sleep(startup_delay)
    if process.poll() is not None:
        detail = _process_error(process)
        raise CaptureError(
            "TShark could not start capturing. Check that the interface exists and "
            f"that your user has packet-capture permission. Details: {detail}"
        )

    return CaptureSession(process, output_path, interface)


def stop_capture(session: CaptureSession, timeout: float = 10.0) -> Path:
    """Stop TShark gracefully, escalating only when it does not exit."""
    process = session.process
    stderr = ""

    if process.poll() is None:
        process.send_signal(signal.SIGINT)
        try:
            _, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            try:
                _, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                _, stderr = process.communicate()
    else:
        _, stderr = process.communicate()

    if process.returncode not in (0, None):
        detail = (stderr or "").strip() or f"exit status {process.returncode}"
        raise CaptureError(f"TShark stopped with an error: {detail}")

    if not session.output_path.is_file() or session.output_path.stat().st_size == 0:
        raise CaptureError(f"TShark did not create a usable capture: {session.output_path}")

    return session.output_path
