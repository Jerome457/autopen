"""Nmap-backed reconnaissance for an explicitly supplied target IP."""

from __future__ import annotations

import ipaddress
import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import TypedDict


class ReconError(RuntimeError):
    """Raised when reconnaissance cannot be completed."""


class ServiceInfo(TypedDict):
    """A discovered network service."""

    port: int
    protocol: str
    state: str
    service: str
    version: str


def validate_target(target: str) -> str:
    """Return a normalized IP address, rejecting hostnames and network ranges."""
    try:
        return str(ipaddress.ip_address(target.strip()))
    except ValueError as exc:
        raise ValueError("Target must be one explicit IPv4 or IPv6 address.") from exc


def _service_version(service: ET.Element) -> str:
    """Build a readable version string from Nmap's service attributes."""
    parts = [
        service.get("product", ""),
        service.get("version", ""),
        service.get("extrainfo", ""),
    ]
    return " ".join(part.strip() for part in parts if part.strip())


def parse_nmap_xml(xml_output: str) -> list[ServiceInfo]:
    """Parse open services from Nmap XML output."""
    try:
        root = ET.fromstring(xml_output)
    except ET.ParseError as exc:
        raise ReconError("Nmap returned invalid XML output.") from exc

    services: list[ServiceInfo] = []
    for port_element in root.findall("./host/ports/port"):
        state_element = port_element.find("state")
        state = state_element.get("state", "unknown") if state_element is not None else "unknown"
        if state != "open":
            continue

        service_element = port_element.find("service")
        services.append(
            {
                "port": int(port_element.get("portid", "0")),
                "protocol": port_element.get("protocol", "unknown"),
                "state": state,
                "service": (
                    service_element.get("name", "unknown")
                    if service_element is not None
                    else "unknown"
                ),
                "version": _service_version(service_element) if service_element is not None else "",
            }
        )

    return services


def run_recon(target: str, timeout: int = 180) -> list[ServiceInfo]:
    """Run Nmap service detection against one validated IP address."""
    normalized_target = validate_target(target)
    nmap_binary = shutil.which("nmap")
    if nmap_binary is None:
        raise ReconError("Nmap is not installed or not available in PATH.")

    command = [nmap_binary, "-sV", "-oX", "-", normalized_target]
    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ReconError(f"Nmap timed out after {timeout} seconds.") from exc
    except OSError as exc:
        raise ReconError(f"Unable to start Nmap: {exc}") from exc

    if result.returncode != 0:
        detail = result.stderr.strip() or "unknown Nmap error"
        raise ReconError(f"Nmap scan failed: {detail}")

    return parse_nmap_xml(result.stdout)
