"""Command-line entry point for the AutoPen lab toolkit."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from modules.capture import CaptureError, start_capture, stop_capture
from modules.credential_test import (
    CredentialResult,
    CredentialTestError,
    find_ssh_port,
    run_ssh_credential_test,
)
from modules.database import (
    DEFAULT_DATABASE_PATH,
    DatabaseError,
    create_assessment,
    finish_assessment,
    insert_credential_result,
    insert_packets,
    insert_services,
)
from modules.pcap_parser import PcapParserError, parse_pcap
from modules.recon import ReconError, run_recon, validate_target
from modules.report import DEFAULT_REPORT_PATH, ReportError, generate_report


def target_ip(value: str) -> str:
    """Argparse adapter for single-IP validation."""
    try:
        return validate_target(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    """Create the AutoPen command-line parser."""
    parser = argparse.ArgumentParser(
        description="Run AutoPen reconnaissance against an explicit lab target."
    )
    parser.add_argument(
        "--target",
        required=True,
        type=target_ip,
        help="one IPv4 or IPv6 address belonging to the isolated lab",
    )
    parser.add_argument(
        "--interface",
        help="capture interface (automatically uses lo for a loopback target)",
    )
    parser.add_argument(
        "--ssh-user",
        help="explicit SSH username for the optional controlled lab test",
    )
    parser.add_argument(
        "--password-list",
        type=Path,
        help="path to a small, explicitly supplied lab password list",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Capture traffic around the reconnaissance workflow."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.ssh_user) != bool(args.password_list):
        parser.error("--ssh-user and --password-list must be supplied together")
    interface = args.interface
    if interface is None and ipaddress.ip_address(args.target).is_loopback:
        interface = "lo"
    if interface is None:
        build_parser().error(
            "--interface is required for non-loopback targets; choose it explicitly"
        )

    print("[*] AutoPen starting")
    print(f"[*] Target: {args.target}")

    try:
        assessment_id = create_assessment(args.target)
    except DatabaseError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    print(f"\n[*] Starting traffic capture on {interface}...")

    try:
        capture = start_capture(interface)
    except CaptureError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1

    services = None
    credential_result: CredentialResult | None = None
    recon_error = None
    credential_error = None
    capture_error = None
    try:
        print("\n[*] Running reconnaissance...")
        try:
            services = run_recon(args.target)
        except ReconError as exc:
            recon_error = exc
        else:
            if not services:
                print("[!] No open services found.")
            else:
                for item in services:
                    version = f" - {item['version']}" if item["version"] else ""
                    print(
                        f"[+] {item['port']}/{item['protocol']} OPEN - "
                        f"{item['service']}{version}"
                    )

            if args.ssh_user and args.password_list:
                ssh_port = find_ssh_port(services)
                if ssh_port is None:
                    print("[!] SSH was not discovered; credential testing skipped.")
                else:
                    print(f"\n[*] SSH discovered on port {ssh_port}")
                    print("[*] Running controlled SSH credential test...")
                    try:
                        credential_result = run_ssh_credential_test(
                            args.target,
                            ssh_port,
                            args.ssh_user,
                            args.password_list,
                        )
                    except CredentialTestError as exc:
                        credential_error = exc
                    else:
                        print("[+] SSH credential test completed")
                        if credential_result["credential_found"]:
                            print("[+] Test credential matched")
                        else:
                            print("[!] No test credential matched")
    finally:
        print("\n[*] Stopping traffic capture...")
        try:
            capture_path = stop_capture(capture)
            print(f"[+] Capture saved: {capture_path}")
        except CaptureError as exc:
            capture_error = exc

    if recon_error is not None:
        print(f"[-] {recon_error}", file=sys.stderr)
    if capture_error is not None:
        print(f"[-] {capture_error}", file=sys.stderr)
    if credential_error is not None:
        print(f"[-] {credential_error}", file=sys.stderr)
    if recon_error is not None or credential_error is not None or capture_error is not None:
        return 1

    print("\n[*] Structured service information:")
    print(json.dumps(services, indent=2))

    print("\n[*] Parsing captured traffic...")
    try:
        packets = parse_pcap(capture_path)
    except PcapParserError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    print(f"[+] {len(packets)} packets parsed")

    print("\n[*] Storing forensic data...")
    try:
        insert_services(assessment_id, services)
        if credential_result is not None:
            insert_credential_result(assessment_id, credential_result)
        insert_packets(assessment_id, packets)
        finish_assessment(assessment_id)
    except DatabaseError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    print(f"[+] Assessment stored in {DEFAULT_DATABASE_PATH}")

    print("\n[*] Generating consolidated report...")
    try:
        report_path = generate_report(
            DEFAULT_DATABASE_PATH, assessment_id, DEFAULT_REPORT_PATH
        )
    except ReportError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1
    print(f"[+] Report saved: {report_path}")

    print("\n[✓] Assessment complete")
    print("\nArtifacts:")
    print(f"    PCAP:     {capture_path}")
    print(f"    Database: {DEFAULT_DATABASE_PATH}")
    print(f"    Report:   {report_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
