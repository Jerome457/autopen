"""Command-line entry point for the AutoPen lab toolkit."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from modules.artifacts import assessment_artifact_paths
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
    create_assessment_host,
    finish_assessment,
    finish_assessment_host,
    finish_phase,
    insert_credential_result,
    insert_packets,
    insert_services,
    register_artifact,
    start_phase,
    update_artifact_status,
    update_assessment_status,
)
from modules.pcap_parser import PcapParserError, parse_pcap
from modules.recon import ReconError, run_recon, validate_target
from modules.report import ReportError, generate_report


def target_ip(value: str) -> str:
    """Argparse adapter for single-IP validation."""
    try:
        return validate_target(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def build_parser() -> argparse.ArgumentParser:
    """Create the backward-compatible single-target parser."""
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


def _credential_record(
    outcome: str,
    username: str | None,
    port: int | None,
) -> CredentialResult:
    return {
        "service": "ssh",
        "port": port,
        "username": username,
        "outcome": outcome,
        "credential_found": True if outcome == "matched" else False if outcome == "no_match" else None,
    }


def _display_services(services: list[dict[str, object]]) -> None:
    if not services:
        print("[!] No open services found.")
        return
    for item in services:
        version = f" - {item['version']}" if item["version"] else ""
        print(
            f"[+] {item['port']}/{item['protocol']} OPEN - "
            f"{item['service']}{version}"
        )


def main(argv: Sequence[str] | None = None) -> int:
    """Run one explicit target while persisting host, phase, and artifact outcomes."""
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.ssh_user) != bool(args.password_list):
        parser.error("--ssh-user and --password-list must be supplied together")
    interface = args.interface
    if interface is None and ipaddress.ip_address(args.target).is_loopback:
        interface = "lo"
    if interface is None:
        parser.error("--interface is required for non-loopback targets; choose it explicitly")

    print("[*] AutoPen starting")
    print(f"[*] Target: {args.target}")

    try:
        assessment_id = create_assessment(args.target)
        host_id = create_assessment_host(assessment_id, args.target, interface)
        paths = assessment_artifact_paths(assessment_id)
        capture_artifact_id = register_artifact(
            assessment_id, "pcap", paths.capture
        )
        report_artifact_id = register_artifact(
            assessment_id, "report", paths.report
        )
    except DatabaseError as exc:
        print(f"[-] {exc}", file=sys.stderr)
        if "assessment_id" in locals():
            try:
                finish_assessment(assessment_id, status="failed")
            except DatabaseError:
                pass
        return 1

    services: list[dict[str, object]] = []
    errors: list[str] = []
    interrupted = False
    capture_available = False
    recon_ok = False
    credential_ok = False
    parse_ok = False
    packet_store_ok = False
    capture = None

    print(f"\n[*] Starting traffic capture on {interface}...")
    capture_phase = start_phase(assessment_id, "capture", host_id)
    try:
        try:
            capture = start_capture(interface, paths.capture)
        except CaptureError as exc:
            errors.append(str(exc))
            finish_phase(capture_phase, "failed", exc)
            update_artifact_status(capture_artifact_id, "failed")
            print(f"[-] {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            interrupted = True
            errors.append("Capture startup interrupted.")
            finish_phase(capture_phase, "interrupted", "Capture startup interrupted.")
            update_artifact_status(capture_artifact_id, "incomplete")
        else:
            print("\n[*] Running reconnaissance...")
            recon_phase = start_phase(assessment_id, "reconnaissance", host_id)
            try:
                services = run_recon(args.target)
                insert_services(
                    assessment_id, services, host_id=host_id
                )
                recon_ok = True
                finish_phase(recon_phase, "completed")
                _display_services(services)
            except KeyboardInterrupt:
                interrupted = True
                errors.append("Reconnaissance interrupted.")
                finish_phase(recon_phase, "interrupted", "Reconnaissance interrupted.")
            except (ReconError, DatabaseError) as exc:
                errors.append(str(exc))
                finish_phase(recon_phase, "failed", exc)
                print(f"[-] {exc}", file=sys.stderr)

            if not interrupted:
                credential_phase = start_phase(
                    assessment_id, "credential_testing", host_id
                )
                ssh_port = find_ssh_port(services) if recon_ok else None
                credential_result: CredentialResult
                if not args.ssh_user:
                    credential_result = _credential_record("skipped", None, ssh_port)
                    insert_credential_result(
                        assessment_id, credential_result, host_id=host_id
                    )
                    credential_ok = True
                    finish_phase(credential_phase, "skipped")
                elif not recon_ok or ssh_port is None:
                    print("[!] SSH was not discovered; credential testing skipped.")
                    credential_result = _credential_record(
                        "skipped", args.ssh_user, ssh_port
                    )
                    insert_credential_result(
                        assessment_id, credential_result, host_id=host_id
                    )
                    credential_ok = True
                    finish_phase(credential_phase, "skipped")
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
                        insert_credential_result(
                            assessment_id, credential_result, host_id=host_id
                        )
                        credential_ok = True
                        finish_phase(credential_phase, "completed")
                        print("[+] SSH credential test completed")
                        if credential_result["outcome"] == "matched":
                            print("[+] Test credential matched")
                        else:
                            print("[!] No test credential matched")
                    except KeyboardInterrupt:
                        interrupted = True
                        errors.append("Credential testing interrupted.")
                        finish_phase(
                            credential_phase,
                            "interrupted",
                            "Credential testing interrupted.",
                        )
                    except CredentialTestError as exc:
                        errors.append(str(exc))
                        credential_result = _credential_record(
                            exc.outcome, args.ssh_user, ssh_port
                        )
                        insert_credential_result(
                            assessment_id, credential_result, host_id=host_id
                        )
                        finish_phase(credential_phase, exc.outcome, exc)
                        print(f"[-] {exc}", file=sys.stderr)
                    except DatabaseError as exc:
                        errors.append(str(exc))
                        finish_phase(credential_phase, "failed", exc)
                        print(f"[-] {exc}", file=sys.stderr)
    finally:
        if capture is not None:
            print("\n[*] Stopping traffic capture...")
            try:
                capture_path = stop_capture(capture)
                capture_available = True
                update_artifact_status(capture_artifact_id, "available")
                finish_phase(capture_phase, "completed")
                print(f"[+] Capture saved: {capture_path}")
            except CaptureError as exc:
                errors.append(str(exc))
                update_artifact_status(capture_artifact_id, "failed")
                finish_phase(capture_phase, "failed", exc)
                print(f"[-] {exc}", file=sys.stderr)

    if capture is None and not interrupted:
        recon_skip = start_phase(assessment_id, "reconnaissance", host_id)
        finish_phase(recon_skip, "skipped", "Capture was unavailable.")
        credential_skip = start_phase(assessment_id, "credential_testing", host_id)
        skipped_result = _credential_record("skipped", args.ssh_user, None)
        insert_credential_result(assessment_id, skipped_result, host_id=host_id)
        finish_phase(credential_skip, "skipped", "Reconnaissance was not run.")

    if interrupted:
        host_status = "interrupted"
        finish_assessment_host(host_id, host_status, "; ".join(errors))
        finish_assessment(assessment_id, status="interrupted")
        update_artifact_status(report_artifact_id, "incomplete")
        print("\n[!] Assessment interrupted")
        return 130

    if capture_available:
        print("\n[*] Parsing captured traffic...")
        parse_phase = start_phase(assessment_id, "pcap_parsing", host_id)
        try:
            packets = parse_pcap(paths.capture)
            parse_ok = True
            finish_phase(parse_phase, "completed")
            print(f"[+] {len(packets)} packets parsed")
        except KeyboardInterrupt:
            finish_phase(parse_phase, "interrupted", "PCAP parsing interrupted.")
            finish_assessment_host(host_id, "interrupted", "PCAP parsing interrupted.")
            finish_assessment(assessment_id, status="interrupted")
            update_artifact_status(report_artifact_id, "incomplete")
            return 130
        except PcapParserError as exc:
            errors.append(str(exc))
            finish_phase(parse_phase, "failed", exc)
            print(f"[-] {exc}", file=sys.stderr)

        if parse_ok:
            print("\n[*] Storing forensic data...")
            storage_phase = start_phase(assessment_id, "packet_storage", host_id)
            try:
                insert_packets(assessment_id, packets)
                packet_store_ok = True
                finish_phase(storage_phase, "completed")
                print(f"[+] Assessment stored in {DEFAULT_DATABASE_PATH}")
            except DatabaseError as exc:
                errors.append(str(exc))
                finish_phase(storage_phase, "failed", exc)
                print(f"[-] {exc}", file=sys.stderr)
        else:
            storage_phase = start_phase(assessment_id, "packet_storage", host_id)
            finish_phase(storage_phase, "skipped", "PCAP parsing did not complete.")
    else:
        parse_phase = start_phase(assessment_id, "pcap_parsing", host_id)
        finish_phase(parse_phase, "skipped", "No available PCAP artifact.")
        storage_phase = start_phase(assessment_id, "packet_storage", host_id)
        finish_phase(storage_phase, "skipped", "No parsed packets were available.")

    required_ok = (
        capture_available and recon_ok and credential_ok and parse_ok and packet_store_ok
    )
    evidence_exists = capture_available or bool(services)
    host_status = "completed" if required_ok else "partial" if evidence_exists else "failed"
    finish_assessment_host(host_id, host_status, "; ".join(errors) or None)
    overall_status = host_status
    finish_assessment(assessment_id, status=overall_status)

    print("\n[*] Structured service information:")
    print(json.dumps(services, indent=2))
    print("\n[*] Generating consolidated report...")
    report_phase = start_phase(assessment_id, "report_generation")
    report_path: Path | None = None
    try:
        report_path = generate_report(DEFAULT_DATABASE_PATH, assessment_id, paths.report)
        update_artifact_status(report_artifact_id, "available")
        finish_phase(report_phase, "completed")
        print(f"[+] Report saved: {report_path}")
    except KeyboardInterrupt:
        update_artifact_status(report_artifact_id, "incomplete")
        finish_phase(report_phase, "interrupted", "Report generation interrupted.")
        update_assessment_status(assessment_id, "interrupted")
        print("\n[!] Assessment interrupted")
        return 130
    except ReportError as exc:
        errors.append(str(exc))
        update_artifact_status(report_artifact_id, "failed")
        finish_phase(report_phase, "failed", exc)
        if overall_status == "completed":
            overall_status = "partial"
            update_assessment_status(assessment_id, overall_status)
        print(f"[-] {exc}", file=sys.stderr)

    marker = "✓" if overall_status == "completed" else "!"
    print(f"\n[{marker}] Assessment {overall_status}")
    print("\nArtifacts:")
    print(f"    PCAP:     {paths.capture}")
    print(f"    Database: {DEFAULT_DATABASE_PATH}")
    print(f"    Report:   {report_path or paths.report}")
    return 0 if overall_status == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
