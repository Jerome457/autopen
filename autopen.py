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
from modules.security_analysis import SecurityAnalysisError, analyze_assessment


def normalize_targets(values: Sequence[str]) -> list[str]:
    """Validate, normalize, and order-deduplicate explicit IP targets."""
    targets: list[str] = []
    seen: set[str] = set()
    for value in values:
        normalized = validate_target(value)
        if normalized not in seen:
            seen.add(normalized)
            targets.append(normalized)
    return targets


def capture_filter_for(targets: Sequence[str]) -> str:
    """Build a BPF host filter containing only explicitly supplied addresses."""
    return "(" + " or ".join(f"host {target}" for target in targets) + ")"


def build_parser() -> argparse.ArgumentParser:
    """Create the parser for one or more explicit targets."""
    parser = argparse.ArgumentParser(
        description="Run AutoPen reconnaissance against an explicit lab target."
    )
    parser.add_argument(
        "--target",
        required=True,
        action="append",
        help="explicit IPv4 or IPv6 address; repeat for multiple lab targets",
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
    """Run one assessment over explicitly supplied targets, sequentially."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        targets = normalize_targets(args.target)
    except ValueError as exc:
        parser.error(str(exc))
    if bool(args.ssh_user) != bool(args.password_list):
        parser.error("--ssh-user and --password-list must be supplied together")

    loopback_flags = [ipaddress.ip_address(target).is_loopback for target in targets]
    if any(loopback_flags) and not all(loopback_flags):
        parser.error(
            "Loopback and non-loopback targets cannot be mixed in one assessment; "
            "they require different capture interfaces."
        )
    interface = args.interface
    if interface is None and all(loopback_flags):
        interface = "lo"
    if interface is None:
        parser.error("--interface is required for non-loopback targets; choose it explicitly")

    print("[*] AutoPen starting")
    print(f"[*] Targets ({len(targets)}): {', '.join(targets)}")

    try:
        assessment_id = create_assessment(targets[0])
        hosts = [
            {
                "id": create_assessment_host(assessment_id, target, interface),
                "target": target,
                "status": "running",
                "services": [],
                "errors": [],
            }
            for target in targets
        ]
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

    all_services: list[dict[str, object]] = []
    shared_errors: list[str] = []
    interrupted = False
    capture_available = False
    parse_ok = False
    packet_store_ok = False
    capture = None

    print(f"\n[*] Starting traffic capture on {interface}...")
    capture_phase = start_phase(assessment_id, "capture")
    try:
        try:
            capture = start_capture(
                interface,
                paths.capture,
                capture_filter=capture_filter_for(targets),
            )
        except CaptureError as exc:
            shared_errors.append(str(exc))
            finish_phase(capture_phase, "failed", exc)
            update_artifact_status(capture_artifact_id, "failed")
            print(f"[-] {exc}", file=sys.stderr)
        except KeyboardInterrupt:
            interrupted = True
            shared_errors.append("Capture startup interrupted.")
            finish_phase(capture_phase, "interrupted", "Capture startup interrupted.")
            update_artifact_status(capture_artifact_id, "incomplete")
        else:
            for host in hosts:
                if interrupted:
                    break
                host_id = int(host["id"])
                target = str(host["target"])
                print(f"\n[*] Running reconnaissance for {target}...")
                recon_phase = start_phase(assessment_id, "reconnaissance", host_id)
                recon_ok = False
                try:
                    services = run_recon(target)
                    insert_services(assessment_id, services, host_id=host_id)
                    host["services"] = services
                    all_services.extend(services)
                    recon_ok = True
                    finish_phase(recon_phase, "completed")
                    _display_services(services)
                except KeyboardInterrupt:
                    interrupted = True
                    host["errors"].append("Reconnaissance interrupted.")
                    host["status"] = "interrupted"
                    finish_phase(recon_phase, "interrupted", "Reconnaissance interrupted.")
                except (ReconError, DatabaseError) as exc:
                    host["errors"].append(str(exc))
                    host["status"] = "failed"
                    finish_phase(recon_phase, "failed", exc)
                    print(f"[-] {target}: {exc}", file=sys.stderr)

                if interrupted:
                    continue

                credential_phase = start_phase(
                    assessment_id, "credential_testing", host_id
                )
                ssh_port = find_ssh_port(host["services"]) if recon_ok else None
                if not recon_ok:
                    result = _credential_record("skipped", args.ssh_user, None)
                    insert_credential_result(assessment_id, result, host_id=host_id)
                    finish_phase(
                        credential_phase,
                        "skipped",
                        "Reconnaissance failed; credential testing was not run.",
                    )
                    finish_assessment_host(
                        host_id, "failed", "; ".join(host["errors"])
                    )
                    continue
                if not args.ssh_user or ssh_port is None:
                    result = _credential_record("skipped", args.ssh_user, ssh_port)
                    insert_credential_result(assessment_id, result, host_id=host_id)
                    reason = (
                        "Optional credential testing was not configured."
                        if not args.ssh_user
                        else "SSH was not discovered."
                    )
                    finish_phase(credential_phase, "skipped", reason)
                    host["status"] = "completed"
                else:
                    print(f"[*] Running controlled SSH credential test for {target}:{ssh_port}...")
                    try:
                        result = run_ssh_credential_test(
                            target, ssh_port, args.ssh_user, args.password_list
                        )
                        insert_credential_result(assessment_id, result, host_id=host_id)
                        finish_phase(credential_phase, "completed")
                        host["status"] = "completed"
                        print("[+] SSH credential test completed")
                    except KeyboardInterrupt:
                        interrupted = True
                        host["errors"].append("Credential testing interrupted.")
                        host["status"] = "interrupted"
                        finish_phase(
                            credential_phase, "interrupted", "Credential testing interrupted."
                        )
                    except CredentialTestError as exc:
                        host["errors"].append(str(exc))
                        result = _credential_record(exc.outcome, args.ssh_user, ssh_port)
                        insert_credential_result(assessment_id, result, host_id=host_id)
                        finish_phase(credential_phase, exc.outcome, exc)
                        host["status"] = "partial"
                        print(f"[-] {target}: {exc}", file=sys.stderr)
                    except DatabaseError as exc:
                        host["errors"].append(str(exc))
                        finish_phase(credential_phase, "failed", exc)
                        host["status"] = "partial"
                        print(f"[-] {target}: {exc}", file=sys.stderr)

                if host["status"] != "interrupted":
                    finish_assessment_host(
                        host_id,
                        str(host["status"]),
                        "; ".join(host["errors"]) or None,
                    )
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
                shared_errors.append(str(exc))
                update_artifact_status(capture_artifact_id, "failed")
                finish_phase(capture_phase, "failed", exc)
                print(f"[-] {exc}", file=sys.stderr)
            except KeyboardInterrupt:
                interrupted = True
                shared_errors.append("Capture shutdown interrupted.")
                update_artifact_status(capture_artifact_id, "incomplete")
                finish_phase(capture_phase, "interrupted", "Capture shutdown interrupted.")

    if capture is None and not interrupted:
        for host in hosts:
            host_id = int(host["id"])
            reason = "Shared capture was unavailable; host processing was not started."
            recon_skip = start_phase(assessment_id, "reconnaissance", host_id)
            finish_phase(recon_skip, "skipped", reason)
            credential_skip = start_phase(assessment_id, "credential_testing", host_id)
            skipped_result = _credential_record("skipped", args.ssh_user, None)
            insert_credential_result(assessment_id, skipped_result, host_id=host_id)
            finish_phase(credential_skip, "skipped", reason)
            host["status"] = "failed"
            finish_assessment_host(host_id, "failed", reason)

    if interrupted:
        for host in hosts:
            if host["status"] == "running":
                host["status"] = "interrupted"
                host["errors"].append(
                    "Not processed because the assessment was interrupted."
                )
            if host["status"] == "interrupted":
                finish_assessment_host(
                    int(host["id"]),
                    "interrupted",
                    "; ".join(host["errors"]),
                )
        finish_assessment(assessment_id, status="interrupted")
        update_artifact_status(report_artifact_id, "incomplete")
        print("\n[!] Assessment interrupted")
        return 130

    if capture_available:
        print("\n[*] Parsing captured traffic...")
        parse_phase = start_phase(assessment_id, "pcap_parsing")
        try:
            packets = parse_pcap(paths.capture)
            parse_ok = True
            finish_phase(parse_phase, "completed")
            print(f"[+] {len(packets)} packets parsed")
        except KeyboardInterrupt:
            finish_phase(parse_phase, "interrupted", "PCAP parsing interrupted.")
            finish_assessment(assessment_id, status="interrupted")
            update_artifact_status(report_artifact_id, "incomplete")
            return 130
        except PcapParserError as exc:
            shared_errors.append(str(exc))
            finish_phase(parse_phase, "failed", exc)
            print(f"[-] {exc}", file=sys.stderr)

        if parse_ok:
            print("\n[*] Storing forensic data...")
            storage_phase = start_phase(assessment_id, "packet_storage")
            try:
                insert_packets(assessment_id, packets)
                packet_store_ok = True
                finish_phase(storage_phase, "completed")
                print(f"[+] Assessment stored in {DEFAULT_DATABASE_PATH}")
            except DatabaseError as exc:
                shared_errors.append(str(exc))
                finish_phase(storage_phase, "failed", exc)
                print(f"[-] {exc}", file=sys.stderr)
        else:
            storage_phase = start_phase(assessment_id, "packet_storage")
            finish_phase(storage_phase, "skipped", "PCAP parsing did not complete.")
    else:
        parse_phase = start_phase(assessment_id, "pcap_parsing")
        finish_phase(parse_phase, "skipped", "No available PCAP artifact.")
        storage_phase = start_phase(assessment_id, "packet_storage")
        finish_phase(storage_phase, "skipped", "No parsed packets were available.")

    host_statuses = [str(host["status"]) for host in hosts]
    required_shared_ok = capture_available and parse_ok and packet_store_ok
    useful_results = capture_available or any(
        status in {"completed", "partial"} for status in host_statuses
    )
    if required_shared_ok and all(status == "completed" for status in host_statuses):
        overall_status = "completed"
    elif useful_results:
        overall_status = "partial"
    else:
        overall_status = "failed"

    print("\n[*] Analyzing stored security evidence...")
    analysis_phase = start_phase(assessment_id, "security_analysis")
    try:
        finding_count = analyze_assessment(DEFAULT_DATABASE_PATH, assessment_id)
        finish_phase(analysis_phase, "completed")
        print(f"[+] {finding_count} new findings stored")
    except KeyboardInterrupt:
        finish_phase(analysis_phase, "interrupted", "Security analysis interrupted.")
        finish_assessment(assessment_id, status="interrupted")
        update_artifact_status(report_artifact_id, "incomplete")
        print("\n[!] Assessment interrupted")
        return 130
    except SecurityAnalysisError as exc:
        shared_errors.append(str(exc))
        finish_phase(analysis_phase, "failed", exc)
        if useful_results:
            overall_status = "partial"
        print(f"[-] {exc}", file=sys.stderr)

    finish_assessment(assessment_id, status=overall_status)

    print("\n[*] Structured service information:")
    print(json.dumps(all_services, indent=2))
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
        shared_errors.append(str(exc))
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
