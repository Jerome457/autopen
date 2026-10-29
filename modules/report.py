"""Generate a standalone, offline HTML assessment report from SQLite evidence."""

from __future__ import annotations

import html
import ipaddress
import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

DEFAULT_REPORT_PATH = Path("reports/report.html")
DEFAULT_PCAP_PATH = Path("data/capture.pcap")
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "informational": 3}


class ReportError(RuntimeError):
    """Raised when an assessment report cannot be generated."""


def _escape(value: Any) -> str:
    if value is None or value == "":
        return "&mdash;"
    return html.escape(str(value), quote=True)


def _table_or_empty(
    headers: tuple[str, ...], rows: Iterable[tuple[Any, ...]], empty_message: str
) -> str:
    rows = list(rows)
    if not rows:
        return f'<p class="empty">{html.escape(empty_message)}</p>'
    header = "".join(f"<th>{html.escape(item)}</th>" for item in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_escape(value)}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return f'<div class="table-wrap"><table><thead><tr>{header}</tr></thead><tbody>{body}</tbody></table></div>'


def _normalize_ip(value: Any) -> str | None:
    """Normalize an IP value; missing and non-IP addresses are ignored."""
    if value is None:
        return None
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return None


def _timestamp(value: Any) -> datetime | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        try:
            parsed = datetime.fromtimestamp(float(text), timezone.utc)
        except (ValueError, OverflowError, OSError):
            return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(timezone.utc)


def _packet_length(packet: sqlite3.Row) -> int:
    try:
        return max(int(packet["length"] or 0), 0)
    except (TypeError, ValueError):
        return 0


def _connection_rows(
    packets: Iterable[sqlite3.Row], limit: int = 10
) -> list[tuple[Any, ...]]:
    counts: Counter[tuple[Any, ...]] = Counter()
    for packet in packets:
        source = _normalize_ip(packet["src_ip"])
        destination = _normalize_ip(packet["dst_ip"])
        if source is None or destination is None:
            continue
        counts[(source, packet["src_port"], destination, packet["dst_port"], packet["protocol"])] += 1
    return [(*key, count) for key, count in counts.most_common(limit)]


def _host_traffic(target: str, packets: list[sqlite3.Row]) -> dict[str, Any]:
    target_ip = _normalize_ip(target)
    involved: list[sqlite3.Row] = []
    sent = received = 0
    if target_ip is not None:
        for packet in packets:
            source = _normalize_ip(packet["src_ip"])
            destination = _normalize_ip(packet["dst_ip"])
            is_sent = source == target_ip
            is_received = destination == target_ip
            if is_sent or is_received:
                involved.append(packet)
            sent += int(is_sent)
            received += int(is_received)
    return {
        "packets": len(involved),
        "bytes": sum(_packet_length(packet) for packet in involved),
        "sent": sent,
        "received": received,
        "protocols": sorted({str(packet["protocol"]) for packet in involved if packet["protocol"]}),
        "connections": _connection_rows(involved, 5),
    }


def _phase_status(phases: list[sqlite3.Row], name: str) -> tuple[str, str | None]:
    matches = [row for row in phases if row["phase_name"] == name]
    if not matches:
        return "unknown", None
    return str(matches[-1]["status"]), matches[-1]["error_summary"]


def _credential_phase(phases: list[sqlite3.Row], host_id: int) -> sqlite3.Row | None:
    matches = [
        row for row in phases
        if row["host_id"] == host_id and row["phase_name"] == "credential_testing"
    ]
    return matches[-1] if matches else None


def _supporting_traffic(
    finding: sqlite3.Row,
    service: sqlite3.Row | None,
    host_target: str,
    packets: list[sqlite3.Row],
    phases: list[sqlite3.Row],
) -> str:
    """Correlate target-side service traffic without inferring an outcome."""
    if service is None:
        return "No service reference is available for packet correlation."
    target = _normalize_ip(host_target)
    if target is None:
        return "No matching packets in stored capture metadata."
    protocol = str(service["protocol"] or "").upper()
    port = service["port"]
    matched = []
    for packet in packets:
        source = _normalize_ip(packet["src_ip"])
        destination = _normalize_ip(packet["dst_ip"])
        if str(packet["protocol"] or "").upper() != protocol:
            continue
        if ((destination == target and packet["dst_port"] == port)
                or (source == target and packet["src_port"] == port)):
            matched.append(packet)

    label = "Assessment-wide service traffic"
    phase_specific = False
    if finding["rule_id"] == "AUTOPEN.SSH.CREDENTIAL_ACCEPTED":
        phase = _credential_phase(phases, finding["host_id"])
        if phase is not None and phase["status"] == "completed":
            started, finished = _timestamp(phase["started_at"]), _timestamp(phase["finished_at"])
            packet_times = [_timestamp(packet["timestamp"]) for packet in matched]
            timestamps_suitable = not matched or all(value is not None for value in packet_times)
            if started is not None and finished is not None and started <= finished and timestamps_suitable:
                matched = [
                    packet for packet, packet_time in zip(matched, packet_times)
                    if packet_time is not None
                    and started <= packet_time <= finished
                ]
                label = "Traffic observed during the credential-test phase"
                phase_specific = True

    if matched:
        detail = f"{label}: {len(matched):,} packets / {sum(_packet_length(row) for row in matched):,} bytes."
    else:
        detail = f"{label}: No matching packets in stored capture metadata."
    if finding["rule_id"] == "AUTOPEN.SSH.CREDENTIAL_ACCEPTED":
        if not phase_specific:
            detail += " Phase timestamps were unavailable or unsuitable, so assessment-wide service traffic was used."
        detail += (
            " The credential tool result establishes the accepted login; encrypted SSH packet metadata "
            "only corroborates traffic and does not reveal authentication content."
        )
    return detail


def _credential_table(
    credentials: list[sqlite3.Row], phases: list[sqlite3.Row], host_id: int
) -> str:
    if not credentials:
        return '<p class="empty">No credential testing results were recorded.</p>'
    labels = {
        "matched": "Credential matched", "no_match": "No credential matched",
        "skipped": "Skipped", "failed": "Failed", "timed_out": "Timed out",
    }
    phase = _credential_phase(phases, host_id)
    reason = phase["error_summary"] if phase is not None else None
    rows = [(
        row["service"], row["port"], row["username"], labels.get(row["outcome"], row["outcome"]),
        reason if row["outcome"] in {"skipped", "failed", "timed_out"} else None,
    ) for row in credentials]
    return _table_or_empty(("Service", "Port", "Username", "Outcome", "Reason"), rows, "No credential testing results were recorded.")


def _finding_priority(findings: list[sqlite3.Row], analysis: str, assessed: bool) -> str:
    if not assessed:
        return "Host not assessed"
    if analysis != "completed":
        return "Analysis unavailable or incomplete"
    priorities = [row["severity"] for row in findings if row["severity"] != "informational"]
    if not priorities:
        return "No non-informational findings generated"
    return min(priorities, key=lambda value: SEVERITY_ORDER[value]).title()


def _findings_output(
    findings: list[sqlite3.Row], services: dict[int, sqlite3.Row], host_target: str,
    packets: list[sqlite3.Row], phases: list[sqlite3.Row], analysis: str, assessed: bool,
) -> str:
    if not findings:
        if not assessed:
            message = "Host not assessed; no finding conclusion is available."
        elif analysis != "completed":
            message = "Analysis unavailable or incomplete; absence of findings is not a security conclusion."
        else:
            message = "No non-informational findings generated. No findings does not establish that the system is secure."
        return f'<p class="empty">{html.escape(message)}</p>'
    cards = []
    for finding in sorted(findings, key=lambda row: (SEVERITY_ORDER[row["severity"]], row["id"])):
        try:
            evidence = json.dumps(json.loads(finding["evidence"]), indent=2, sort_keys=True)
        except (TypeError, ValueError):
            evidence = str(finding["evidence"])
        traffic = _supporting_traffic(
            finding, services.get(finding["service_id"]), host_target, packets, phases
        )
        cards.append(
            '<article class="finding">'
            f"<h4>{_escape(finding['title'])}</h4>"
            f'<p><span class="badge severity-{_escape(finding["severity"])}">{_escape(finding["severity"])}</span> '
            f"<strong>Confidence:</strong> {_escape(finding['confidence'])} · <strong>Evidence state:</strong> {_escape(finding['evidence_state'])}</p>"
            f"<p>{_escape(finding['description'])}</p><h5>Supporting evidence</h5><pre>{_escape(evidence)}</pre>"
            f'<p class="traffic-evidence"><strong>Traffic correlation:</strong> {_escape(traffic)}</p>'
            f"<h5>Impact</h5><p>{_escape(finding['impact'])}</p><h5>Remediation</h5><p>{_escape(finding['remediation'])}</p>"
            "</article>"
        )
    return "".join(cards)


def _relative_link(path: Any, output_path: Path) -> str:
    try:
        result = os.path.relpath(Path(str(path)).resolve(), output_path.parent.resolve())
    except (OSError, ValueError):
        result = str(path)
    return result.replace(os.sep, "/")


def generate_report(
    database_path: Path,
    assessment_id: int,
    output_path: Path = DEFAULT_REPORT_PATH,
    report_notice: str | None = None,
) -> Path:
    """Generate one offline report from a single stored assessment."""
    database_path, output_path = Path(database_path), Path(output_path)
    if not database_path.is_file():
        raise ReportError(f"Database does not exist: {database_path}")
    try:
        with sqlite3.connect(database_path) as connection:
            connection.row_factory = sqlite3.Row
            assessment = connection.execute(
                "SELECT id,target,started_at,finished_at,status FROM assessments WHERE id=?", (assessment_id,)
            ).fetchone()
            if assessment is None:
                raise ReportError(f"Assessment {assessment_id} does not exist.")
            hosts = connection.execute("SELECT id,target,interface,status,started_at,finished_at,error_summary FROM assessment_hosts WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()
            services = connection.execute("SELECT id,host_id,port,protocol,state,service,version FROM services WHERE assessment_id=? ORDER BY host_id,port,protocol", (assessment_id,)).fetchall()
            credentials = connection.execute("SELECT id,host_id,service,port,username,outcome,credential_found FROM credential_results WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()
            packets = connection.execute("SELECT id,timestamp,src_ip,dst_ip,protocol,src_port,dst_port,length FROM packets WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()
            phases = connection.execute("SELECT id,host_id,phase_name,status,started_at,finished_at,error_summary FROM assessment_phases WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()
            artifacts = connection.execute("SELECT artifact_type,path,status FROM artifacts WHERE assessment_id=? ORDER BY id", (assessment_id,)).fetchall()
            findings = connection.execute("SELECT id,host_id,service_id,rule_id,title,severity,confidence,evidence_state,description,evidence,impact,remediation FROM findings WHERE assessment_id=? ORDER BY host_id,id", (assessment_id,)).fetchall()
    except ReportError:
        raise
    except sqlite3.Error as exc:
        raise ReportError(f"Unable to query assessment data: {exc}") from exc

    if not hosts:
        hosts = [{"id": -1, "target": assessment["target"], "interface": None,
                  "status": "legacy_unknown", "started_at": assessment["started_at"],
                  "finished_at": assessment["finished_at"], "error_summary": None}]
    service_by_id = {row["id"]: row for row in services}
    artifact_by_type = {row["artifact_type"]: row for row in artifacts}
    analysis_status, analysis_error = _phase_status(phases, "security_analysis")
    capture_status, capture_error = _phase_status(phases, "capture")
    parsing_status, parsing_error = _phase_status(phases, "pcap_parsing")
    storage_status, storage_error = _phase_status(phases, "packet_storage")
    severity_counts = {value: sum(row["severity"] == value for row in findings) for value in SEVERITY_ORDER}
    status_counts = Counter(str(host["status"]) for host in hosts)
    unprocessed = sum("not processed" in str(host["error_summary"] or "").lower() for host in hosts)

    summary_rows, host_sections = [], []
    for host in hosts:
        host_id = host["id"]
        if host_id == -1:
            host_services = [row for row in services if row["host_id"] is None]
            host_credentials = [row for row in credentials if row["host_id"] is None]
        else:
            host_services = [row for row in services if row["host_id"] == host_id]
            host_credentials = [row for row in credentials if row["host_id"] == host_id]
        host_findings = [row for row in findings if row["host_id"] == host_id]
        assessed = not (host["status"] == "running" or "not processed" in str(host["error_summary"] or "").lower())
        counts = Counter(row["severity"] for row in host_findings)
        priority = _finding_priority(host_findings, analysis_status, assessed)
        outcomes = ", ".join(dict.fromkeys(str(row["outcome"]) for row in host_credentials)) or "not recorded"
        open_count = sum(str(row["state"]).lower() == "open" for row in host_services)
        summary_rows.append((host["target"], host["status"], open_count, outcomes, counts["high"], counts["medium"], counts["low"], counts["informational"], priority))
        traffic = _host_traffic(host["target"], packets)
        service_table = _table_or_empty(
            ("Port", "Protocol", "State", "Service", "Version"),
            [tuple(row[key] for key in ("port", "protocol", "state", "service", "version")) for row in host_services],
            "No services were recorded for this host.",
        )
        host_connections = _table_or_empty(
            ("Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Packets"),
            traffic["connections"], "No matching host connections were found in stored packet metadata."
        )
        host_sections.append(
            '<section class="host-result">'
            f"<h2>Host: {_escape(host['target'])}</h2><p><strong>Execution status:</strong> {_escape(host['status'])} · <strong>Finding priority:</strong> {_escape(priority)}</p>"
            f"<p><strong>Execution detail:</strong> {_escape(host['error_summary'])}</p>"
            f"<h3>Services and versions</h3>{service_table}"
            f"<h3>Credential testing</h3>{_credential_table(host_credentials, phases, host_id)}"
            f"<h3>Host traffic summary</h3><p>{traffic['packets']:,} packets / {traffic['bytes']:,} bytes; sent: {traffic['sent']:,}; received: {traffic['received']:,}; observed protocols: {_escape(', '.join(traffic['protocols']) or 'none')}.</p>{host_connections}"
            f"<h3>Security findings</h3>{_findings_output(host_findings, service_by_id, host['target'], packets, phases, analysis_status, assessed)}</section>"
        )

    host_summary = _table_or_empty(
        ("Target", "Execution Status", "Open Services", "Credential Outcomes", "High", "Medium", "Low", "Info", "Highest Finding Priority"),
        summary_rows, "No hosts were recorded for this assessment."
    )
    total_bytes = sum(_packet_length(row) for row in packets)
    protocol_counts: dict[str, list[int]] = {}
    for packet in packets:
        values = protocol_counts.setdefault(str(packet["protocol"] or "UNKNOWN"), [0, 0])
        values[0] += 1
        values[1] += _packet_length(packet)
    protocol_table = _table_or_empty(
        ("Protocol", "Packets", "Bytes"),
        [(name, values[0], values[1]) for name, values in sorted(protocol_counts.items(), key=lambda item: (-item[1][0], item[0]))],
        "No packet metadata was recorded for this assessment."
    )
    connection_table = _table_or_empty(
        ("Source IP", "Source Port", "Destination IP", "Destination Port", "Protocol", "Packets"),
        _connection_rows(packets), "No connections were available for this assessment."
    )
    coverage_table = _table_or_empty(
        ("Stage", "Coverage Status", "Failure / limitation"),
        [("Capture", capture_status, capture_error), ("PCAP parsing", parsing_status, parsing_error),
         ("Packet storage", storage_status, storage_error), ("Security analysis", analysis_status, analysis_error)],
        "Coverage is unknown."
    )

    artifact_rows = []
    for kind in ("pcap", "report"):
        artifact = artifact_by_type.get(kind)
        if kind == "report":
            path, status = output_path, "generated"
        elif artifact is not None:
            path, status = Path(artifact["path"]), artifact["status"]
        else:
            path, status = DEFAULT_PCAP_PATH, "legacy/unknown"
        href = _relative_link(path, output_path)
        artifact_rows.append(f'<tr><td>{_escape(kind.upper())}</td><td>{_escape(status)}</td><td><a href="{_escape(href)}">{_escape(path)}</a></td></tr>')
    db_href = _relative_link(database_path, output_path)
    artifact_rows.append(f'<tr><td>Database</td><td>available</td><td><a href="{_escape(db_href)}">{_escape(database_path)}</a></td></tr>')
    artifacts_table = f'<div class="table-wrap"><table><thead><tr><th>Artifact</th><th>Status</th><th>Path</th></tr></thead><tbody>{"".join(artifact_rows)}</tbody></table></div>'

    targets = {_normalize_ip(host["target"]) for host in hosts if _normalize_ip(host["target"])}
    observed = {address for packet in packets for address in (_normalize_ip(packet["src_ip"]), _normalize_ip(packet["dst_ip"])) if address}
    host_status_label = ", ".join(dict.fromkeys(str(row[1]) for row in summary_rows))
    document = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutoPen Assessment Report — #{_escape(assessment['id'])}</title><style>
:root{{--ink:#172033;--muted:#667085;--line:#dfe5ee;--paper:#fff;--canvas:#f3f6fa;--accent:#185adb}}*{{box-sizing:border-box}}body{{margin:0;color:var(--ink);background:var(--canvas);font:15px/1.5 Arial,sans-serif}}.page{{width:min(1180px,calc(100% - 30px));margin:28px auto}}.hero{{padding:32px;border-radius:16px;color:#fff;background:linear-gradient(135deg,#102a56,#185adb)}}.eyebrow{{margin:0 0 7px;font-size:12px;font-weight:700;letter-spacing:.14em}}h1{{margin:0;font-size:40px}}.subtitle{{color:#dce8ff}}.synthetic{{margin:14px 0 0;padding:12px;border:2px solid #b54708;border-radius:9px;color:#7a2e0e;background:#fffaeb;font-weight:700}}.grid,.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-top:16px}}.card,.stat,section{{background:var(--paper);border:1px solid var(--line);border-radius:12px}}.card,.stat{{padding:15px}}section{{margin-top:18px;padding:22px}}.label{{display:block;color:var(--muted);font-size:11px;font-weight:700;text-transform:uppercase}}.value{{display:block;margin-top:4px;font-size:18px;font-weight:700;overflow-wrap:anywhere}}.stat .value{{color:var(--accent);font-size:25px}}h2{{margin:0 0 14px}}h3{{margin:22px 0 10px}}h4,h5{{margin:0 0 8px}}.table-wrap{{overflow-x:auto}}table{{width:100%;border-collapse:collapse;font-size:13px}}th,td{{padding:10px;border-bottom:1px solid #edf0f5;text-align:left;vertical-align:top}}th{{background:#f7f9fc}}tbody tr:nth-child(even){{background:#fbfcfe}}.empty,.notice{{padding:13px;color:var(--muted);background:#f8fafc;border-radius:8px}}.badge{{display:inline-block;padding:3px 8px;border-radius:999px;font-weight:700;text-transform:capitalize}}.severity-high{{color:#b42318;background:#fef3f2}}.severity-medium{{color:#b54708;background:#fffaeb}}.severity-low{{color:#175cd3;background:#eff8ff}}.severity-informational{{color:#475467;background:#f2f4f7}}.finding{{margin-top:14px;padding:16px;border:1px solid var(--line);border-radius:10px;break-inside:avoid}}pre{{padding:12px;overflow:auto;white-space:pre-wrap;background:#f7f9fc;border-radius:8px}}.traffic-evidence{{padding:11px;background:#eef4ff;border-left:4px solid var(--accent)}}a{{color:#175cd3;overflow-wrap:anywhere}}footer{{padding:24px;text-align:center;color:var(--muted)}}@media(max-width:760px){{.grid,.stats{{grid-template-columns:1fr 1fr}}h1{{font-size:30px}}}}@media(max-width:480px){{.grid,.stats{{grid-template-columns:1fr}}.page{{width:calc(100% - 14px);margin:7px auto}}}}@media print{{body{{background:#fff}}.page{{width:100%;margin:0}}section,.card,.stat{{box-shadow:none}}a{{color:inherit;text-decoration:none}}}}
</style></head><body><main class="page">
<header class="hero"><p class="eyebrow">AUTOMATED SECURITY ASSESSMENT</p><h1>AutoPen Assessment Report</h1><p class="subtitle">Consolidated execution, findings, and traffic-evidence report.</p></header>
{f'<p class="synthetic">{_escape(report_notice)}</p>' if report_notice else ''}
<section><h2>Assessment Overview</h2><div class="grid">
<div class="card"><span class="label">Assessment ID</span><span class="value">{_escape(assessment['id'])}</span></div><div class="card"><span class="label">Assessment status</span><span class="value">{_escape(assessment['status'])}</span></div><div class="card"><span class="label">Started</span><span class="value">{_escape(assessment['started_at'])}</span></div><div class="card"><span class="label">Finished</span><span class="value">{_escape(assessment['finished_at'])}</span></div><div class="card"><span class="label">Total targets requested</span><span class="value">{len(hosts)}</span></div><div class="card"><span class="label">Completed</span><span class="value">{status_counts['completed']}</span></div><div class="card"><span class="label">Failed</span><span class="value">{status_counts['failed']}</span></div><div class="card"><span class="label">Interrupted / unprocessed</span><span class="value">{status_counts['interrupted']} / {unprocessed}</span></div><div class="card"><span class="label">Host status</span><span class="value">{_escape(host_status_label)}</span></div></div>
<div class="stats"><div class="stat"><span class="label">High findings</span><span class="value">{severity_counts['high']}</span></div><div class="stat"><span class="label">Medium findings</span><span class="value">{severity_counts['medium']}</span></div><div class="stat"><span class="label">Low findings</span><span class="value">{severity_counts['low']}</span></div><div class="stat"><span class="label">Informational observations</span><span class="value">{severity_counts['informational']}</span></div></div><h3>Collection and analysis coverage</h3>{coverage_table}</section>
<section><h2>Host Comparison / Host Summary</h2>{host_summary}</section>{''.join(host_sections)}
<section><h2>Assessment-wide Traffic Forensics / Summary</h2><div class="stats"><div class="stat"><span class="label">Total packets</span><span class="value">{len(packets):,}</span></div><div class="stat"><span class="label">Total bytes</span><span class="value">{total_bytes:,}</span></div><div class="stat"><span class="label">Observed IP addresses</span><span class="value">{len(observed):,}</span></div><div class="stat"><span class="label">Targets represented</span><span class="value">{len(targets & observed):,}</span></div></div><p>{len(packets):,} packets were captured and stored as packet metadata for this assessment.</p><h3>Protocol distribution</h3>{protocol_table}<h3>Top Connections</h3>{connection_table}<p class="notice">Host traffic totals may overlap when a packet involves two assessed targets and therefore must not be summed to obtain assessment totals. Packet metadata does not by itself prove reachability, authentication success, or malicious activity.</p></section>
<section><h2>Artifacts</h2>{artifacts_table}</section><section><h2>Scope, Methodology, and Limitations</h2><ul><li>Testing was limited to explicitly supplied targets and the configured lab interface.</li><li>Severities are project-defined finding priorities, not CVSS scores. Execution status and security severity are independent.</li><li>No findings or no open services does not establish that a host is secure, reachable, or fully assessed.</li><li>Service versions alone are not proof of a vulnerability or CVE applicability.</li><li>Traffic correlation uses stored IP addresses, transport metadata, ports, and available phase timestamps. Missing or unsuitable timestamps reduce correlation precision.</li><li>Encrypted SSH metadata cannot reveal whether authentication succeeded; the credential tool result is the authoritative evidence for a matched test credential.</li><li>Capture and parsing failures, filters, encryption, and incomplete traffic visibility can limit stored evidence. Unknown legacy coverage remains unknown.</li></ul></section><footer>Generated by AutoPen · Offline standalone report · Assessment #{_escape(assessment['id'])}</footer>
</main></body></html>"""
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(document, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Unable to write report {output_path}: {exc}") from exc
    return output_path
