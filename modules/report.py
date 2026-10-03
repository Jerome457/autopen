"""Generate a standalone HTML assessment report from AutoPen's SQLite data."""

from __future__ import annotations

import html
import sqlite3
from pathlib import Path
from typing import Any


DEFAULT_REPORT_PATH = Path("reports/report.html")
DEFAULT_PCAP_PATH = Path("data/capture.pcap")


class ReportError(RuntimeError):
    """Raised when an assessment report cannot be generated."""


def _escape(value: Any) -> str:
    if value is None or value == "":
        return "&mdash;"
    return html.escape(str(value), quote=True)


def _table_or_empty(
    headers: tuple[str, ...], rows: list[tuple[Any, ...]], empty_message: str
) -> str:
    if not rows:
        return f'<p class="empty">{html.escape(empty_message)}</p>'
    header_html = "".join(f"<th>{html.escape(header)}</th>" for header in headers)
    body_html = "".join(
        "<tr>" + "".join(f"<td>{_escape(value)}</td>" for value in row) + "</tr>"
        for row in rows
    )
    return (
        '<div class="table-wrap"><table><thead><tr>'
        f"{header_html}</tr></thead><tbody>{body_html}</tbody></table></div>"
    )


def _credential_table(credentials: list[sqlite3.Row]) -> str:
    if not credentials:
        return '<p class="empty">No credential testing results were recorded.</p>'
    rows = []
    for result in credentials:
        matched = bool(result["credential_found"])
        badge_class = "success" if matched else "neutral"
        label = "Credential matched" if matched else "No credential matched"
        badge = f'<span class="badge {badge_class}">{label}</span>'
        rows.append(
            "<tr>"
            f"<td>{_escape(result['service'])}</td>"
            f"<td>{_escape(result['port'])}</td>"
            f"<td>{_escape(result['username'])}</td>"
            f"<td>{badge}</td>"
            "</tr>"
        )
    return (
        '<div class="table-wrap"><table><thead><tr>'
        "<th>Service</th><th>Port</th><th>Username</th><th>Result</th>"
        f"</tr></thead><tbody>{''.join(rows)}</tbody></table></div>"
    )


def generate_report(
    database_path: Path,
    assessment_id: int,
    output_path: Path = DEFAULT_REPORT_PATH,
) -> Path:
    """Generate an offline HTML report for exactly one stored assessment."""
    database_path = Path(database_path)
    output_path = Path(output_path)
    if not database_path.is_file():
        raise ReportError(f"Database does not exist: {database_path}")

    try:
        with sqlite3.connect(database_path) as connection:
            connection.row_factory = sqlite3.Row
            assessment = connection.execute(
                """
                SELECT id, target, started_at, finished_at
                FROM assessments WHERE id = ?
                """,
                (assessment_id,),
            ).fetchone()
            if assessment is None:
                raise ReportError(f"Assessment {assessment_id} does not exist.")

            services = connection.execute(
                """
                SELECT port, protocol, state, service, version
                FROM services WHERE assessment_id = ? ORDER BY port, protocol
                """,
                (assessment_id,),
            ).fetchall()
            credentials = connection.execute(
                """
                SELECT service, port, username, credential_found
                FROM credential_results WHERE assessment_id = ? ORDER BY id
                """,
                (assessment_id,),
            ).fetchall()
            total_packets = connection.execute(
                "SELECT COUNT(*) FROM packets WHERE assessment_id = ?",
                (assessment_id,),
            ).fetchone()[0]
            protocol_rows = connection.execute(
                """
                SELECT protocol, COUNT(*) AS packet_count
                FROM packets WHERE assessment_id = ?
                GROUP BY protocol ORDER BY packet_count DESC, protocol
                """,
                (assessment_id,),
            ).fetchall()
            address_counts = connection.execute(
                """
                SELECT COUNT(DISTINCT src_ip), COUNT(DISTINCT dst_ip)
                FROM packets WHERE assessment_id = ?
                """,
                (assessment_id,),
            ).fetchone()
            connections = connection.execute(
                """
                SELECT src_ip, src_port, dst_ip, dst_port, protocol,
                       COUNT(*) AS packet_count
                FROM packets WHERE assessment_id = ?
                GROUP BY src_ip, src_port, dst_ip, dst_port, protocol
                ORDER BY packet_count DESC, protocol, src_ip, src_port
                LIMIT 10
                """,
                (assessment_id,),
            ).fetchall()
    except ReportError:
        raise
    except sqlite3.Error as exc:
        raise ReportError(f"Unable to query assessment data: {exc}") from exc

    service_rows = [
        tuple(row[column] for column in ("port", "protocol", "state", "service", "version"))
        for row in services
    ]
    protocol_table_rows = [
        (row["protocol"], row["packet_count"]) for row in protocol_rows
    ]
    connection_rows = [
        tuple(
            row[column]
            for column in (
                "src_ip",
                "src_port",
                "dst_ip",
                "dst_port",
                "protocol",
                "packet_count",
            )
        )
        for row in connections
    ]

    open_services = [row for row in services if str(row["state"]).lower() == "open"]
    ssh_services = [
        row
        for row in open_services
        if str(row["service"]).lower() == "ssh"
        and str(row["protocol"]).lower() == "tcp"
    ]
    matched_credentials = [row for row in credentials if row["credential_found"]]

    summary_items = [f"{len(open_services):,} open services were identified."]
    if ssh_services:
        ports = ", ".join(str(row["port"]) for row in ssh_services)
        summary_items.append(f"SSH was available on TCP port {ports}.")
    if credentials:
        if matched_credentials:
            summary_items.append(
                "The controlled SSH credential test matched a credential for the "
                "configured lab account."
            )
        else:
            summary_items.append(
                "The controlled SSH credential test did not match a credential."
            )
    else:
        summary_items.append("No credential test result was recorded.")
    summary_items.append(
        f"{total_packets:,} packets were captured and stored for forensic analysis."
    )

    service_table = _table_or_empty(
        ("Port", "Protocol", "State", "Service", "Version"),
        service_rows,
        "No services were recorded for this assessment.",
    )
    protocol_table = _table_or_empty(
        ("Protocol", "Packets"),
        protocol_table_rows,
        "No packet metadata was recorded for this assessment.",
    )
    connection_table = _table_or_empty(
        (
            "Source IP",
            "Source Port",
            "Destination IP",
            "Destination Port",
            "Protocol",
            "Packet Count",
        ),
        connection_rows,
        "No connections were available for this assessment.",
    )
    summary_html = "".join(f"<li>{html.escape(item)}</li>" for item in summary_items)

    document = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>AutoPen Assessment Report — #{_escape(assessment['id'])}</title>
  <style>
    :root {{ --ink:#172033; --muted:#667085; --line:#dfe5ee; --paper:#fff;
      --canvas:#f3f6fa; --accent:#185adb; --accent-soft:#eaf1ff;
      --success:#067647; --success-bg:#ecfdf3; --neutral:#475467; --neutral-bg:#f2f4f7; }}
    * {{ box-sizing:border-box; }}
    body {{ margin:0; color:var(--ink); background:var(--canvas);
      font-family:Arial,Helvetica,sans-serif; line-height:1.5; }}
    .page {{ width:min(1120px,calc(100% - 32px)); margin:32px auto; }}
    .hero {{ padding:34px; border-radius:16px; color:#fff;
      background:linear-gradient(135deg,#102a56,#185adb); box-shadow:0 14px 38px #1d29391c; }}
    .eyebrow {{ margin:0 0 7px; font-size:12px; font-weight:700; letter-spacing:.14em; opacity:.8; }}
    h1 {{ margin:0; font-size:clamp(28px,5vw,44px); letter-spacing:-.03em; }}
    .subtitle {{ margin:8px 0 0; color:#dce8ff; }}
    .meta,.stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:14px; margin-top:18px; }}
    .meta-card,.stat {{ padding:16px; border:1px solid var(--line); border-radius:12px; background:var(--paper); }}
    .label {{ display:block; color:var(--muted); font-size:12px; font-weight:700; letter-spacing:.06em; text-transform:uppercase; }}
    .value {{ display:block; margin-top:5px; font-size:16px; font-weight:700; overflow-wrap:anywhere; }}
    .stat .value {{ font-size:26px; color:var(--accent); }}
    section {{ margin-top:20px; padding:24px; border:1px solid var(--line); border-radius:14px;
      background:var(--paper); box-shadow:0 5px 18px #1d29390a; }}
    h2 {{ margin:0 0 16px; font-size:18px; letter-spacing:.03em; }}
    .table-wrap {{ overflow-x:auto; }}
    table {{ width:100%; border-collapse:collapse; font-size:14px; }}
    th {{ padding:11px 12px; color:#344054; background:#f7f9fc; text-align:left; border-bottom:1px solid var(--line); }}
    td {{ padding:11px 12px; border-bottom:1px solid #edf0f5; vertical-align:top; }}
    tbody tr:nth-child(even) {{ background:#fbfcfe; }}
    .badge {{ display:inline-block; padding:4px 9px; border-radius:999px; font-size:12px; font-weight:700; }}
    .badge.success {{ color:var(--success); background:var(--success-bg); }}
    .badge.neutral {{ color:var(--neutral); background:var(--neutral-bg); }}
    .empty {{ margin:0; padding:14px; color:var(--muted); background:#f8fafc; border-radius:9px; }}
    .summary {{ margin:0; padding-left:21px; }} .summary li+li {{ margin-top:8px; }}
    .artifacts code {{ color:#273b64; overflow-wrap:anywhere; }}
    footer {{ padding:25px 0 8px; text-align:center; color:var(--muted); font-size:13px; }}
    @media (max-width:760px) {{ .meta,.stats {{ grid-template-columns:1fr 1fr; }} .hero {{ padding:24px; }} }}
    @media (max-width:480px) {{ .page {{ width:min(100% - 18px,1120px); margin:9px auto; }}
      .meta,.stats {{ grid-template-columns:1fr; }} section {{ padding:17px; }} }}
  </style>
</head>
<body>
<main class="page">
  <header class="hero">
    <p class="eyebrow">AUTOMATED SECURITY ASSESSMENT</p>
    <h1>AutoPen Assessment Report</h1>
    <p class="subtitle">Consolidated reconnaissance, credential-testing, and traffic-forensics results.</p>
  </header>

  <div class="meta" aria-label="Assessment metadata">
    <div class="meta-card"><span class="label">Assessment ID</span><span class="value">{_escape(assessment['id'])}</span></div>
    <div class="meta-card"><span class="label">Target IP</span><span class="value">{_escape(assessment['target'])}</span></div>
    <div class="meta-card"><span class="label">Started</span><span class="value">{_escape(assessment['started_at'])}</span></div>
    <div class="meta-card"><span class="label">Finished</span><span class="value">{_escape(assessment['finished_at'])}</span></div>
  </div>

  <div class="stats" aria-label="Traffic statistics">
    <div class="stat"><span class="label">Open services</span><span class="value">{len(open_services):,}</span></div>
    <div class="stat"><span class="label">Total packets</span><span class="value">{total_packets:,}</span></div>
    <div class="stat"><span class="label">Source IPs</span><span class="value">{address_counts[0]:,}</span></div>
    <div class="stat"><span class="label">Destination IPs</span><span class="value">{address_counts[1]:,}</span></div>
  </div>

  <section><h2>Reconnaissance</h2>{service_table}</section>
  <section><h2>Credential Testing</h2>{_credential_table(credentials)}</section>
  <section><h2>Traffic Forensics</h2>{protocol_table}</section>
  <section><h2>Top Connections</h2>{connection_table}</section>
  <section><h2>Security / Assessment Summary</h2><ul class="summary">{summary_html}</ul></section>
  <section class="artifacts"><h2>Artifacts</h2>
    <p><strong>PCAP:</strong> <code>{_escape(DEFAULT_PCAP_PATH)}</code></p>
    <p><strong>Database:</strong> <code>{_escape(database_path)}</code></p>
    <p><strong>Report:</strong> <code>{_escape(output_path)}</code></p>
  </section>
  <footer>Generated by AutoPen · Offline standalone report</footer>
</main>
</body>
</html>
"""

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(document, encoding="utf-8")
    except OSError as exc:
        raise ReportError(f"Unable to write report {output_path}: {exc}") from exc
    return output_path
