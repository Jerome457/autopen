"""Deterministic security findings derived from stored AutoPen observations."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from modules.database import (
    DEFAULT_DATABASE_PATH,
    DatabaseError,
    initialize_database,
    insert_findings,
)


SSH_CREDENTIAL_ACCEPTED = "AUTOPEN.SSH.CREDENTIAL_ACCEPTED"
CLEARTEXT_REMOTE_ACCESS = "AUTOPEN.REMOTE_ACCESS.CLEARTEXT_POTENTIAL"
HTTP_TRANSPORT_REVIEW = "AUTOPEN.HTTP.TRANSPORT_REVIEW"
SERVICE_EXPOSURE = "AUTOPEN.SERVICE.EXPOSURE_OBSERVED"


class SecurityAnalysisError(RuntimeError):
    """Raised when stored assessment data cannot be analyzed."""


def _is_plain_ftp(name: str) -> bool:
    return name == "ftp"


def _is_plain_telnet(name: str) -> bool:
    return name == "telnet"


def _is_plain_http(name: str) -> bool:
    return (name == "http" or name.startswith("http-")) and not any(
        marker in name for marker in ("https", "ssl", "tls")
    )


def _service_finding(service: sqlite3.Row, target: str) -> dict[str, Any]:
    name = str(service["service"]).strip().lower()
    evidence = {
        "host": target,
        "port": service["port"],
        "protocol": service["protocol"],
        "service": service["service"],
        "service_id": service["id"],
        "version": service["version"],
    }
    base = {
        "host_id": service["host_id"],
        "service_id": service["id"],
        "dedupe_key": f"service:{service['id']}",
        "evidence": evidence,
    }
    if _is_plain_ftp(name) or _is_plain_telnet(name):
        protocol_name = "FTP" if _is_plain_ftp(name) else "Telnet"
        ftp_uncertainty = (
            " TLS may be available or required by the FTP service, but that was not tested."
            if protocol_name == "FTP"
            else ""
        )
        return {
            **base,
            "rule_id": CLEARTEXT_REMOTE_ACCESS,
            "title": f"Potential cleartext {protocol_name} remote-access service",
            "severity": "medium",
            "confidence": "medium",
            "evidence_state": "potential_issue",
            "description": (
                f"The service was positively identified as {protocol_name}. This protocol can "
                "expose credentials or content when used without transport protection."
                f"{ftp_uncertainty} No plaintext credentials were observed."
            ),
            "impact": (
                "If unprotected authentication or data transfer is permitted, parties able to "
                "observe the traffic could read that information."
            ),
            "remediation": (
                "Verify the service's transport protection. Use an encrypted alternative or "
                "enforce TLS as appropriate, and restrict access to authorized systems."
            ),
        }
    if _is_plain_http(name):
        return {
            **base,
            "rule_id": HTTP_TRANSPORT_REVIEW,
            "title": "HTTP service observed; transport protection requires review",
            "severity": "low",
            "confidence": "medium",
            "evidence_state": "potential_issue",
            "description": (
                "A service was positively identified as plain HTTP. Redirect behavior, "
                "authentication, sensitive content, and TLS enforcement were not tested. "
                "No sensitive information is claimed to have been transmitted."
            ),
            "impact": (
                "Sensitive interactions could lack confidentiality or integrity if they are "
                "actually permitted over unprotected HTTP."
            ),
            "remediation": (
                "Verify that sensitive interactions use HTTPS and that HTTP is redirected or "
                "restricted appropriately."
            ),
        }
    return {
        **base,
        "rule_id": SERVICE_EXPOSURE,
        "title": f"{service['service']} service exposure observed",
        "severity": "informational",
        "confidence": "high",
        "evidence_state": "confirmed_observation",
        "description": (
            "Reconnaissance observed this open service as reachable from the assessment "
            "machine. Service reachability is not itself proof of a vulnerability, and no "
            "internet accessibility is implied."
        ),
        "impact": (
            "The service adds reachable functionality that may require operational and access "
            "control review; no security impact was established by discovery alone."
        ),
        "remediation": (
            "Confirm that the service is necessary, maintained, and restricted to appropriate "
            "clients and networks."
        ),
    }


def analyze_assessment(
    database_path: Path = DEFAULT_DATABASE_PATH,
    assessment_id: int | None = None,
) -> int:
    """Analyze one stored assessment and return the number of newly inserted findings."""
    if assessment_id is None:
        raise SecurityAnalysisError("An assessment ID is required for security analysis.")
    database_path = Path(database_path)
    try:
        initialize_database(database_path)
        with sqlite3.connect(database_path) as connection:
            connection.row_factory = sqlite3.Row
            assessment = connection.execute(
                "SELECT id FROM assessments WHERE id=?", (assessment_id,)
            ).fetchone()
            if assessment is None:
                raise SecurityAnalysisError(
                    f"Assessment {assessment_id} does not exist."
                )
            services = connection.execute(
                """SELECT s.id,s.assessment_id,s.host_id,s.port,s.protocol,s.state,
                          s.service,s.version,h.target
                   FROM services AS s
                   JOIN assessment_hosts AS h
                     ON h.id=s.host_id AND h.assessment_id=s.assessment_id
                   WHERE s.assessment_id=? AND lower(s.state)='open'
                   ORDER BY s.id""",
                (assessment_id,),
            ).fetchall()
            credentials = connection.execute(
                """SELECT c.id,c.host_id,c.port,c.username,h.target
                   FROM credential_results AS c
                   JOIN assessment_hosts AS h
                     ON h.id=c.host_id AND h.assessment_id=c.assessment_id
                   WHERE c.assessment_id=? AND c.outcome='matched'
                   ORDER BY c.id""",
                (assessment_id,),
            ).fetchall()
    except SecurityAnalysisError:
        raise
    except (sqlite3.Error, DatabaseError) as exc:
        raise SecurityAnalysisError(f"Unable to analyze stored assessment data: {exc}") from exc

    findings: list[dict[str, Any]] = []
    represented_service_ids: set[int] = set()
    for credential in credentials:
        service = next(
            (
                item
                for item in services
                if item["host_id"] == credential["host_id"]
                and item["port"] == credential["port"]
                and str(item["service"]).lower() == "ssh"
            ),
            None,
        )
        service_id = service["id"] if service is not None else None
        if service_id is not None:
            represented_service_ids.add(service_id)
        findings.append({
            "host_id": credential["host_id"],
            "service_id": service_id,
            "rule_id": SSH_CREDENTIAL_ACCEPTED,
            "dedupe_key": f"credential_result:{credential['id']}",
            "title": "SSH login succeeded using supplied test credentials",
            "severity": "high",
            "confidence": "high",
            "evidence_state": "confirmed_observation",
            "description": (
                "The explicitly supplied candidate list contained a credential accepted by "
                "the SSH service. This does not establish that the password was default, "
                "commonly used, reused, or obtained without prior knowledge."
            ),
            "evidence": {
                "host": credential["target"],
                "port": credential["port"],
                "username": credential["username"],
                "credential_result_id": credential["id"],
                "service_id": service_id,
            },
            "impact": (
                "The supplied credential permitted account access. Account privileges were "
                "not established and remain unknown."
            ),
            "remediation": (
                "Replace deliberately weak lab credentials. Consider key-based authentication "
                "and appropriate network and account access restrictions."
            ),
        })

    for service in services:
        if service["id"] in represented_service_ids:
            continue
        finding = _service_finding(service, service["target"])
        findings.append(finding)

    try:
        return insert_findings(assessment_id, findings, database_path)
    except DatabaseError as exc:
        raise SecurityAnalysisError(f"Unable to store security findings: {exc}") from exc
