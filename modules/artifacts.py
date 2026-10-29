"""Deterministic, non-overwriting artifact paths for an assessment."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class AssessmentArtifactPaths:
    capture: Path
    report: Path


def assessment_artifact_paths(assessment_id: int) -> AssessmentArtifactPaths:
    """Return unique PCAP and report paths derived from a database ID."""
    if assessment_id < 1:
        raise ValueError("Assessment ID must be positive.")
    return AssessmentArtifactPaths(
        capture=Path("data/assessments") / str(assessment_id) / "capture.pcap",
        report=Path("reports/assessments") / str(assessment_id) / "report.html",
    )
