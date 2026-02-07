"""
Risk scoring engine for SkillsGuard.

Scoring philosophy (from spec):
  - Capabilities = low weight
  - Red flags = high weight
  - Inspectability = medium weight
  - High risk should be rare
  - High usually requires: red_flag + inspectability, or multiple red flags

Top reasons are ranked by: severity_weight * confidence_weight,
then code priority, then file path / line (for stability).
"""

from __future__ import annotations

from .models import (
    Confidence,
    Finding,
    FindingKind,
    RiskLabel,
    Severity,
)


# ---------------------------------------------------------------------------
# Weight tables
# ---------------------------------------------------------------------------

KIND_WEIGHTS: dict[FindingKind, float] = {
    FindingKind.CAPABILITY: 1.0,
    FindingKind.INSPECTABILITY: 2.0,
    FindingKind.RED_FLAG: 3.0,
}

SEVERITY_WEIGHTS: dict[Severity, float] = {
    Severity.LOW: 1.0,
    Severity.MEDIUM: 2.0,
    Severity.HIGH: 3.0,
}

CONFIDENCE_WEIGHTS: dict[Confidence, float] = {
    Confidence.LOW: 0.5,
    Confidence.MEDIUM: 0.75,
    Confidence.HIGH: 1.0,
}

# Code priority for stable tie-breaking (lower = higher priority)
CODE_PRIORITY: dict[str, int] = {
    # Red flags (highest priority)
    "CURL_PIPE_SH": 1,
    "BASE64_EXEC": 2,
    "DOWNLOAD_EXEC": 3,
    "POSTINSTALL_EXEC": 4,
    "PERSISTENCE": 5,
    "GHA_USES_UNPINNED": 6,
    "GHA_USES_DOCKER": 7,
    "GHA_RUN_SHELL": 8,
    "EVAL_DYNAMIC": 9,
    "GHA_USES_REMOTE": 10,
    # Inspectability
    "OPAQUE_BINARY": 20,
    "PACKED_OR_MINIFIED": 21,
    "PARSE_ERROR": 22,
    "LOCKFILE_PRESENT": 23,
    # Capabilities
    "SENSITIVE_PATH_READ": 30,
    "SHELL_EXEC": 31,
    "NETWORK_EGRESS": 32,
    "FS_WRITE": 33,
    "ENV_READ": 34,
}


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

def finding_weight(f: Finding) -> float:
    """Calculate the weight of a single finding."""
    return (
        KIND_WEIGHTS.get(f.kind, 1.0)
        * SEVERITY_WEIGHTS.get(f.severity, 1.0)
        * CONFIDENCE_WEIGHTS.get(f.confidence, 0.5)
    )


def compute_risk_score(findings: list[Finding]) -> float:
    """
    Compute a 0-10 risk score from findings.

    Uses a logarithmic scale to avoid linear inflation:
    many low-severity capabilities shouldn't push the score to 10.
    """
    if not findings:
        return 0.0

    raw = sum(finding_weight(f) for f in findings)

    # Normalize with diminishing returns
    # A single high-severity red flag: 3 * 3 * 1.0 = 9.0 → score ~5.2
    # Two high-severity red flags: 18.0 → score ~7.0
    # Three high-severity red flags + inspectability: ~8.5
    import math
    score = 10.0 * (1.0 - math.exp(-raw / 15.0))

    return min(round(score, 1), 10.0)


def compute_risk_label(score: float) -> RiskLabel:
    """Map a 0-10 risk score to a risk label."""
    if score <= 2.0:
        return RiskLabel.LOW
    elif score <= 5.0:
        return RiskLabel.MEDIUM
    elif score <= 8.0:
        return RiskLabel.HIGH
    else:
        return RiskLabel.CRITICAL


def rank_top_reasons(findings: list[Finding], limit: int = 5) -> list[Finding]:
    """
    Rank findings by importance for "top reasons" display.

    Sorted by: severity_weight * confidence_weight (desc),
    then code priority (asc), then file/line for stability.
    """
    def sort_key(f: Finding) -> tuple:
        weight = finding_weight(f)
        priority = CODE_PRIORITY.get(f.code, 99)
        # First evidence file/line for stability
        first_file = f.evidence[0].file if f.evidence else ""
        first_line = f.evidence[0].line or 0 if f.evidence else 0
        # Negate weight for descending sort
        return (-weight, priority, first_file, first_line)

    sorted_findings = sorted(findings, key=sort_key)
    return sorted_findings[:limit]
