"""
Data models for SkillsGuard findings and scan results.

The core mental model is three first-class concepts:
  - Capabilities (neutral): what the code CAN do
  - Red Flags (weighted heavily): how the code does things in RISKY ways
  - Inspectability (trust gaps): things we CANNOT confidently inspect
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class FindingKind(str, Enum):
    """Four-pillar classification for every finding."""
    CAPABILITY = "capability"
    RED_FLAG = "red_flag"
    INSPECTABILITY = "inspectability"
    SKILL_THREAT = "skill_threat"


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Confidence(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class Context(str, Enum):
    EXPECTED = "expected"
    UNEXPECTED = "unexpected"
    UNKNOWN = "unknown"


class Purpose(str, Enum):
    """Purpose flag for expectedness context."""
    UNKNOWN = "unknown"
    AGENT_SKILL = "agent_skill"
    FORMATTER = "formatter"
    LINTER = "linter"
    BUILD_TOOL = "build_tool"
    DEVOPS = "devops"
    CLI = "cli"
    LIBRARY = "library"


class RiskLabel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Evidence & Finding
# ---------------------------------------------------------------------------

@dataclass
class Evidence:
    """A single piece of evidence for a finding."""
    file: str               # repo-relative path
    line: int | None = None
    excerpt: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"file": self.file}
        if self.line is not None:
            d["line"] = self.line
        if self.excerpt is not None:
            d["excerpt"] = self.excerpt
        return d


@dataclass
class Finding:
    """
    A single finding emitted by the scanner.

    Every finding is classified into one of the three pillars:
    capability, red_flag, or inspectability.
    """
    kind: FindingKind
    code: str                       # stable identifier, e.g. "CURL_PIPE_SH"
    title: str
    severity: Severity
    confidence: Confidence
    context: Context = Context.UNKNOWN
    evidence: list[Evidence] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind.value,
            "code": self.code,
            "title": self.title,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "context": self.context.value,
            "evidence": [e.to_dict() for e in self.evidence],
            "details": self.details if self.details else {},
        }


# ---------------------------------------------------------------------------
# Scan Result
# ---------------------------------------------------------------------------

@dataclass
class ScanResult:
    """Aggregated result from a single scan run."""
    repo_name: str
    purpose: Purpose
    scan_duration_seconds: float
    file_count: int
    risk_score: float               # 0.0 – 10.0
    risk_label: RiskLabel
    findings: list[Finding] = field(default_factory=list)
    top_reasons: list[Finding] = field(default_factory=list)

    @property
    def red_flags(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == FindingKind.RED_FLAG]

    @property
    def capabilities(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == FindingKind.CAPABILITY]

    @property
    def inspectability(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == FindingKind.INSPECTABILITY]

    @property
    def skill_threats(self) -> list[Finding]:
        return [f for f in self.findings if f.kind == FindingKind.SKILL_THREAT]

    @property
    def breakdown(self) -> dict[str, int]:
        d = {
            "red_flags": len(self.red_flags),
            "capabilities": len(self.capabilities),
            "inspectability": len(self.inspectability),
        }
        st = len(self.skill_threats)
        if st > 0:
            d["skill_threats"] = st
        return d

    def to_dict(self) -> dict[str, Any]:
        return {
            "summary": {
                "repo": self.repo_name,
                "purpose": self.purpose.value,
                "scan_duration_seconds": round(self.scan_duration_seconds, 2),
                "file_count": self.file_count,
                "risk_score": round(self.risk_score, 1),
                "risk_label": self.risk_label.value,
            },
            "breakdown": self.breakdown,
            "top_reasons": [f.to_dict() for f in self.top_reasons],
            "findings": [f.to_dict() for f in self.findings],
        }
