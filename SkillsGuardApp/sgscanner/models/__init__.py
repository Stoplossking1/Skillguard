"""Core data models for SGScanner.

Defines the primary types used throughout the scanning pipeline:
skills, issues, scan outcomes, and summary reports.
"""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any


class RiskLevel(str, Enum):
    """Severity classification for detected issues."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    SAFE = "SAFE"


class ThreatClass(str, Enum):
    """Categories of security threats detected by scan engines."""
    PROMPT_INJECTION = "prompt_injection"
    COMMAND_INJECTION = "command_injection"
    DATA_EXFILTRATION = "data_exfiltration"
    UNAUTHORIZED_TOOL_USE = "unauthorized_tool_use"
    OBFUSCATION = "obfuscation"
    HARDCODED_SECRETS = "hardcoded_secrets"
    SOCIAL_ENGINEERING = "social_engineering"
    RESOURCE_ABUSE = "resource_abuse"
    POLICY_VIOLATION = "policy_violation"
    MALWARE = "malware"
    HARMFUL_CONTENT = "harmful_content"
    SKILL_DISCOVERY_ABUSE = "skill_discovery_abuse"
    TRANSITIVE_TRUST_ABUSE = "transitive_trust_abuse"
    AUTONOMY_ABUSE = "autonomy_abuse"
    TOOL_CHAINING_ABUSE = "tool_chaining_abuse"
    UNICODE_STEGANOGRAPHY = "unicode_steganography"


@dataclass
class SkillManifest:
    """Parsed metadata from a skill's SKILL.md frontmatter."""
    name: str
    description: str
    license: str | None = None
    compatibility: str | None = None
    allowed_tools: list[str] | None = None
    metadata: dict[str, Any] | None = None
    disable_model_invocation: bool = False

    def __post_init__(self):
        if self.allowed_tools is None:
            self.allowed_tools = []
        elif isinstance(self.allowed_tools, str):
            parts = [p.strip() for p in self.allowed_tools.split(",")]
            self.allowed_tools = [p for p in parts if p]

    @property
    def short_description(self) -> str | None:
        if self.metadata and isinstance(self.metadata, dict):
            return self.metadata.get("short-description")
        return None


@dataclass
class SkillAsset:
    """A single file within a skill package."""
    path: Path
    relative_path: str
    file_type: str
    content: str | None = None
    size_bytes: int = 0

    def read_content(self) -> str:
        """Lazily read file content from disk."""
        if self.content is None and self.path.exists():
            try:
                with open(self.path, encoding="utf-8") as f:
                    self.content = f.read()
            except (OSError, UnicodeDecodeError):
                self.content = ""
        return self.content or ""


@dataclass
class Skill:
    """A loaded skill package ready for scanning."""
    directory: Path
    manifest: SkillManifest
    skill_md_path: Path
    instruction_body: str
    files: list[SkillAsset] = field(default_factory=list)
    referenced_files: list[str] = field(default_factory=list)

    @property
    def name(self) -> str:
        return self.manifest.name

    @property
    def description(self) -> str:
        return self.manifest.description

    def get_scripts(self) -> list[SkillAsset]:
        """Return Python and Bash script assets."""
        return [f for f in self.files if f.file_type in ("python", "bash")]

    def get_markdown_files(self) -> list[SkillAsset]:
        """Return Markdown file assets."""
        return [f for f in self.files if f.file_type == "markdown"]


@dataclass
class Issue:
    """A single security finding produced by a scan engine."""
    id: str
    rule_id: str
    category: ThreatClass
    severity: RiskLevel
    title: str
    description: str
    file_path: str | None = None
    line_number: int | None = None
    snippet: str | None = None
    remediation: str | None = None
    engine: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    # Legacy aliases
    @property
    def analyzer(self) -> str | None:
        return self.engine

    @analyzer.setter
    def analyzer(self, value: str | None) -> None:
        self.engine = value

    def serialize(self) -> dict[str, Any]:
        """Convert to a plain dictionary for JSON serialization."""
        return {
            "id": self.id,
            "rule_id": self.rule_id,
            "category": self.category.value,
            "severity": self.severity.value,
            "title": self.title,
            "description": self.description,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "snippet": self.snippet,
            "remediation": self.remediation,
            "engine": self.engine,
            "metadata": self.metadata,
        }


@dataclass
class ScanOutcome:
    """Result of scanning a single skill."""
    skill_name: str
    skill_directory: str
    findings: list[Issue] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    engines_used: list[str] = field(default_factory=list)
    timestamp: datetime = field(default_factory=datetime.now)

    @property
    def is_safe(self) -> bool:
        """True if no CRITICAL or HIGH issues were found."""
        return not any(
            f.severity in (RiskLevel.CRITICAL, RiskLevel.HIGH)
            for f in self.findings
        )

    @property
    def max_severity(self) -> RiskLevel:
        """Return the highest severity among all findings."""
        if not self.findings:
            return RiskLevel.SAFE
        severity_order = [
            RiskLevel.CRITICAL, RiskLevel.HIGH, RiskLevel.MEDIUM,
            RiskLevel.LOW, RiskLevel.INFO,
        ]
        for sev in severity_order:
            if any(f.severity == sev for f in self.findings):
                return sev
        return RiskLevel.SAFE

    def filter_by_risk(self, severity: RiskLevel) -> list[Issue]:
        """Return findings matching a specific risk level."""
        return [f for f in self.findings if f.severity == severity]

    def get_findings_by_category(self, category: ThreatClass) -> list[Issue]:
        """Return findings matching a specific threat class."""
        return [f for f in self.findings if f.category == category]

    def serialize(self) -> dict[str, Any]:
        """Convert to a plain dictionary for JSON serialization."""
        return {
            "skill_name": self.skill_name,
            "skill_path": self.skill_directory,
            "skill_directory": self.skill_directory,
            "is_safe": self.is_safe,
            "max_severity": self.max_severity.value,
            "findings_count": len(self.findings),
            "findings": [f.serialize() for f in self.findings],
            "scan_duration_seconds": self.scan_duration_seconds,
            "duration_ms": int(self.scan_duration_seconds * 1000),
            "engines_used": list(self.engines_used),
            "timestamp": self.timestamp.isoformat(),
        }


@dataclass
class ScanSummary:
    """Aggregated report across multiple skill scans."""
    scan_results: list[ScanOutcome] = field(default_factory=list)
    total_skills_scanned: int = 0
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    safe_count: int = 0
    timestamp: datetime = field(default_factory=datetime.now)

    def add_scan_result(self, result: ScanOutcome) -> None:
        """Add a scan outcome and update aggregate counters."""
        self.scan_results.append(result)
        self.total_skills_scanned += 1
        self.total_findings += len(result.findings)
        for finding in result.findings:
            if finding.severity == RiskLevel.CRITICAL:
                self.critical_count += 1
            elif finding.severity == RiskLevel.HIGH:
                self.high_count += 1
            elif finding.severity == RiskLevel.MEDIUM:
                self.medium_count += 1
            elif finding.severity == RiskLevel.LOW:
                self.low_count += 1
            elif finding.severity == RiskLevel.INFO:
                self.info_count += 1
        if result.is_safe:
            self.safe_count += 1

    def serialize(self) -> dict[str, Any]:
        """Convert to a plain dictionary for JSON serialization."""
        return {
            "summary": {
                "total_skills_scanned": self.total_skills_scanned,
                "total_findings": self.total_findings,
                "safe_skills": self.safe_count,
                "findings_by_severity": {
                    "critical": self.critical_count,
                    "high": self.high_count,
                    "medium": self.medium_count,
                    "low": self.low_count,
                    "info": self.info_count,
                },
                "timestamp": self.timestamp.isoformat(),
            },
            "results": [r.serialize() for r in self.scan_results],
        }


# Backward-compatible aliases
Finding = Issue
ScanResult = ScanOutcome
Report = ScanSummary
Severity = RiskLevel
ThreatCategory = ThreatClass
SkillFile = SkillAsset
