"""
Inspectability detection rules.

Inspectability findings represent trust gaps — things we cannot confidently
inspect. These increase risk only when combined with red flags.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ..loader import FileMap
from ..models import (
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OPAQUE_EXTENSIONS = frozenset({
    ".exe", ".dll", ".so", ".dylib", ".bin", ".node",
    ".wasm", ".o", ".a", ".lib", ".pyd", ".pyc",
})

# Files that should be parseable as JSON
JSON_FILES = frozenset({
    "package.json", "package-lock.json", "tsconfig.json",
    "jsconfig.json", "composer.json",
})

# Files that should be parseable as YAML
YAML_EXTENSIONS = frozenset({".yml", ".yaml"})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_safe(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Rule functions
# ---------------------------------------------------------------------------

def detect_opaque_binary(file_map: FileMap) -> list[Finding]:
    """OPAQUE_BINARY: binary files that resist inspection."""
    findings = []
    for fpath in file_map.binaries:
        findings.append(Finding(
            kind=FindingKind.INSPECTABILITY,
            code="OPAQUE_BINARY",
            title="Opaque binary file",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            evidence=[Evidence(
                file=file_map.rel(fpath),
                excerpt=f"Binary file: {fpath.suffix} ({_human_size(fpath)})",
            )],
            details={
                "extension": fpath.suffix,
                "size_bytes": fpath.stat().st_size if fpath.exists() else 0,
                "description": "Binary file cannot be statically inspected for malicious behavior.",
            },
        ))
    return findings


def detect_packed_or_minified(file_map: FileMap) -> list[Finding]:
    """PACKED_OR_MINIFIED: single-line files > 10KB or low whitespace ratio."""
    findings = []
    threshold_bytes = 10_000  # 10 KB
    whitespace_threshold = 0.05  # 5%

    for fpath in file_map.source_code:
        content = _read_safe(fpath)
        if not content:
            continue

        size = len(content.encode("utf-8"))
        if size < threshold_bytes:
            continue

        lines = content.splitlines()
        line_count = len(lines)

        # Check: very few lines for the file size (minified)
        is_minified = False
        if line_count <= 3 and size > threshold_bytes:
            is_minified = True
        elif size > 0:
            whitespace_ratio = sum(1 for c in content if c in (" ", "\t", "\n", "\r")) / len(content)
            if whitespace_ratio < whitespace_threshold:
                is_minified = True

        if is_minified:
            findings.append(Finding(
                kind=FindingKind.INSPECTABILITY,
                code="PACKED_OR_MINIFIED",
                title="Packed or minified code",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=[Evidence(
                    file=file_map.rel(fpath),
                    excerpt=f"{_human_size(fpath)}, {line_count} line{'s' if line_count != 1 else ''}",
                )],
                details={
                    "size_bytes": size,
                    "line_count": line_count,
                    "description": "Large file with very few lines or low whitespace ratio — likely minified or packed. Difficult to inspect for hidden behavior.",
                },
            ))
    return findings


def detect_lockfile_present(file_map: FileMap) -> list[Finding]:
    """LOCKFILE_PRESENT: lockfiles may contain transitive install scripts."""
    findings = []
    for fpath in file_map.lockfiles:
        findings.append(Finding(
            kind=FindingKind.INSPECTABILITY,
            code="LOCKFILE_PRESENT",
            title="Lockfile with potential hidden install scripts",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            evidence=[Evidence(
                file=file_map.rel(fpath),
                excerpt=f"Lockfile: {fpath.name}",
            )],
            details={
                "description": "Dependencies may run install scripts; transitive behavior not fully inspected.",
            },
        ))
    return findings


def detect_parse_error(file_map: FileMap) -> list[Finding]:
    """PARSE_ERROR: YAML/JSON files that fail to parse."""
    findings = []

    # Check JSON files
    for fpath in file_map.package_manifests + file_map.lockfiles:
        if fpath.name not in JSON_FILES:
            continue
        content = _read_safe(fpath)
        if not content:
            continue
        try:
            json.loads(content)
        except (json.JSONDecodeError, ValueError) as e:
            findings.append(Finding(
                kind=FindingKind.INSPECTABILITY,
                code="PARSE_ERROR",
                title=f"JSON parse failure: {fpath.name}",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                evidence=[Evidence(
                    file=file_map.rel(fpath),
                    excerpt=str(e)[:200],
                )],
                details={
                    "format": "json",
                    "error": str(e)[:200],
                    "description": "File could not be parsed as valid JSON. May be intentionally malformed to evade scanning.",
                },
            ))

    # Check YAML files
    for fpath in file_map.ci_workflows:
        content = _read_safe(fpath)
        if not content:
            continue
        try:
            yaml.safe_load(content)
        except yaml.YAMLError as e:
            findings.append(Finding(
                kind=FindingKind.INSPECTABILITY,
                code="PARSE_ERROR",
                title=f"YAML parse failure: {fpath.name}",
                severity=Severity.MEDIUM,
                confidence=Confidence.LOW,
                evidence=[Evidence(
                    file=file_map.rel(fpath),
                    excerpt=str(e)[:200],
                )],
                details={
                    "format": "yaml",
                    "error": str(e)[:200],
                    "description": "Workflow file could not be parsed as valid YAML. May be intentionally malformed to evade scanning.",
                },
            ))

    return findings


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _human_size(path: Path) -> str:
    """Return a human-readable file size."""
    try:
        size = path.stat().st_size
    except OSError:
        return "unknown size"
    if size < 1024:
        return f"{size}B"
    elif size < 1024 * 1024:
        return f"{size / 1024:.0f}KB"
    else:
        return f"{size / (1024 * 1024):.1f}MB"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_INSPECTABILITY_RULES = [
    detect_opaque_binary,
    detect_packed_or_minified,
    detect_lockfile_present,
    detect_parse_error,
]


def run_inspectability_rules(file_map: FileMap) -> list[Finding]:
    """Run all inspectability detection rules and return findings."""
    findings = []
    for rule_fn in ALL_INSPECTABILITY_RULES:
        findings.extend(rule_fn(file_map))
    return findings
