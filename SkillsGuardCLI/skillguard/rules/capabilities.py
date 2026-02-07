"""
Capability detection rules.

Capabilities describe what the code CAN do — shell execution, network egress,
filesystem writes, env reads, sensitive path access. These are neutral findings
that do not imply danger by themselves. Context determines risk.
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from ..loader import FileMap
from ..models import (
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)


# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

_SHELL_EXEC_PATTERNS = [
    # Python
    re.compile(r"subprocess\.\w+\s*\(", re.IGNORECASE),
    re.compile(r"os\.system\s*\("),
    re.compile(r"os\.popen\s*\("),
    re.compile(r"os\.exec\w+\s*\("),
    re.compile(r"Popen\s*\("),
    # JavaScript / Node
    re.compile(r"child_process"),
    re.compile(r"\.exec\s*\("),
    re.compile(r"\.execSync\s*\("),
    re.compile(r"\.spawn\s*\("),
    re.compile(r"\.spawnSync\s*\("),
    re.compile(r"shelljs"),
    re.compile(r"execa\s*\("),
]

_NETWORK_EGRESS_PATTERNS = [
    re.compile(r"\bfetch\s*\("),
    re.compile(r"https?://", re.IGNORECASE),
    re.compile(r"\brequests\.\w+\s*\("),
    re.compile(r"\burllib\b"),
    re.compile(r"\bhttp\.(?:get|request|createServer)\s*\("),
    re.compile(r"\baxios\b"),
    re.compile(r"\bnode-fetch\b"),
    re.compile(r"\bgot\s*\("),
    re.compile(r"\bsocket\.connect\s*\("),
    re.compile(r"\bWebSocket\s*\("),
    re.compile(r"\bxmlhttp|XMLHttpRequest", re.IGNORECASE),
]

_FS_WRITE_PATTERNS = [
    # Python
    re.compile(r"open\s*\([^)]*['\"]w['\"]"),
    re.compile(r"open\s*\([^)]*['\"]a['\"]"),
    re.compile(r"\.write\s*\("),
    re.compile(r"\.writelines\s*\("),
    re.compile(r"Path\s*\([^)]*\)\.write_text"),
    re.compile(r"Path\s*\([^)]*\)\.write_bytes"),
    re.compile(r"shutil\.copy"),
    re.compile(r"shutil\.move"),
    # JavaScript / Node
    re.compile(r"fs\.writeFile"),
    re.compile(r"fs\.appendFile"),
    re.compile(r"fs\.createWriteStream"),
    re.compile(r"fs\.mkdir"),
    re.compile(r"fs\.rename"),
    re.compile(r"fsPromises\.writeFile"),
]

_ENV_READ_PATTERNS = [
    re.compile(r"process\.env\b"),
    re.compile(r"os\.environ\b"),
    re.compile(r"os\.getenv\s*\("),
    re.compile(r"dotenv"),
    re.compile(r"\.env\b.*?(?:load|config|parse)"),
    re.compile(r"getenv\s*\("),
    re.compile(r"Environment\.\w+"),
]

_SENSITIVE_PATH_PATTERNS = [
    re.compile(r"~/.ssh|\.ssh/"),
    re.compile(r"~/.aws|\.aws/"),
    re.compile(r"~/.gnupg|\.gnupg/"),
    re.compile(r"/etc/passwd"),
    re.compile(r"/etc/shadow"),
    re.compile(r"~/.config"),
    re.compile(r"~/.netrc|\.netrc"),
    re.compile(r"~/.npmrc|\.npmrc"),
    re.compile(r"~/.bash_history|\.bash_history"),
    re.compile(r"~/.zsh_history|\.zsh_history"),
    re.compile(r"GITHUB_TOKEN|AWS_SECRET|PRIVATE_KEY", re.IGNORECASE),
    re.compile(r"~/.kube/config"),
    re.compile(r"~/.docker/config"),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _read_safe(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


def _detect_capability(
    file_map: FileMap,
    files: list[Path],
    patterns: list[re.Pattern],
    code: str,
    title: str,
    description: str,
) -> Finding | None:
    """
    Generic capability detector.

    Scans given files for patterns, collects evidence, and returns a single
    aggregated Finding if any matches are found, or None.
    """
    all_evidence: list[Evidence] = []
    file_hit_count: dict[str, int] = defaultdict(int)

    for fpath in files:
        content = _read_safe(fpath)
        if not content:
            continue

        rel = file_map.rel(fpath)
        file_matched = False

        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern in patterns:
                if pattern.search(line):
                    if not file_matched:
                        file_matched = True
                        file_hit_count[rel] += 1
                    # Keep first few evidence items per file
                    if len([e for e in all_evidence if e.file == rel]) < 3:
                        all_evidence.append(Evidence(
                            file=rel,
                            line=line_num,
                            excerpt=line.strip()[:200],
                        ))
                    else:
                        file_hit_count[rel] += 1
                    break  # One match per line

    if not all_evidence:
        return None

    return Finding(
        kind=FindingKind.CAPABILITY,
        code=code,
        title=title,
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        evidence=all_evidence,
        details={
            "description": description,
            "files_affected": len(file_hit_count),
        },
    )


# ---------------------------------------------------------------------------
# Rule functions
# ---------------------------------------------------------------------------

def detect_shell_exec(file_map: FileMap) -> list[Finding]:
    """SHELL_EXEC: subprocess, exec, spawn, system() calls."""
    result = _detect_capability(
        file_map,
        file_map.source_code + file_map.shell_scripts,
        _SHELL_EXEC_PATTERNS,
        "SHELL_EXEC",
        "Shell / subprocess execution",
        "Code can execute shell commands or spawn subprocesses.",
    )
    return [result] if result else []


def detect_network_egress(file_map: FileMap) -> list[Finding]:
    """NETWORK_EGRESS: fetch, http, requests, axios, curl."""
    result = _detect_capability(
        file_map,
        file_map.source_code,
        _NETWORK_EGRESS_PATTERNS,
        "NETWORK_EGRESS",
        "Network egress",
        "Code can make outbound network requests.",
    )
    return [result] if result else []


def detect_fs_write(file_map: FileMap) -> list[Finding]:
    """FS_WRITE: writeFile, open('w'), fs.write."""
    result = _detect_capability(
        file_map,
        file_map.source_code,
        _FS_WRITE_PATTERNS,
        "FS_WRITE",
        "Filesystem write access",
        "Code can write to the local filesystem.",
    )
    return [result] if result else []


def detect_env_read(file_map: FileMap) -> list[Finding]:
    """ENV_READ: process.env, os.environ, os.getenv."""
    result = _detect_capability(
        file_map,
        file_map.source_code,
        _ENV_READ_PATTERNS,
        "ENV_READ",
        "Environment variable access",
        "Code reads environment variables (may contain tokens, secrets, API keys).",
    )
    return [result] if result else []


def detect_sensitive_path_read(file_map: FileMap) -> list[Finding]:
    """SENSITIVE_PATH_READ: ~/.ssh, ~/.aws, /etc/passwd, etc."""
    result = _detect_capability(
        file_map,
        file_map.source_code + file_map.shell_scripts,
        _SENSITIVE_PATH_PATTERNS,
        "SENSITIVE_PATH_READ",
        "Sensitive path access",
        "Code references sensitive filesystem paths (SSH keys, AWS credentials, etc.).",
    )
    return [result] if result else []


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_CAPABILITY_RULES = [
    detect_shell_exec,
    detect_network_egress,
    detect_fs_write,
    detect_env_read,
    detect_sensitive_path_read,
]


def run_capability_rules(file_map: FileMap) -> list[Finding]:
    """Run all capability detection rules and return findings."""
    findings = []
    for rule_fn in ALL_CAPABILITY_RULES:
        findings.extend(rule_fn(file_map))
    return findings
