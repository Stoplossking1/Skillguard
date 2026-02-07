"""
Red flag detection rules.

Red flags represent risky execution patterns that drive risk scoring.
These are the highest-weight findings in the three-pillar model.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from ..loader import FileMap
from ..models import (
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)
from .github_actions import parse_workflow


# ---------------------------------------------------------------------------
# Regex patterns  (compiled once at module level)
# ---------------------------------------------------------------------------

# CURL_PIPE_SH: curl/wget piped to bash/sh/zsh
_CURL_PIPE_RE = re.compile(
    r"(?:curl|wget)\s+[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh|zsh|dash)",
    re.IGNORECASE,
)

# DOWNLOAD_EXEC: download then execute pattern
_DOWNLOAD_EXEC_PATTERNS = [
    re.compile(r"(?:urllib|requests|http|fetch|axios|wget|curl).*?(?:exec|eval|spawn|system|popen|subprocess)", re.IGNORECASE | re.DOTALL),
    re.compile(r"(?:download|fetch).*?(?:&&|\;|\|)\s*(?:chmod\s+\+x|bash|sh|python|node)", re.IGNORECASE),
]

# BASE64_EXEC: base64 decode + exec/eval
_BASE64_EXEC_PATTERNS = [
    re.compile(r"atob\s*\([^)]*\).*?eval", re.IGNORECASE | re.DOTALL),
    re.compile(r"eval\s*\(\s*atob", re.IGNORECASE),
    re.compile(r"base64[._\-]?decode.*?(?:exec|eval|system|popen|subprocess)", re.IGNORECASE),
    re.compile(r"(?:exec|eval)\s*\(.*?(?:b64decode|base64\.decode|atob)", re.IGNORECASE),
    re.compile(r"echo\s+[A-Za-z0-9+/=]+\s*\|\s*base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh)", re.IGNORECASE),
]

# EVAL_DYNAMIC: eval() with variable/dynamic input
_EVAL_DYNAMIC_PATTERNS = [
    re.compile(r"eval\s*\(\s*[a-zA-Z_]\w*\s*\)", re.IGNORECASE),  # eval(variable)
    re.compile(r"eval\s*\(\s*[`\"'].*?\$", re.IGNORECASE),          # eval with template strings
    re.compile(r"new\s+Function\s*\(", re.IGNORECASE),               # new Function(...)
    re.compile(r"exec\s*\(\s*(?:compile|open|input)\s*\(", re.IGNORECASE),  # Python exec(compile(...))
]

# PERSISTENCE: cron, systemd, launchd, registry
_PERSISTENCE_PATTERNS = [
    re.compile(r"crontab\s+(?:-[elr]\s+)?", re.IGNORECASE),
    re.compile(r"/etc/cron\.", re.IGNORECASE),
    re.compile(r"systemctl\s+(?:enable|start|daemon-reload)", re.IGNORECASE),
    re.compile(r"/etc/systemd/", re.IGNORECASE),
    re.compile(r"LaunchAgents|LaunchDaemons|launchctl\s+load", re.IGNORECASE),
    re.compile(r"(?:HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER).*\\Run", re.IGNORECASE),
    re.compile(r"reg\s+add\s+.*\\Run", re.IGNORECASE),
    re.compile(r"chkconfig\s+", re.IGNORECASE),
    re.compile(r"update-rc\.d\s+", re.IGNORECASE),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _scan_lines(content: str, pattern: re.Pattern, filepath: str, root: Path) -> list[Evidence]:
    """Scan file content line-by-line for a regex pattern."""
    evidence = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        if pattern.search(line):
            evidence.append(Evidence(
                file=filepath,
                line=line_num,
                excerpt=line.strip()[:200],
            ))
    return evidence


def _scan_lines_multi(content: str, patterns: list[re.Pattern], filepath: str, root: Path) -> list[Evidence]:
    """Scan file content line-by-line for multiple regex patterns."""
    evidence = []
    for line_num, line in enumerate(content.splitlines(), start=1):
        for pattern in patterns:
            if pattern.search(line):
                evidence.append(Evidence(
                    file=filepath,
                    line=line_num,
                    excerpt=line.strip()[:200],
                ))
                break  # One match per line
    return evidence


def _read_safe(path: Path) -> str | None:
    """Read file content, returning None on failure."""
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except (OSError, UnicodeDecodeError):
        return None


# ---------------------------------------------------------------------------
# Rule functions
# ---------------------------------------------------------------------------

def detect_curl_pipe_sh(file_map: FileMap) -> list[Finding]:
    """CURL_PIPE_SH: curl/wget piped to bash/sh."""
    findings = []
    scan_files = file_map.shell_scripts + file_map.source_code + file_map.build_files + file_map.dockerfiles
    for fpath in scan_files:
        content = _read_safe(fpath)
        if not content:
            continue
        evidence = _scan_lines(content, _CURL_PIPE_RE, file_map.rel(fpath), file_map.root)
        if evidence:
            findings.append(Finding(
                kind=FindingKind.RED_FLAG,
                code="CURL_PIPE_SH",
                title="Piped download to shell execution",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=evidence,
                details={"description": "Downloads and executes remote code in one step via curl/wget piped to bash/sh. This is a classic supply-chain attack vector."},
            ))
    return findings


def detect_download_exec(file_map: FileMap) -> list[Finding]:
    """DOWNLOAD_EXEC: runtime download + execute."""
    findings = []
    scan_files = file_map.shell_scripts + file_map.source_code
    for fpath in scan_files:
        content = _read_safe(fpath)
        if not content:
            continue
        evidence = _scan_lines_multi(content, _DOWNLOAD_EXEC_PATTERNS, file_map.rel(fpath), file_map.root)
        if evidence:
            findings.append(Finding(
                kind=FindingKind.RED_FLAG,
                code="DOWNLOAD_EXEC",
                title="Runtime download and execute",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                evidence=evidence,
                details={"description": "Downloads content at runtime and executes it. The executed code is not available for pre-install inspection."},
            ))
    return findings


def detect_postinstall_exec(file_map: FileMap) -> list[Finding]:
    """POSTINSTALL_EXEC: preinstall/install/postinstall/prepare scripts in package.json."""
    findings = []
    risky_scripts = {"preinstall", "install", "postinstall", "prepare"}

    for fpath in file_map.package_manifests:
        if fpath.name != "package.json":
            continue
        content = _read_safe(fpath)
        if not content:
            continue
        try:
            pkg = json.loads(content)
        except (json.JSONDecodeError, ValueError):
            continue

        scripts = pkg.get("scripts", {})
        if not isinstance(scripts, dict):
            continue

        for key, cmd in scripts.items():
            if key in risky_scripts and cmd:
                # Find the line number
                line_num = None
                for i, line in enumerate(content.splitlines(), start=1):
                    if f'"{key}"' in line or f"'{key}'" in line:
                        line_num = i
                        break

                findings.append(Finding(
                    kind=FindingKind.RED_FLAG,
                    code="POSTINSTALL_EXEC",
                    title=f"Lifecycle script: {key}",
                    severity=Severity.HIGH if key in ("preinstall", "postinstall") else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=[Evidence(
                        file=file_map.rel(fpath),
                        line=line_num,
                        excerpt=f'"{key}": "{cmd}"',
                    )],
                    details={"script_name": key, "command": cmd},
                ))
    return findings


def detect_base64_exec(file_map: FileMap) -> list[Finding]:
    """BASE64_EXEC: base64 decode + exec/eval."""
    findings = []
    scan_files = file_map.source_code + file_map.shell_scripts
    for fpath in scan_files:
        content = _read_safe(fpath)
        if not content:
            continue
        evidence = _scan_lines_multi(content, _BASE64_EXEC_PATTERNS, file_map.rel(fpath), file_map.root)
        if evidence:
            findings.append(Finding(
                kind=FindingKind.RED_FLAG,
                code="BASE64_EXEC",
                title="Obfuscated execution via base64",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                evidence=evidence,
                details={"description": "Decodes base64-encoded content and executes it. This is a common obfuscation technique to hide malicious payloads."},
            ))
    return findings


def detect_eval_dynamic(file_map: FileMap) -> list[Finding]:
    """EVAL_DYNAMIC: eval() with variable/dynamic input."""
    findings = []
    for fpath in file_map.source_code:
        content = _read_safe(fpath)
        if not content:
            continue
        evidence = _scan_lines_multi(content, _EVAL_DYNAMIC_PATTERNS, file_map.rel(fpath), file_map.root)
        if evidence:
            findings.append(Finding(
                kind=FindingKind.RED_FLAG,
                code="EVAL_DYNAMIC",
                title="Dynamic code evaluation",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM,
                evidence=evidence,
                details={"description": "Evaluates dynamically constructed code at runtime. This can execute arbitrary code that is not available for static inspection."},
            ))
    return findings


def detect_persistence(file_map: FileMap) -> list[Finding]:
    """PERSISTENCE: cron, systemd, launchd, registry writes."""
    findings = []
    scan_files = file_map.shell_scripts + file_map.source_code + file_map.build_files
    for fpath in scan_files:
        content = _read_safe(fpath)
        if not content:
            continue
        evidence = _scan_lines_multi(content, _PERSISTENCE_PATTERNS, file_map.rel(fpath), file_map.root)
        if evidence:
            findings.append(Finding(
                kind=FindingKind.RED_FLAG,
                code="PERSISTENCE",
                title="Persistence mechanism detected",
                severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
                evidence=evidence,
                details={"description": "Installs persistent execution hooks (cron, systemd, launchd, registry). Code will survive reboots and run without user interaction."},
            ))
    return findings


def detect_gha_uses_remote(file_map: FileMap) -> list[Finding]:
    """GHA_USES_REMOTE: any uses: owner/repo@ref in workflows."""
    findings = []
    for fpath in file_map.ci_workflows:
        action_refs, _ = parse_workflow(fpath)
        rel = file_map.rel(fpath)
        for ref in action_refs:
            if ref.is_local or ref.is_docker:
                continue
            findings.append(Finding(
                kind=FindingKind.RED_FLAG,
                code="GHA_USES_REMOTE",
                title="Remote GitHub Action usage",
                severity=Severity.LOW,
                confidence=Confidence.HIGH,
                evidence=[Evidence(
                    file=rel,
                    line=ref.line_number,
                    excerpt=f"uses: {ref.raw}",
                )],
                details={
                    "action": ref.owner_repo,
                    "ref": ref.ref,
                    "pinned": ref.is_pinned,
                    "description": "Uses a remote GitHub Action. Every `uses:` is remote code execution by design.",
                },
            ))
    return findings


def detect_gha_uses_unpinned(file_map: FileMap) -> list[Finding]:
    """GHA_USES_UNPINNED: uses: with tag/branch instead of SHA."""
    findings = []
    for fpath in file_map.ci_workflows:
        action_refs, _ = parse_workflow(fpath)
        rel = file_map.rel(fpath)
        for ref in action_refs:
            if ref.is_local or ref.is_docker:
                continue
            if ref.ref and not ref.is_pinned:
                findings.append(Finding(
                    kind=FindingKind.RED_FLAG,
                    code="GHA_USES_UNPINNED",
                    title="Unpinned GitHub Action",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    evidence=[Evidence(
                        file=rel,
                        line=ref.line_number,
                        excerpt=f"uses: {ref.raw}",
                    )],
                    details={
                        "action": ref.owner_repo,
                        "ref": ref.ref,
                        "description": f"Action pinned to '{ref.ref}' (tag/branch) instead of a commit SHA. A compromised tag can silently change the executed code.",
                    },
                ))
    return findings


def detect_gha_uses_docker(file_map: FileMap) -> list[Finding]:
    """GHA_USES_DOCKER: uses: docker://..."""
    findings = []
    for fpath in file_map.ci_workflows:
        action_refs, _ = parse_workflow(fpath)
        rel = file_map.rel(fpath)
        for ref in action_refs:
            if ref.is_docker:
                findings.append(Finding(
                    kind=FindingKind.RED_FLAG,
                    code="GHA_USES_DOCKER",
                    title="Docker-based GitHub Action",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    evidence=[Evidence(
                        file=rel,
                        line=ref.line_number,
                        excerpt=f"uses: {ref.raw}",
                    )],
                    details={
                        "image": ref.raw,
                        "description": "Runs a Docker container as a GitHub Action. The container image is pulled from a remote registry at runtime.",
                    },
                ))
    return findings


def detect_gha_run_shell(file_map: FileMap) -> list[Finding]:
    """GHA_RUN_SHELL: suspicious shell patterns in run: steps."""
    findings = []
    suspicious_patterns = [
        _CURL_PIPE_RE,
        *_BASE64_EXEC_PATTERNS,
        *_EVAL_DYNAMIC_PATTERNS,
        re.compile(r"(?:curl|wget)\s+.*?-[^\s]*o\s+.*?&&\s*(?:chmod|bash|sh)", re.IGNORECASE),
    ]
    for fpath in file_map.ci_workflows:
        _, run_steps = parse_workflow(fpath)
        rel = file_map.rel(fpath)
        for step in run_steps:
            for pattern in suspicious_patterns:
                if pattern.search(step.content):
                    # Find the specific line within the run content
                    excerpt_line = None
                    for line in step.content.splitlines():
                        if pattern.search(line):
                            excerpt_line = line.strip()[:200]
                            break

                    findings.append(Finding(
                        kind=FindingKind.RED_FLAG,
                        code="GHA_RUN_SHELL",
                        title="Suspicious command in CI workflow",
                        severity=Severity.HIGH,
                        confidence=Confidence.MEDIUM,
                        evidence=[Evidence(
                            file=rel,
                            line=step.line_number,
                            excerpt=excerpt_line or step.content.strip()[:200],
                        )],
                        details={
                            "job": step.job_name,
                            "step": step.step_name,
                            "description": "CI workflow run: step contains suspicious shell patterns (pipe-to-shell, eval, base64 exec).",
                        },
                    ))
                    break  # One finding per step
    return findings


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

ALL_RED_FLAG_RULES = [
    detect_curl_pipe_sh,
    detect_download_exec,
    detect_postinstall_exec,
    detect_base64_exec,
    detect_eval_dynamic,
    detect_persistence,
    detect_gha_uses_remote,
    detect_gha_uses_unpinned,
    detect_gha_uses_docker,
    detect_gha_run_shell,
]


def run_red_flag_rules(file_map: FileMap) -> list[Finding]:
    """Run all red flag detection rules and return findings."""
    findings = []
    for rule_fn in ALL_RED_FLAG_RULES:
        findings.extend(rule_fn(file_map))
    return findings
