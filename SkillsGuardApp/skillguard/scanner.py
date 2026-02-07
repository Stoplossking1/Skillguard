"""
Scanner orchestrator.

Coordinates file loading, rule execution, deep skill analysis, scoring,
and result assembly. When a target contains a SKILL.md, the sgscanner
deep analysis engines are invoked automatically.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from pathlib import Path

from .loader import FileMap, cleanup_temp, extract_repo_name, load_target
from .models import (
    Context,
    FindingKind,
    Purpose,
    ScanResult,
)
from .rules.capabilities import run_capability_rules
from .rules.inspectability import run_inspectability_rules
from .rules.red_flags import run_red_flag_rules
from .scoring import compute_risk_label, compute_risk_score, rank_top_reasons


# ---------------------------------------------------------------------------
# Deep scan options
# ---------------------------------------------------------------------------

@dataclass
class DeepScanOptions:
    """Controls which sgscanner engines are enabled."""
    enabled: bool | None = None   # None = auto-detect (SKILL.md present)
    use_pattern: bool = True
    use_dataflow: bool = True
    use_llm: bool = False


# ---------------------------------------------------------------------------
# Purpose -> context mapping
# ---------------------------------------------------------------------------

EXPECTED_CAPABILITIES: dict[Purpose, set[str]] = {
    Purpose.AGENT_SKILL: {"SHELL_EXEC", "FS_WRITE", "NETWORK_EGRESS", "ENV_READ"},
    Purpose.FORMATTER: {"FS_WRITE"},
    Purpose.LINTER: {"FS_WRITE"},
    Purpose.BUILD_TOOL: {"SHELL_EXEC", "FS_WRITE", "NETWORK_EGRESS", "ENV_READ"},
    Purpose.DEVOPS: {"SHELL_EXEC", "FS_WRITE", "NETWORK_EGRESS", "ENV_READ", "SENSITIVE_PATH_READ"},
    Purpose.CLI: {"SHELL_EXEC", "FS_WRITE", "NETWORK_EGRESS", "ENV_READ"},
    Purpose.LIBRARY: set(),
    Purpose.UNKNOWN: set(),
}


def _apply_purpose_context(result: ScanResult) -> None:
    """Set context field on findings based on the scan purpose."""
    expected = EXPECTED_CAPABILITIES.get(result.purpose, set())
    for finding in result.findings:
        if finding.kind == FindingKind.CAPABILITY:
            if finding.code in expected:
                finding.context = Context.EXPECTED
            elif result.purpose == Purpose.UNKNOWN:
                finding.context = Context.UNKNOWN
            else:
                finding.context = Context.UNEXPECTED
        elif finding.kind == FindingKind.RED_FLAG:
            finding.context = Context.UNEXPECTED
        elif finding.kind == FindingKind.SKILL_THREAT:
            finding.context = Context.UNEXPECTED
        else:
            finding.context = Context.UNKNOWN


# ---------------------------------------------------------------------------
# Main scan function
# ---------------------------------------------------------------------------

def scan(
    target: str,
    purpose: Purpose = Purpose.UNKNOWN,
    deep: DeepScanOptions | None = None,
) -> ScanResult:
    """
    Scan a target (GitHub URL or local path) and return a ScanResult.

    This is the main entry point for the scanning engine.

    Args:
        target: GitHub URL or local directory path.
        purpose: Purpose context for the repo.
        deep: Options for deep skill analysis. None uses defaults (auto-detect).
    """
    if deep is None:
        deep = DeepScanOptions()

    start_time = time.time()

    # Load and categorize files
    file_map, is_temp = load_target(target)

    try:
        # Layer 1: Repo-level rules
        red_flag_findings = run_red_flag_rules(file_map)
        capability_findings = run_capability_rules(file_map)
        inspectability_findings = run_inspectability_rules(file_map)

        all_findings = red_flag_findings + capability_findings + inspectability_findings

        # Layer 2: Deep skill analysis (if applicable)
        should_run_deep = deep.enabled
        if should_run_deep is None:
            # Auto-detect: run deep scan if SKILL.md exists
            from .deep_scan import has_skill_md
            should_run_deep = has_skill_md(file_map.root)

        if should_run_deep:
            from .deep_scan import run_deep_skill_scan
            skill_findings = run_deep_skill_scan(
                target_dir=file_map.root,
                use_pattern=deep.use_pattern,
                use_dataflow=deep.use_dataflow,
                use_llm=deep.use_llm,
            )
            all_findings += skill_findings

        # Compute score and label
        risk_score = compute_risk_score(all_findings)
        risk_label = compute_risk_label(risk_score)

        # Rank top reasons
        top_reasons = rank_top_reasons(all_findings)

        scan_duration = time.time() - start_time

        result = ScanResult(
            repo_name=extract_repo_name(target),
            purpose=purpose,
            scan_duration_seconds=scan_duration,
            file_count=file_map.total_count,
            risk_score=risk_score,
            risk_label=risk_label,
            findings=all_findings,
            top_reasons=top_reasons,
        )

        # Apply purpose context to findings
        _apply_purpose_context(result)

        return result

    finally:
        if is_temp:
            cleanup_temp(file_map.root)
