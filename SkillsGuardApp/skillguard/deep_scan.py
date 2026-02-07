"""
Bridge module: connects sgscanner deep analysis into the SkillsGuard pipeline.

When a target directory contains a SKILL.md file, this module runs sgscanner's
multi-engine analysis and converts the results back into SkillsGuard Finding objects.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any

from .models import (
    Confidence,
    Evidence,
    Finding,
    FindingKind,
    Severity,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping: sgscanner RiskLevel -> skillguard Severity
# ---------------------------------------------------------------------------

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.HIGH,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.LOW,
    "SAFE": Severity.LOW,
}


# ---------------------------------------------------------------------------
# Confidence heuristic based on engine type
# ---------------------------------------------------------------------------

_ENGINE_CONFIDENCE: dict[str, Confidence] = {
    "pattern": Confidence.HIGH,
    "dataflow": Confidence.HIGH,
    "semantic": Confidence.MEDIUM,
    "llm": Confidence.MEDIUM,
    "meta": Confidence.MEDIUM,
    "aidefense": Confidence.HIGH,
    "virustotal": Confidence.HIGH,
    "description": Confidence.MEDIUM,
}


# ---------------------------------------------------------------------------
# API key resolution
# ---------------------------------------------------------------------------

def _resolve_openai_key() -> str | None:
    """Resolve the OpenAI API key from environment or .env file."""
    # Check if already in environment (e.g., loaded by dotenv earlier)
    key = os.getenv("OPEN_AI_API") or os.getenv("OPENAI_API_KEY")
    if key:
        return key

    # Try loading from .env in project root
    try:
        from dotenv import load_dotenv
        # Walk up to find .env
        for candidate in [Path.cwd() / ".env", Path(__file__).parent.parent / ".env"]:
            if candidate.exists():
                load_dotenv(candidate)
                key = os.getenv("OPEN_AI_API") or os.getenv("OPENAI_API_KEY")
                if key:
                    return key
    except ImportError:
        pass

    return None


# ---------------------------------------------------------------------------
# Core bridge function
# ---------------------------------------------------------------------------

def has_skill_md(target_dir: Path) -> bool:
    """Check if the target directory contains a SKILL.md file."""
    return (target_dir / "SKILL.md").exists()


def run_deep_skill_scan(
    target_dir: Path,
    use_dataflow: bool = True,
    use_llm: bool = False,
    use_pattern: bool = True,
) -> list[Finding]:
    """
    Run sgscanner deep analysis on a skill directory and return skillguard Findings.

    Args:
        target_dir: Path to the skill directory (must contain SKILL.md).
        use_dataflow: Enable dataflow/taint analysis engine.
        use_llm: Enable LLM semantic analysis engine (requires API key).
        use_pattern: Enable pattern matching engine (YARA + regex).

    Returns:
        List of skillguard Finding objects from the deep analysis.
    """
    if not has_skill_md(target_dir):
        return []

    try:
        from sgscanner.pipeline.orchestrator import ScanOrchestrator
        from sgscanner.engines.pattern import PatternEngine
    except ImportError as e:
        logger.warning("sgscanner not available for deep analysis: %s", e)
        return []

    # Build the engine list
    engines: list[Any] = []

    if use_pattern:
        try:
            engines.append(PatternEngine())
        except Exception as e:
            logger.warning("Could not initialize PatternEngine: %s", e)

    if use_dataflow:
        try:
            from sgscanner.engines.dataflow import DataflowEngine
            engines.append(DataflowEngine(use_static_analysis=True))
        except (ImportError, Exception) as e:
            logger.warning("Could not initialize DataflowEngine: %s", e)

    if use_llm:
        api_key = _resolve_openai_key()
        if api_key:
            try:
                from sgscanner.engines.llm_engine import LLMEngine
                engines.append(LLMEngine(
                    model="gpt-4o",
                    api_key=api_key,
                ))
                logger.info("LLM engine enabled with OpenAI gpt-4o")
            except (ImportError, Exception) as e:
                logger.warning("Could not initialize LLMEngine: %s", e)
        else:
            logger.warning(
                "LLM engine requested but no API key found. "
                "Set OPEN_AI_API in .env or OPENAI_API_KEY in environment."
            )

    if not engines:
        logger.warning("No sgscanner engines available; skipping deep analysis.")
        return []

    # Run the scan
    try:
        orchestrator = ScanOrchestrator(engines=engines)
        outcome = orchestrator.inspect(target_dir)
    except Exception as e:
        logger.error("Deep skill scan failed: %s", e)
        return []

    # Convert sgscanner Issues -> skillguard Findings
    return _convert_issues(outcome.findings)


def _convert_issues(issues: list) -> list[Finding]:
    """Convert a list of sgscanner Issue objects to skillguard Finding objects."""
    findings: list[Finding] = []

    for issue in issues:
        severity = _SEVERITY_MAP.get(
            issue.severity.value if hasattr(issue.severity, "value") else str(issue.severity),
            Severity.MEDIUM,
        )

        engine_name = issue.engine or "unknown"
        confidence = _ENGINE_CONFIDENCE.get(engine_name, Confidence.MEDIUM)

        # Build evidence from the issue
        evidence_list: list[Evidence] = []
        if issue.file_path:
            evidence_list.append(Evidence(
                file=issue.file_path,
                line=issue.line_number,
                excerpt=issue.snippet[:200] if issue.snippet else issue.title,
            ))

        # Build details dict
        details: dict[str, Any] = {
            "description": issue.description,
            "engine": engine_name,
            "rule_id": issue.rule_id,
        }
        if issue.remediation:
            details["remediation"] = issue.remediation
        if issue.metadata:
            # Include AITech codes if present
            for key in ("aitech", "aitech_name", "aisubtech", "aisubtech_name"):
                if key in issue.metadata:
                    details[key] = issue.metadata[key]

        findings.append(Finding(
            kind=FindingKind.SKILL_THREAT,
            code=issue.rule_id,
            title=issue.title,
            severity=severity,
            confidence=confidence,
            evidence=evidence_list,
            details=details,
        ))

    return findings
