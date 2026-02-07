"""
CLI reporter for SkillsGuard.

Generates human-friendly terminal output and machine-friendly JSON.
The pretty output matches the website terminal demo exactly.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict

from .models import Finding, FindingKind, RiskLabel, ScanResult


# ---------------------------------------------------------------------------
# ANSI colors (disabled if not a TTY)
# ---------------------------------------------------------------------------

def _supports_color() -> bool:
    return hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


class _Colors:
    """ANSI color codes."""
    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        if not self.enabled:
            return text
        return f"\033[{code}m{text}\033[0m"

    def red(self, t: str) -> str:      return self._wrap("31", t)
    def green(self, t: str) -> str:    return self._wrap("32", t)
    def yellow(self, t: str) -> str:   return self._wrap("33", t)
    def blue(self, t: str) -> str:     return self._wrap("34", t)
    def magenta(self, t: str) -> str:  return self._wrap("35", t)
    def cyan(self, t: str) -> str:     return self._wrap("36", t)
    def white(self, t: str) -> str:    return self._wrap("97", t)
    def dim(self, t: str) -> str:      return self._wrap("2", t)
    def bold(self, t: str) -> str:     return self._wrap("1", t)


C = _Colors(_supports_color())


# ---------------------------------------------------------------------------
# Risk level bar
# ---------------------------------------------------------------------------

def _risk_bar(score: float, label: RiskLabel) -> str:
    """Generate a risk level bar: █████████░  HIGH (7.2/10)"""
    filled = int(round(score))
    empty = 10 - filled
    bar = "█" * filled + "░" * empty

    label_str = label.value
    color_fn = {
        RiskLabel.LOW: C.green,
        RiskLabel.MEDIUM: C.yellow,
        RiskLabel.HIGH: C.red,
        RiskLabel.CRITICAL: C.red,
    }.get(label, C.white)

    return f"{color_fn(bar)}  {color_fn(label_str)} ({score}/10)"


# ---------------------------------------------------------------------------
# Pretty reporter
# ---------------------------------------------------------------------------

def format_pretty(result: ScanResult) -> str:
    """Generate human-friendly terminal output."""
    lines: list[str] = []

    # Header
    lines.append("")
    lines.append(C.dim("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    lines.append(C.bold("  SkillsGuard Risk Report"))
    lines.append(C.dim("  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"))
    lines.append("")

    # Metadata
    lines.append(f"  {C.dim('Repo:')}      {C.white(result.repo_name)}")
    lines.append(f"  {C.dim('Purpose:')}   {C.white(result.purpose.value)}")
    lines.append(f"  {C.dim('Scanned:')}   {C.white(f'{result.file_count} files in {result.scan_duration_seconds:.1f}s')}")
    lines.append("")

    # Risk level
    lines.append(f"  {C.bold('Risk Level:')} {_risk_bar(result.risk_score, result.risk_label)}")
    lines.append("")

    # Red Flags
    red_flags = result.red_flags
    if red_flags:
        lines.append(C.bold("  Red Flags:"))
        for f in red_flags:
            # Group evidence by finding
            for ev in f.evidence[:5]:  # Show up to 5 evidence items
                loc = ""
                if ev.file:
                    loc = ev.file
                    if ev.line:
                        loc += f":{ev.line}"
                lines.append(f"  {C.red('✗')} {C.red(f.code):<24s} {C.dim(loc)}")
                if ev.excerpt:
                    lines.append(f"    {C.white(ev.excerpt)}")
        lines.append("")

    # Capabilities
    capabilities = result.capabilities
    if capabilities:
        lines.append(C.bold("  Capabilities:"))
        for f in capabilities:
            file_count = f.details.get("files_affected", len(f.evidence))
            suffix = f"{file_count} file{'s' if file_count != 1 else ''}"
            lines.append(f"  {C.blue('●')} {C.blue(f.code):<24s} {C.dim(suffix)}")
            # Show specific env vars or sensitive paths if relevant
            if f.code == "ENV_READ":
                env_refs = _extract_env_refs(f)
                if env_refs:
                    lines.append(f"    {C.dim(', '.join(env_refs[:5]))}")
        lines.append("")

    # Inspectability
    inspectability = result.inspectability
    if inspectability:
        lines.append(C.bold("  Inspectability:"))
        for f in inspectability:
            for ev in f.evidence[:3]:
                detail = ""
                if ev.file:
                    detail = ev.file
                if ev.excerpt and f.code != "LOCKFILE_PRESENT":
                    detail += f" ({ev.excerpt})" if detail else ev.excerpt
                lines.append(f"  {C.yellow('⚠')} {C.yellow(f.code):<24s} {C.dim(detail)}")
        lines.append("")

    # Skill Threats (from deep analysis)
    skill_threats = result.skill_threats
    if skill_threats:
        lines.append(C.bold("  Skill Threats:"))
        for f in skill_threats:
            for ev in f.evidence[:5]:
                loc = ""
                if ev.file:
                    loc = ev.file
                    if ev.line:
                        loc += f":{ev.line}"
                lines.append(f"  {C.magenta('✗')} {C.magenta(f.code):<24s} {C.dim(loc)}")
                if ev.excerpt:
                    lines.append(f"    {C.white(ev.excerpt)}")
            # Show remediation if available
            remediation = f.details.get("remediation")
            if remediation:
                lines.append(f"    {C.dim('Fix: ' + remediation[:120])}")
            # Show engine that detected it
            engine = f.details.get("engine")
            if engine:
                lines.append(f"    {C.dim('Engine: ' + engine)}")
        lines.append("")

    # Disclaimer
    lines.append(C.dim("  ⓘ Static analysis only — code was never executed."))
    lines.append("")

    return "\n".join(lines)


def _extract_env_refs(finding: Finding) -> list[str]:
    """Extract environment variable names from evidence excerpts."""
    import re
    refs = set()
    pattern = re.compile(r"(?:process\.env\.(\w+)|os\.(?:environ|getenv)\s*\(\s*['\"](\w+)['\"])")
    for ev in finding.evidence:
        if ev.excerpt:
            for match in pattern.finditer(ev.excerpt):
                ref = match.group(1) or match.group(2)
                if ref:
                    refs.add(ref)
    return sorted(refs)


# ---------------------------------------------------------------------------
# JSON reporter
# ---------------------------------------------------------------------------

def format_json(result: ScanResult, pretty: bool = True) -> str:
    """Generate machine-friendly JSON output."""
    indent = 2 if pretty else None
    return json.dumps(result.to_dict(), indent=indent, default=str)
