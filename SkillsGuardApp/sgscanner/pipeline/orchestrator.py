"""Scan orchestrator using a pipeline-based execution model.

Replaces the simple for-loop approach with explicit phases, priorities,
and a shared context that accumulates results across engines.
"""
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..engines.base import ScanEngine, EngineMixin
from ..loader import SkillIngester, IngestionError
from ..models import Issue, ScanSummary, ScanOutcome, RiskLevel, Skill, ThreatClass

logger = logging.getLogger("sg.pipeline")

_STOP_WORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "can", "may", "might", "must", "shall", "to", "of", "in",
    "for", "on", "with", "at", "by", "from", "as", "into", "through",
    "and", "or", "but", "if", "then", "else", "when", "up", "down", "out",
    "that", "this", "these", "those", "it", "its", "they", "them", "their",
})


@dataclass
class ScanPhase:
    """A single phase in the scan pipeline.

    Attributes:
        engine: The scan engine to execute in this phase.
        priority: Lower values run first. Default is 0.
        enabled: Whether this phase should be executed.
    """
    engine: Any  # ScanEngine protocol
    priority: int = 0
    enabled: bool = True


@dataclass
class ScanContext:
    """Accumulated state passed through the pipeline.

    Collects issues and metadata from each phase as the pipeline executes.
    """
    skill: Skill
    issues: list[Issue] = field(default_factory=list)
    engine_names: list[str] = field(default_factory=list)
    validated_binary_files: set[str] = field(default_factory=set)
    start_time: float = field(default_factory=time.time)

    def accumulate(self, phase_issues: list[Issue], engine: Any) -> None:
        """Merge results from a single phase into the context."""
        self.issues.extend(phase_issues)
        self.engine_names.append(engine.engine_name())
        if hasattr(engine, "validated_binary_files"):
            self.validated_binary_files.update(engine.validated_binary_files)

    def finalize(self, skill_directory: Path) -> ScanOutcome:
        """Build the final ScanOutcome after all phases complete."""
        # Filter out binary findings that were validated by other engines
        if self.validated_binary_files:
            self.issues = [
                f for f in self.issues
                if not (f.rule_id == "BINARY_FILE_DETECTED"
                        and f.file_path in self.validated_binary_files)
            ]

        duration = time.time() - self.start_time
        return ScanOutcome(
            skill_name=self.skill.name,
            skill_directory=str(skill_directory.absolute()),
            findings=self.issues,
            scan_duration_seconds=duration,
            engines_used=self.engine_names,
        )


class ScanPipeline:
    """Ordered pipeline of scan phases.

    Engines are wrapped in ScanPhase objects and sorted by priority
    before execution. The pipeline feeds a shared ScanContext through
    each phase sequentially.
    """

    def __init__(self) -> None:
        self.phases: list[ScanPhase] = []

    def add_phase(self, engine: Any, priority: int = 0) -> "ScanPipeline":
        """Add an engine as a pipeline phase. Returns self for chaining."""
        self.phases.append(ScanPhase(engine=engine, priority=priority))
        return self

    def execute(self, skill: Skill, skill_directory: Path) -> ScanOutcome:
        """Run all enabled phases in priority order and return the outcome."""
        ctx = ScanContext(skill=skill)
        for phase in sorted(self.phases, key=lambda p: p.priority):
            if not phase.enabled:
                continue
            phase_issues = phase.engine.run(skill)
            ctx.accumulate(phase_issues, phase.engine)
        return ctx.finalize(skill_directory)

    def list_engines(self) -> list[str]:
        """Return names of all engines in the pipeline."""
        return [p.engine.engine_name() for p in self.phases]


class ScanOrchestrator:
    """High-level orchestrator that manages a ScanPipeline.

    Accepts a list of engines and wraps them in a pipeline for execution.
    Provides convenience methods for scanning individual skills and directories.
    """

    def __init__(
        self,
        engines: list[Any] | None = None,
        use_virustotal: bool = False,
        virustotal_api_key: str | None = None,
        virustotal_upload_files: bool = False,
    ):
        self._pipeline = ScanPipeline()
        self._ingester = SkillIngester()

        if engines is None:
            from ..engines.pattern import PatternEngine
            engines = [PatternEngine()]
            if use_virustotal and virustotal_api_key:
                from ..engines.virustotal import VirusTotalEngine
                engines.append(VirusTotalEngine(
                    api_key=virustotal_api_key,
                    enabled=True,
                    upload_files=virustotal_upload_files,
                ))

        for idx, engine in enumerate(engines):
            self._pipeline.add_phase(engine, priority=idx)

    # Keep backward-compatible attribute
    @property
    def engines(self) -> list[Any]:
        return [p.engine for p in self._pipeline.phases]

    def inspect(self, skill_directory: Path) -> ScanOutcome:
        """Scan a single skill directory and return the outcome."""
        if not isinstance(skill_directory, Path):
            skill_directory = Path(skill_directory)
        skill = self._ingester.ingest(skill_directory)
        return self._pipeline.execute(skill, skill_directory)

    def inspect_directory(
        self,
        skills_directory: Path,
        recursive: bool = False,
        check_overlap: bool = False,
    ) -> ScanSummary:
        """Scan all skills in a directory and return a summary report."""
        if not isinstance(skills_directory, Path):
            skills_directory = Path(skills_directory)
        if not skills_directory.exists():
            raise FileNotFoundError(f"Directory does not exist: {skills_directory}")

        skill_dirs = self._find_skill_directories(skills_directory, recursive)
        report = ScanSummary()
        loaded_skills: list[Skill] = []

        for skill_dir in skill_dirs:
            try:
                skill = self._ingester.ingest(skill_dir)
                outcome = self._pipeline.execute(skill, skill_dir)
                report.add_scan_result(outcome)
                if check_overlap:
                    loaded_skills.append(skill)
            except IngestionError as e:
                logger.warning("Failed to scan %s: %s", skill_dir, e)
                continue

        if check_overlap and len(loaded_skills) > 1:
            overlap_issues = self._check_description_overlap(loaded_skills)
            if overlap_issues and report.scan_results:
                report.scan_results[0].findings.extend(overlap_issues)
            try:
                from ..engines.cross_skill import CrossSkillEngine
                cross_engine = CrossSkillEngine()
                cross_issues = cross_engine.analyze_skill_set(loaded_skills)
                if cross_issues and report.scan_results:
                    report.scan_results[0].findings.extend(cross_issues)
            except ImportError:
                pass

        return report

    def add_engine(self, engine: Any, priority: int | None = None) -> None:
        """Add an engine to the pipeline at the given priority."""
        prio = priority if priority is not None else len(self._pipeline.phases)
        self._pipeline.add_phase(engine, priority=prio)

    def list_engines(self) -> list[str]:
        """Return names of all engines in the pipeline."""
        return self._pipeline.list_engines()

    # ── Private helpers ──────────────────────────────────────────────

    def _check_description_overlap(self, skills: list[Skill]) -> list[Issue]:
        """Detect skills with dangerously similar descriptions."""
        issues: list[Issue] = []
        for i, skill_a in enumerate(skills):
            for skill_b in skills[i + 1:]:
                similarity = self._jaccard_similarity(
                    skill_a.description, skill_b.description
                )
                if similarity > 0.7:
                    issues.append(Issue(
                        id=f"OVERLAP_{hash(skill_a.name + skill_b.name) & 0xFFFF_FFFF:08x}",
                        rule_id="TRIGGER_OVERLAP_RISK",
                        category=ThreatClass.SOCIAL_ENGINEERING,
                        severity=RiskLevel.MEDIUM,
                        title="Skills have overlapping descriptions",
                        description=(
                            f"Skills '{skill_a.name}' and '{skill_b.name}' have "
                            f"{similarity:.0%} similar descriptions. This may cause "
                            f"confusion or enable trigger hijacking attacks."
                        ),
                        file_path=f"{skill_a.name}/SKILL.md",
                        remediation=(
                            "Make skill descriptions more distinct by clearly specifying "
                            "unique capabilities, file types, or use cases."
                        ),
                        metadata={
                            "skill_a": skill_a.name,
                            "skill_b": skill_b.name,
                            "similarity": similarity,
                        },
                    ))
                elif similarity > 0.5:
                    issues.append(Issue(
                        id=f"OVERLAP_WARN_{hash(skill_a.name + skill_b.name) & 0xFFFF_FFFF:08x}",
                        rule_id="TRIGGER_OVERLAP_WARNING",
                        category=ThreatClass.SOCIAL_ENGINEERING,
                        severity=RiskLevel.LOW,
                        title="Skills have somewhat similar descriptions",
                        description=(
                            f"Skills '{skill_a.name}' and '{skill_b.name}' have "
                            f"{similarity:.0%} similar descriptions."
                        ),
                        file_path=f"{skill_a.name}/SKILL.md",
                        remediation="Consider making skill descriptions more distinct.",
                        metadata={
                            "skill_a": skill_a.name,
                            "skill_b": skill_b.name,
                            "similarity": similarity,
                        },
                    ))
        return issues

    @staticmethod
    def _jaccard_similarity(text_a: str, text_b: str) -> float:
        """Compute Jaccard similarity between two text strings."""
        tokens_a = set(re.findall(r"\b[a-zA-Z]+\b", text_a.lower())) - _STOP_WORDS
        tokens_b = set(re.findall(r"\b[a-zA-Z]+\b", text_b.lower())) - _STOP_WORDS
        if not tokens_a or not tokens_b:
            return 0.0
        intersection = len(tokens_a & tokens_b)
        union = len(tokens_a | tokens_b)
        return intersection / union if union > 0 else 0.0

    @staticmethod
    def _find_skill_directories(directory: Path, recursive: bool) -> list[Path]:
        """Discover skill directories by locating SKILL.md files."""
        skill_dirs: list[Path] = []
        if recursive:
            for skill_md in directory.rglob("SKILL.md"):
                skill_dirs.append(skill_md.parent)
        else:
            for item in directory.iterdir():
                if item.is_dir() and (item / "SKILL.md").exists():
                    skill_dirs.append(item)
        return skill_dirs


# ── Module-level convenience functions ───────────────────────────────

def inspect_skill(
    skill_directory: Path,
    engines: list[Any] | None = None,
) -> ScanOutcome:
    """Scan a single skill directory (convenience wrapper)."""
    orchestrator = ScanOrchestrator(engines=engines)
    return orchestrator.inspect(skill_directory)


def inspect_directory(
    skills_directory: Path,
    recursive: bool = False,
    engines: list[Any] | None = None,
    check_overlap: bool = False,
) -> ScanSummary:
    """Scan all skills in a directory (convenience wrapper)."""
    orchestrator = ScanOrchestrator(engines=engines)
    return orchestrator.inspect_directory(
        skills_directory, recursive=recursive, check_overlap=check_overlap
    )
