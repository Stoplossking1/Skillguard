"""SGScanner - Security scanner for AI agent skills packages."""

try:
    from ._version import __version__
except ImportError:
    __version__ = "0.0.0+unknown"

__author__ = "SkillsGuard"

# Core imports that should always work
from .config.config import Config
from .config.constants import ScanOrchestratorConstants as SGConstants
from .models import Issue, ScanSummary, ScanOutcome, RiskLevel, Skill, ThreatClass

# Lazy imports for components with optional dependencies
try:
    from .loader import SkillIngester, ingest
except ImportError:
    SkillIngester = None  # type: ignore[assignment, misc]
    ingest = None  # type: ignore[assignment]

try:
    from .pipeline.orchestrator import ScanOrchestrator, inspect_skill, inspect_directory
except ImportError:
    ScanOrchestrator = None  # type: ignore[assignment, misc]
    inspect_skill = None  # type: ignore[assignment]
    inspect_directory = None  # type: ignore[assignment]

__all__ = [
    "ScanOrchestrator",
    "inspect_skill",
    "inspect_directory",
    "Skill",
    "Issue",
    "ScanOutcome",
    "ScanSummary",
    "RiskLevel",
    "ThreatClass",
    "SkillIngester",
    "ingest",
    "Config",
    "SGConstants",
]
