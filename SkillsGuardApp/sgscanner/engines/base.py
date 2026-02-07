"""Base engine protocol for all scan engines.

Uses structural subtyping (Protocol) instead of nominal inheritance.
Any class that implements `run()` and `engine_name` is a valid ScanEngine.
"""
from typing import Protocol, runtime_checkable
from ..models import Issue, Skill


@runtime_checkable
class ScanEngine(Protocol):
    """Protocol defining the interface for all scan engines.

    Any class implementing `run(skill) -> list[Issue]` and the
    `engine_name` property satisfies this protocol via structural typing.
    """

    engine_id: str
    supports_async: bool

    def run(self, skill: Skill) -> list[Issue]:
        """Execute the engine against a loaded skill and return issues found."""
        ...

    async def run_async(self, skill: Skill) -> list[Issue]:
        """Async variant of run(). Defaults to calling run() synchronously."""
        ...

    def engine_name(self) -> str:
        """Return the human-readable name of this engine."""
        ...


class EngineMixin:
    """Shared base implementation for scan engines.

    Provides default implementations for common engine functionality.
    Concrete engines should inherit from this and implement `run()`.
    """

    engine_id: str = "base_engine"
    supports_async: bool = False

    def __init__(self, name: str | None = None):
        self.name = name or self.engine_id

    def run(self, skill: Skill) -> list[Issue]:
        raise NotImplementedError("Subclasses must implement run()")

    async def run_async(self, skill: Skill) -> list[Issue]:
        """Default async implementation delegates to synchronous run()."""
        return self.run(skill)

    def engine_name(self) -> str:
        """Return the engine's display name."""
        return self.name

    @classmethod
    def get_id(cls) -> str:
        """Return the engine's unique identifier."""
        return cls.engine_id
