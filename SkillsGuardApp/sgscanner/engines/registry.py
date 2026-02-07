from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable
from .base import ScanEngine

class EngineRegistryError(RuntimeError):
    pass

class EngineNotFoundError(EngineRegistryError, KeyError):
    pass

class EngineAlreadyRegisteredError(EngineRegistryError):
    pass

@dataclass(frozen=True)
class EngineSpec:
    name: str
    detector_cls: type[ScanEngine]
    description: str | None = None
    aliases: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)
    availability_check: Callable[[], bool] | None = None

    def is_available(self) -> bool:
        if self.availability_check is None:
            return True
        try:
            return bool(self.availability_check())
        except Exception:
            return False

class EngineRegistry:

    def __init__(self) -> None:
        self._specs: dict[str, EngineSpec] = {}
        self._aliases: dict[str, str] = {}

    def register_class(self, detector_cls: type[ScanEngine], name: str | None=None, description: str | None=None, aliases: Iterable[str] | None=None, metadata: dict[str, Any] | None=None, availability_check: Callable[[], bool] | None=None) -> EngineSpec:
        detector_name = name or getattr(detector_cls, 'engine_id', detector_cls.__name__)
        alias_list = tuple(aliases or ())
        if detector_name in self._specs or detector_name in self._aliases:
            raise EngineAlreadyRegisteredError(f"Detector '{detector_name}' is already registered.")
        for alias in alias_list:
            if alias in self._specs or alias in self._aliases:
                raise EngineAlreadyRegisteredError(f"Detector alias '{alias}' is already registered.")
        spec = EngineSpec(name=detector_name, detector_cls=detector_cls, description=description, aliases=alias_list, metadata=metadata or {}, availability_check=availability_check)
        self._specs[detector_name] = spec
        for alias in alias_list:
            self._aliases[alias] = detector_name
        return spec

    def resolve_name(self, name: str) -> str:
        if name in self._specs:
            return name
        if name in self._aliases:
            return self._aliases[name]
        raise EngineNotFoundError(f"Detector '{name}' is not registered.")

    def get_spec(self, name: str) -> EngineSpec:
        canonical = self.resolve_name(name)
        return self._specs[canonical]

    def list_specs(self) -> list[EngineSpec]:
        return list(self._specs.values())

    def create(self, name: str, **kwargs: Any) -> ScanEngine:
        spec = self.get_spec(name)
        if not spec.is_available():
            raise EngineRegistryError(f"Detector '{spec.name}' is not available.")
        return spec.detector_cls(**kwargs)

    def list_api_entries(self) -> list[dict[str, Any]]:
        entries_with_order: list[tuple[int, dict[str, Any]]] = []
        for spec in self.list_specs():
            if not spec.metadata.get('expose_api', False):
                continue
            if not spec.is_available():
                continue
            entry = {'name': spec.name, 'description': spec.description or '', 'available': spec.is_available()}
            for key, value in spec.metadata.items():
                if key.startswith('expose_') or key == 'order':
                    continue
                entry[key] = value
            order = int(spec.metadata.get('order', 1000))
            entries_with_order.append((order, entry))
        entries_with_order.sort(key=lambda item: item[0])
        return [entry for _, entry in entries_with_order]
ENGINE_REGISTRY = EngineRegistry()

def register_engine(name: str | None=None, description: str | None=None, aliases: Iterable[str] | None=None, metadata: dict[str, Any] | None=None, availability_check: Callable[[], bool] | None=None) -> Callable[[type[ScanEngine]], type[ScanEngine]]:

    def decorator(detector_cls: type[ScanEngine]) -> type[ScanEngine]:
        ENGINE_REGISTRY.register_class(detector_cls=detector_cls, name=name, description=description, aliases=aliases, metadata=metadata, availability_check=availability_check)
        return detector_cls
    return decorator
