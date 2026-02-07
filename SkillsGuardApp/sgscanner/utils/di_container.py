from collections.abc import Callable
from typing import Any, TypeVar
from ..config.config import Config
T = TypeVar('T')

class DIContainer:

    def __init__(self):
        self._services: dict[type, Any] = {}
        self._singletons: dict[type, Any] = {}

    def register(self, service_type: type[T], instance: T, singleton: bool=True) -> None:
        if singleton:
            self._singletons[service_type] = instance
        else:
            self._services[service_type] = instance

    def register_factory(self, service_type: type[T], factory: Callable[[], T], singleton: bool=True) -> None:
        if singleton:
            self._singletons[service_type] = factory()
        else:
            self._services[service_type] = factory

    def get(self, service_type: type[T]) -> T | None:
        if service_type in self._singletons:
            return self._singletons[service_type]
        if service_type in self._services:
            service = self._services[service_type]
            if callable(service):
                return service()
            return service
        return None

    def get_or_create(self, service_type: type[T], factory: Callable[[], T] | None=None) -> T:
        instance = self.get(service_type)
        if instance is not None:
            return instance
        if factory is not None:
            instance = factory()
            self.register(service_type, instance)
            return instance
        raise ValueError(f'Service {service_type} not registered and no factory provided')

    def clear(self) -> None:
        self._services.clear()
        self._singletons.clear()
_container = DIContainer()

def get_container() -> DIContainer:
    return _container

def configure_default_services(config: Config | None=None) -> None:
    container = get_container()
    if config:
        container.register(Config, config)

def inject_config() -> Config:
    container = get_container()
    config = container.get(Config)
    if config is None:
        raise ValueError('Config not registered in DI container. Call configure_default_services() first.')
    return config
