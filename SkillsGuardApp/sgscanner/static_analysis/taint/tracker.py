from dataclasses import dataclass, field
from enum import Enum

class TaintStatus(Enum):
    TAINTED = 'tainted'
    UNTAINTED = 'untainted'
    UNKNOWN = 'unknown'

@dataclass
class Taint:
    status: TaintStatus = TaintStatus.UNTAINTED
    labels: set[str] = field(default_factory=set)

    def is_tainted(self) -> bool:
        return self.status == TaintStatus.TAINTED

    def add_label(self, label: str) -> None:
        self.labels.add(label)

    def has_label(self, label: str) -> bool:
        return label in self.labels

    def merge(self, other: 'Taint') -> 'Taint':
        if not self.is_tainted() and (not other.is_tainted()):
            return Taint(status=TaintStatus.UNTAINTED)
        return Taint(status=TaintStatus.TAINTED, labels=self.labels | other.labels)

    def copy(self) -> 'Taint':
        return Taint(status=self.status, labels=self.labels.copy())

class ShapeEnvironment:

    def __init__(self) -> None:
        self._shapes: dict[str, TaintShape] = {}

    def get(self, var_name: str) -> 'TaintShape':
        if var_name not in self._shapes:
            self._shapes[var_name] = TaintShape()
        return self._shapes[var_name]

    def set_taint(self, var_name: str, taint: Taint) -> None:
        shape = self.get(var_name)
        shape.set_taint(taint)

    def get_taint(self, var_name: str) -> Taint:
        if var_name in self._shapes:
            return self._shapes[var_name].get_taint()
        return Taint(status=TaintStatus.UNTAINTED)

    def copy(self) -> 'ShapeEnvironment':
        new_env = ShapeEnvironment()
        for var_name, shape in self._shapes.items():
            new_env._shapes[var_name] = shape.copy()
        return new_env

    def merge(self, other: 'ShapeEnvironment') -> 'ShapeEnvironment':
        merged = ShapeEnvironment()
        all_vars = set(self._shapes.keys()) | set(other._shapes.keys())
        for var_name in all_vars:
            self_taint = self.get_taint(var_name)
            other_taint = other.get_taint(var_name)
            merged.set_taint(var_name, self_taint.merge(other_taint))
        return merged

class TaintShape:
    MAX_DEPTH = 3

    def __init__(self, taint: Taint | None=None, depth: int=0):
        self.scalar_taint = taint or Taint()
        self.fields: dict[str, TaintShape] = {}
        self.element_shape: TaintShape | None = None
        self.is_object = False
        self.is_array = False
        self.depth = depth
        self.collapsed = depth >= self.MAX_DEPTH

    def get_taint(self) -> Taint:
        return self.scalar_taint

    def set_taint(self, taint: Taint) -> None:
        self.scalar_taint = taint

    def get_field(self, field: str) -> Taint:
        if self.scalar_taint.is_tainted():
            return self.scalar_taint
        if field in self.fields:
            return self.fields[field].get_taint()
        return Taint(status=TaintStatus.UNTAINTED)

    def set_field(self, field: str, taint: Taint) -> None:
        if self.collapsed:
            self.scalar_taint = self.scalar_taint.merge(taint)
            return
        self.is_object = True
        if field not in self.fields:
            self.fields[field] = TaintShape(depth=self.depth + 1)
        self.fields[field].set_taint(taint)

    def get_element(self) -> Taint:
        if self.scalar_taint.is_tainted():
            return self.scalar_taint
        if self.element_shape:
            return self.element_shape.get_taint()
        return Taint(status=TaintStatus.UNTAINTED)

    def set_element(self, taint: Taint) -> None:
        if self.collapsed:
            self.scalar_taint = self.scalar_taint.merge(taint)
            return
        self.is_array = True
        if not self.element_shape:
            self.element_shape = TaintShape(depth=self.depth + 1)
        self.element_shape.set_taint(taint)

    def copy(self) -> 'TaintShape':
        new_shape = TaintShape(taint=self.scalar_taint.copy(), depth=self.depth)
        new_shape.is_object = self.is_object
        new_shape.is_array = self.is_array
        new_shape.collapsed = self.collapsed
        for field_name, shape in self.fields.items():
            new_shape.fields[field_name] = shape.copy()
        if self.element_shape:
            new_shape.element_shape = self.element_shape.copy()
        return new_shape
