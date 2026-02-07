import ast
from enum import Enum
from typing import Any

class TypeKind(Enum):
    UNKNOWN = 'unknown'
    INT = 'int'
    FLOAT = 'float'
    STR = 'str'
    BOOL = 'bool'
    LIST = 'list'
    DICT = 'dict'
    TUPLE = 'tuple'
    SET = 'set'
    NONE = 'none'
    FUNCTION = 'function'
    CLASS = 'class'
    ANY = 'any'

class Type:

    def __init__(self, kind: TypeKind, params: list['Type'] | None=None) -> None:
        self.kind = kind
        self.params = params or []

    def __str__(self) -> str:
        if self.params:
            params_str = ', '.join((str(p) for p in self.params))
            return f'{self.kind.value}[{params_str}]'
        return self.kind.value

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, Type):
            return False
        return self.kind == other.kind and self.params == other.params

class TypeAnalyzer:

    def __init__(self, ast_root: ast.AST):
        self.ast_root = ast_root
        self.node_types: dict[Any, Type] = {}
        self.var_types: dict[str, Type] = {}

    def run(self) -> None:
        self._analyze_python(self.ast_root)

    def _analyze_python(self, node: ast.AST) -> None:
        for n in ast.walk(node):
            inferred_type = self._infer_python_type(n)
            if inferred_type:
                self.node_types[n] = inferred_type
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for arg in n.args.args:
                    if arg.annotation:
                        param_type = self._annotation_to_type(arg.annotation)
                        self.var_types[arg.arg] = param_type
                    else:
                        self.var_types[arg.arg] = Type(TypeKind.ANY)
            if isinstance(n, ast.Assign):
                rhs_type = self.node_types.get(n.value, Type(TypeKind.UNKNOWN))
                for target in n.targets:
                    if isinstance(target, ast.Name):
                        self.var_types[target.id] = rhs_type

    def _infer_python_type(self, node: ast.AST) -> Type | None:
        if isinstance(node, ast.Constant):
            return self._infer_constant_type(node.value)
        elif isinstance(node, ast.List):
            return Type(TypeKind.LIST)
        elif isinstance(node, ast.Dict):
            return Type(TypeKind.DICT)
        elif isinstance(node, ast.Tuple):
            return Type(TypeKind.TUPLE)
        elif isinstance(node, ast.Set):
            return Type(TypeKind.SET)
        elif isinstance(node, ast.Compare):
            return Type(TypeKind.BOOL)
        elif isinstance(node, ast.BoolOp):
            return Type(TypeKind.BOOL)
        elif isinstance(node, ast.FunctionDef):
            return Type(TypeKind.FUNCTION)
        elif isinstance(node, ast.ClassDef):
            return Type(TypeKind.CLASS)
        return None

    def _infer_constant_type(self, value: Any) -> Type:
        if isinstance(value, bool):
            return Type(TypeKind.BOOL)
        elif isinstance(value, int):
            return Type(TypeKind.INT)
        elif isinstance(value, float):
            return Type(TypeKind.FLOAT)
        elif isinstance(value, str):
            return Type(TypeKind.STR)
        elif value is None:
            return Type(TypeKind.NONE)
        else:
            return Type(TypeKind.UNKNOWN)

    def _annotation_to_type(self, annotation: ast.AST) -> Type:
        if isinstance(annotation, ast.Name):
            type_name = annotation.id.lower()
            try:
                return Type(TypeKind(type_name))
            except ValueError:
                return Type(TypeKind.UNKNOWN)
        elif isinstance(annotation, ast.Constant):
            if isinstance(annotation.value, str):
                try:
                    return Type(TypeKind(annotation.value.lower()))
                except ValueError:
                    return Type(TypeKind.UNKNOWN)
        return Type(TypeKind.UNKNOWN)

    def get_type(self, var_name: str) -> Type:
        return self.var_types.get(var_name, Type(TypeKind.UNKNOWN))
