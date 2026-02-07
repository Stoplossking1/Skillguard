import ast
from typing import Any, Optional

class Scope:

    def __init__(self, parent: Optional['Scope']=None) -> None:
        self.parent = parent
        self.symbols: dict[str, Any] = {}
        self.children: list[Scope] = []

    def define(self, name: str, node: Any) -> None:
        self.symbols[name] = node

    def lookup(self, name: str) -> Any | None:
        if name in self.symbols:
            return self.symbols[name]
        elif self.parent:
            return self.parent.lookup(name)
        return None

class NameResolver:

    def __init__(self, ast_root: ast.AST):
        self.ast_root = ast_root
        self.global_scope = Scope()
        self.current_scope = self.global_scope
        self.name_to_def: dict[Any, Any] = {}

    def resolve(self) -> None:
        self._resolve_python(self.ast_root)

    def _resolve_python(self, node: ast.AST) -> None:
        self._visit_node(node)

    def _visit_node(self, node: ast.AST) -> None:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            self._visit_function(node)
        elif isinstance(node, ast.ClassDef):
            self._visit_class(node)
        elif isinstance(node, ast.Assign):
            self._define_assignment(node)
            for child in ast.iter_child_nodes(node):
                self._visit_node(child)
        elif isinstance(node, ast.Import):
            self._define_import(node)
        elif isinstance(node, ast.ImportFrom):
            self._define_import_from(node)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            self._resolve_name(node)
        else:
            for child in ast.iter_child_nodes(node):
                self._visit_node(child)

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        self.current_scope.define(node.name, node)
        func_scope = Scope(parent=self.current_scope)
        self.current_scope.children.append(func_scope)
        old_scope = self.current_scope
        self.current_scope = func_scope
        for arg in node.args.args:
            func_scope.define(arg.arg, arg)
        for child in node.body:
            self._visit_node(child)
        self.current_scope = old_scope

    def _visit_class(self, node: ast.ClassDef) -> None:
        self.current_scope.define(node.name, node)
        class_scope = Scope(parent=self.current_scope)
        self.current_scope.children.append(class_scope)
        old_scope = self.current_scope
        self.current_scope = class_scope
        for child in node.body:
            self._visit_node(child)
        self.current_scope = old_scope

    def _define_assignment(self, node: ast.Assign) -> None:
        for target in node.targets:
            if isinstance(target, ast.Name):
                self.current_scope.define(target.id, node)
            elif isinstance(target, ast.Tuple):
                for elt in target.elts:
                    if isinstance(elt, ast.Name):
                        self.current_scope.define(elt.id, node)

    def _define_import(self, node: ast.Import) -> None:
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.current_scope.define(name, node)

    def _define_import_from(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            name = alias.asname if alias.asname else alias.name
            self.current_scope.define(name, node)

    def _resolve_name(self, node: ast.Name) -> None:
        definition = self.current_scope.lookup(node.id)
        if definition:
            self.name_to_def[node] = definition

    def get_definition(self, node: Any) -> Any | None:
        return self.name_to_def.get(node)
