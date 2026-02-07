import ast
import logging
from pathlib import Path
from typing import Any

class CallGraph:

    def __init__(self) -> None:
        self.functions: dict[str, Any] = {}
        self.calls: list[tuple] = []
        self.entry_points: set[str] = set()

    def add_function(self, name: str, node: Any, file_path: Path, is_entry_point: bool=False) -> None:
        full_name = f'{file_path}::{name}'
        self.functions[full_name] = node
        if is_entry_point:
            self.entry_points.add(full_name)

    def add_call(self, caller: str, callee: str) -> None:
        self.calls.append((caller, callee))

    def get_callees(self, func_name: str) -> list[str]:
        return [callee for caller, callee in self.calls if caller == func_name]

    def get_entry_points(self) -> set[str]:
        return self.entry_points.copy()

class CallGraphAnalyzer:

    def __init__(self) -> None:
        self.call_graph = CallGraph()
        self.engines: dict[Path, ast.Module] = {}
        self.import_map: dict[Path, list[Path]] = {}
        self.logger = logging.getLogger('sg.' + __name__)

    def add_file(self, file_path: Path, source_code: str) -> None:
        try:
            tree = ast.parse(source_code)
            self.engines[file_path] = tree
            self._extract_functions(file_path, tree)
            self._extract_imports(file_path, tree)
        except SyntaxError as e:
            self.logger.debug(f'Skipping unparseable file {file_path}: {e}')

    def _extract_functions(self, file_path: Path, tree: ast.Module) -> None:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                is_entry = self._is_entry_point(node)
                self.call_graph.add_function(node.name, node, file_path, is_entry)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        method_full_name = f'{class_name}.{item.name}'
                        self.call_graph.add_function(method_full_name, item, file_path, False)

    def _is_entry_point(self, func_def: ast.FunctionDef) -> bool:
        name_lower = func_def.name.lower()
        if name_lower in ['main', 'run', 'execute', 'process', 'handle']:
            return True
        if name_lower.startswith(('main_', 'run_', 'execute_', 'process_', 'handle_')):
            return True
        if func_def.decorator_list:
            return True
        return False

    def _extract_imports(self, file_path: Path, tree: ast.Module) -> None:
        imported_files = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_name = alias.name
                    imported_file = self._resolve_import(file_path, module_name)
                    if imported_file:
                        imported_files.append(imported_file)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    imported_file = self._resolve_import(file_path, node.module)
                    if imported_file:
                        imported_files.append(imported_file)
        self.import_map[file_path] = imported_files

    def _resolve_import(self, from_file: Path, module_name: str) -> Path | None:
        module_parts = module_name.split('.')
        current_dir = from_file.parent
        for i in range(len(module_parts), 0, -1):
            potential_path = current_dir / '/'.join(module_parts[:i])
            py_file = potential_path.with_suffix('.py')
            if py_file.exists():
                return py_file
            init_file = potential_path / '__init__.py'
            if init_file.exists():
                return init_file
        return None

    def build_call_graph(self) -> CallGraph:
        for file_path, tree in self.engines.items():
            self._extract_calls(file_path, tree)
        return self.call_graph

    def _extract_calls(self, file_path: Path, tree: ast.Module) -> None:
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                caller_name = f'{file_path}::{node.name}'
                self._extract_calls_from_function(file_path, node, caller_name)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                class_name = node.name
                for item in node.body:
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        caller_name = f'{file_path}::{class_name}.{item.name}'
                        self._extract_calls_from_function(file_path, item, caller_name)

    def _extract_calls_from_function(self, file_path: Path, func_node: ast.FunctionDef, caller_name: str) -> None:
        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                callee_name = self._get_call_name(node)
                full_callee = self._resolve_call_target(file_path, callee_name)
                if full_callee:
                    self.call_graph.add_call(caller_name, full_callee)
                else:
                    self.call_graph.add_call(caller_name, callee_name)

    def _get_call_name(self, node: ast.Call) -> str:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            current = node.func
            while isinstance(current, ast.Attribute):
                parts.append(current.attr)
                current = current.value
            if isinstance(current, ast.Name):
                parts.append(current.id)
            return '.'.join(reversed(parts))
        try:
            return ast.unparse(node.func)
        except (AttributeError, TypeError, ValueError):
            return '<unknown>'

    def _resolve_call_target(self, file_path: Path, call_name: str) -> str | None:
        for func_name in self.call_graph.functions.keys():
            if func_name.endswith(f'::{call_name}'):
                if func_name.startswith(str(file_path)):
                    return func_name
        if file_path in self.import_map:
            for imported_file in self.import_map[file_path]:
                potential_name = f'{imported_file}::{call_name}'
                if potential_name in self.call_graph.functions:
                    return potential_name
        return None

    def get_reachable_functions(self, start_func: str) -> list[str]:
        reachable = set()
        to_visit = [start_func]
        visited = set()
        while to_visit:
            current = to_visit.pop()
            if current in visited:
                continue
            visited.add(current)
            reachable.add(current)
            callees = self.call_graph.get_callees(current)
            for callee in callees:
                if callee not in visited:
                    to_visit.append(callee)
        return list(reachable)

    def analyze_parameter_flow_across_files(self, entry_point: str, param_names: list[str]) -> dict[str, Any]:
        reachable = self.get_reachable_functions(entry_point)
        param_influenced_funcs = set()
        cross_file_flows = []
        for func_name in reachable:
            if func_name == entry_point:
                continue
            for caller, callee in self.call_graph.calls:
                if callee == func_name and (caller == entry_point or caller in param_influenced_funcs):
                    param_influenced_funcs.add(func_name)
                    caller_file = caller.split('::')[0] if '::' in caller else 'unknown'
                    callee_file = callee.split('::')[0] if '::' in callee else 'unknown'
                    if caller_file != callee_file:
                        cross_file_flows.append({'from_function': caller, 'to_function': callee, 'from_file': caller_file, 'to_file': callee_file})
        return {'reachable_functions': reachable, 'param_influenced_functions': list(param_influenced_funcs), 'cross_file_flows': cross_file_flows, 'total_files_involved': len(set((f.split('::')[0] for f in reachable if '::' in f)))}

    def get_all_files(self) -> list[Path]:
        return list(self.engines.keys())
