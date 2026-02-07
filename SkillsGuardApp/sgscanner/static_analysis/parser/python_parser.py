import ast
from dataclasses import dataclass, field

@dataclass
class FunctionInfo:
    name: str
    parameters: list[str]
    docstring: str | None
    line_number: int
    source_code: str
    ast_node: ast.FunctionDef
    has_network_calls: bool = False
    has_file_operations: bool = False
    has_subprocess: bool = False
    has_eval_exec: bool = False
    imports: list[str] = field(default_factory=list)
    function_calls: list[str] = field(default_factory=list)
    string_literals: list[str] = field(default_factory=list)
    assignments: list[str] = field(default_factory=list)

class PythonParser:
    NETWORK_MODULES = ['requests', 'urllib', 'http', 'socket', 'aiohttp']
    FILE_OPERATIONS = ['open', 'read', 'write', 'Path', 'os.remove', 'shutil']
    SUBPROCESS_PATTERNS = ['subprocess', 'os.system', 'os.popen']
    DANGEROUS_FUNCTIONS = ['eval', 'exec', 'compile', '__import__']
    TOOL_INDICATORS = {'Read': {'open', 'read', 'readline', 'readlines', 'Path.read_text', 'Path.read_bytes', 'json.load', 'yaml.safe_load', 'configparser'}, 'Write': {'write', 'writelines', 'Path.write_text', 'Path.write_bytes', 'json.dump', 'yaml.dump'}, 'Bash': {'subprocess.run', 'subprocess.call', 'subprocess.Popen', 'subprocess.check_output', 'subprocess.check_call', 'os.system', 'os.popen', 'os.spawn', 'commands.getoutput', 'commands.getstatusoutput'}, 'Grep': {'re.search', 're.match', 're.findall', 're.finditer', 're.sub', 're.split'}, 'Glob': {'glob.glob', 'glob.iglob', 'Path.glob', 'Path.rglob', 'fnmatch.fnmatch', 'fnmatch.filter'}, 'Network': {'requests.get', 'requests.post', 'requests.put', 'requests.delete', 'urllib.request.urlopen', 'urllib.urlopen', 'http.client.HTTPConnection', 'http.client.HTTPSConnection', 'socket.connect', 'socket.create_connection', 'aiohttp.ClientSession', 'httpx.get', 'httpx.post'}}

    def __init__(self, source_code: str):
        self.source_code = source_code
        self.tree: ast.Module | None = None
        self.functions: list[FunctionInfo] = []
        self.imports: list[str] = []
        self.global_calls: list[str] = []
        self.module_strings: list[str] = []
        self.class_attributes: list[dict[str, str]] = []

    def parse(self) -> bool:
        try:
            self.tree = ast.parse(self.source_code)
            self._extract_imports()
            self._extract_module_level_strings()
            self._extract_functions()
            self._extract_global_code()
            return True
        except SyntaxError as e:
            print(f'Syntax error in source: {e}')
            return False

    def _extract_module_level_strings(self) -> None:
        if self.tree is None:
            return
        for node in self.tree.body:
            if isinstance(node, ast.Assign):
                for value_node in ast.walk(node.value):
                    if isinstance(value_node, ast.Constant) and isinstance(value_node.value, str):
                        self.module_strings.append(value_node.value)
            elif isinstance(node, ast.ClassDef):
                for class_node in node.body:
                    if isinstance(class_node, ast.Assign):
                        for target in class_node.targets:
                            if isinstance(target, ast.Name):
                                if isinstance(class_node.value, ast.Constant):
                                    if isinstance(class_node.value.value, str):
                                        self.module_strings.append(class_node.value.value)
                                        self.class_attributes.append({'name': target.id, 'value': class_node.value.value})

    def _extract_imports(self) -> None:
        if self.tree is None:
            return
        for node in ast.walk(self.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self.imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    self.imports.append(node.module)

    def _extract_functions(self) -> None:
        if self.tree is None:
            return
        for node in ast.walk(self.tree):
            if isinstance(node, ast.FunctionDef):
                func_info = self._analyze_function(node)
                self.functions.append(func_info)

    def _analyze_function(self, node: ast.FunctionDef) -> FunctionInfo:
        parameters = [arg.arg for arg in node.args.args]
        docstring = ast.get_docstring(node)
        source_lines = self.source_code.split('\n')
        func_source = '\n'.join(source_lines[node.lineno - 1:node.end_lineno])
        func_info = FunctionInfo(name=node.name, parameters=parameters, docstring=docstring, line_number=node.lineno, source_code=func_source, ast_node=node, imports=self.imports.copy())
        self._analyze_function_body(node, func_info)
        return func_info

    def _analyze_function_body(self, node: ast.FunctionDef, func_info: FunctionInfo):
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                call_name = self._get_call_name(child)
                if call_name:
                    func_info.function_calls.append(call_name)
                    if any((net in call_name for net in self.NETWORK_MODULES)):
                        func_info.has_network_calls = True
                    if any((file_op in call_name for file_op in self.FILE_OPERATIONS)):
                        func_info.has_file_operations = True
                    if any((sub in call_name for sub in self.SUBPROCESS_PATTERNS)):
                        func_info.has_subprocess = True
                    if any((danger in call_name for danger in self.DANGEROUS_FUNCTIONS)):
                        func_info.has_eval_exec = True
            elif isinstance(child, ast.Constant) and isinstance(child.value, str):
                if len(child.value) > 5:
                    func_info.string_literals.append(child.value)
            elif isinstance(child, ast.Assign):
                for target in child.targets:
                    if isinstance(target, ast.Name):
                        func_info.assignments.append(target.id)

    def _get_call_name(self, node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f'{node.func.value.id}.{node.func.attr}'
            return node.func.attr
        return None

    def _extract_global_code(self) -> None:
        if self.tree is None:
            return
        for node in self.tree.body:
            if isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                call_name = self._get_call_name(node.value)
                if call_name:
                    self.global_calls.append(call_name)

    def get_functions(self) -> list[FunctionInfo]:
        return self.functions

    def has_security_indicators(self) -> dict[str, bool]:
        return {'has_network': any((f.has_network_calls for f in self.functions)), 'has_file_ops': any((f.has_file_operations for f in self.functions)), 'has_subprocess': any((f.has_subprocess for f in self.functions)), 'has_eval_exec': any((f.has_eval_exec for f in self.functions)), 'has_dangerous_imports': any((mod in self.imports for mod in self.NETWORK_MODULES + self.SUBPROCESS_PATTERNS))}

    def get_inferred_tools(self) -> dict[str, bool]:
        inferred = {tool: False for tool in self.TOOL_INDICATORS.keys()}
        all_calls = set()
        for func in self.functions:
            all_calls.update(func.function_calls)
        all_calls.update(self.global_calls)
        import_based_tools = {'requests': 'Network', 'urllib': 'Network', 'aiohttp': 'Network', 'httpx': 'Network', 'socket': 'Network', 'subprocess': 'Bash', 'glob': 'Glob', 'fnmatch': 'Glob', 're': 'Grep'}
        for module in self.imports:
            base_module = module.split('.')[0]
            if base_module in import_based_tools:
                tool = import_based_tools[base_module]
                inferred[tool] = True
        for tool, patterns in self.TOOL_INDICATORS.items():
            for call in all_calls:
                for pattern in patterns:
                    if pattern in call or call.endswith(pattern.split('.')[-1] if '.' in pattern else pattern):
                        inferred[tool] = True
                        break
                if inferred[tool]:
                    break
        for func in self.functions:
            if func.has_file_operations:
                for call in func.function_calls:
                    if any((r in call for r in ['read', 'load'])):
                        inferred['Read'] = True
                    if any((w in call for w in ['write', 'dump'])):
                        inferred['Write'] = True
            if func.has_subprocess:
                inferred['Bash'] = True
            if func.has_network_calls:
                inferred['Network'] = True
        return inferred

    def get_detected_tools_list(self) -> list[str]:
        inferred = self.get_inferred_tools()
        return [tool for tool, detected in inferred.items() if detected]
