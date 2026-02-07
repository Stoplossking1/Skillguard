import ast
import importlib
import inspect
import re
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

class TestModulePathsValid:

    def _extract_uvicorn_paths_from_file(self, filepath: Path) -> list[tuple[int, str]]:
        paths = []
        content = filepath.read_text()
        try:
            tree = ast.parse(content)
        except SyntaxError:
            return paths
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Attribute):
                    if node.func.attr == 'run':
                        if isinstance(node.func.value, ast.Name) and node.func.value.id == 'uvicorn':
                            if node.args and isinstance(node.args[0], ast.Constant):
                                paths.append((node.lineno, node.args[0].value))
        return paths

    def _validate_module_path(self, module_path: str) -> tuple[bool, str]:
        if ':' not in module_path:
            return (False, f"Invalid format: missing ':' separator in '{module_path}'")
        module_name, attr_name = module_path.split(':', 1)
        try:
            module = importlib.import_module(module_name)
        except ImportError as e:
            return (False, f"Cannot import module '{module_name}': {e}")
        if not hasattr(module, attr_name):
            return (False, f"Module '{module_name}' has no attribute '{attr_name}'")
        return (True, '')

    def test_api_server_uvicorn_path_is_valid(self):
        api_server_path = Path(__file__).parent.parent / 'sgscanner' / 'api' / 'api_server.py'
        if not api_server_path.exists():
            pytest.skip('api_server.py not found')
        paths = self._extract_uvicorn_paths_from_file(api_server_path)
        assert len(paths) > 0, 'No uvicorn.run() calls found in api_server.py'
        for line_no, module_path in paths:
            is_valid, error = self._validate_module_path(module_path)
            assert is_valid, f'Invalid uvicorn path at line {line_no}: {error}'

    def test_api_cli_uvicorn_path_is_valid(self):
        api_cli_path = Path(__file__).parent.parent / 'sgscanner' / 'api' / 'api_cli.py'
        if not api_cli_path.exists():
            pytest.skip('api_cli.py not found')
        paths = self._extract_uvicorn_paths_from_file(api_cli_path)
        assert len(paths) > 0, 'No uvicorn.run() calls found in api_cli.py'
        for line_no, module_path in paths:
            is_valid, error = self._validate_module_path(module_path)
            assert is_valid, f'Invalid uvicorn path at line {line_no}: {error}'

    def test_all_api_files_have_valid_uvicorn_paths(self):
        api_dir = Path(__file__).parent.parent / 'sgscanner' / 'api'
        if not api_dir.exists():
            pytest.skip('api/ directory not found')
        errors = []
        for py_file in api_dir.glob('*.py'):
            paths = self._extract_uvicorn_paths_from_file(py_file)
            for line_no, module_path in paths:
                is_valid, error = self._validate_module_path(module_path)
                if not is_valid:
                    errors.append(f'{py_file.name}:{line_no}: {error}')
        assert not errors, 'Invalid uvicorn paths found:\n' + '\n'.join(errors)

class TestModulePathFormat:

    def test_api_server_path_includes_api_subpackage(self):
        api_server_path = Path(__file__).parent.parent / 'sgscanner' / 'api' / 'api_server.py'
        content = api_server_path.read_text()
        assert 'sgscanner.api.api_server' in content, "api_server.py should use 'sgscanner.api.api_server:app' not 'sgscanner.api_server:app'"
        incorrect_pattern = '["\\\']sgscanner\\.api_server:'
        assert not re.search(incorrect_pattern, content), "Found incorrect module path 'sgscanner.api_server:' - should be 'sgscanner.api.api_server:'"

    def test_api_cli_path_includes_api_subpackage(self):
        api_cli_path = Path(__file__).parent.parent / 'sgscanner' / 'api' / 'api_cli.py'
        content = api_cli_path.read_text()
        assert 'sgscanner.api.api' in content, "api_cli.py should use 'sgscanner.api.api:app' path"

class TestAppImportable:

    def test_api_app_importable(self):
        try:
            from sgscanner.api.api import app
            assert app is not None
            assert hasattr(app, 'routes'), 'app should be a FastAPI instance with routes'
        except ImportError as e:
            pytest.fail(f'Cannot import app from sgscanner.api.api: {e}')

    def test_api_server_app_importable(self):
        try:
            from sgscanner.api.api_server import app
            assert app is not None
            assert hasattr(app, 'routes'), 'app should be a FastAPI instance with routes'
        except ImportError as e:
            pytest.fail(f'Cannot import app from sgscanner.api.api_server: {e}')

    def test_api_init_exports_app(self):
        try:
            from sgscanner.api import app
            assert app is not None
        except ImportError as e:
            pytest.fail(f'Cannot import app from sgscanner.api: {e}')

class TestRunServerFunction:

    def test_run_server_exists(self):
        from sgscanner.api.api_server import run_server
        assert callable(run_server)

    def test_run_server_has_correct_signature(self):
        from sgscanner.api.api_server import run_server
        sig = inspect.signature(run_server)
        params = list(sig.parameters.keys())
        assert 'host' in params, "run_server should have 'host' parameter"
        assert 'port' in params, "run_server should have 'port' parameter"
        assert 'reload' in params, "run_server should have 'reload' parameter"

    def test_run_server_default_values(self):
        from sgscanner.api.api_server import run_server
        sig = inspect.signature(run_server)
        assert sig.parameters['host'].default == 'localhost'
        assert sig.parameters['port'].default == 8000
        assert sig.parameters['reload'].default is False

    @patch('uvicorn.run')
    def test_run_server_calls_uvicorn_with_correct_path(self, mock_uvicorn_run):
        from sgscanner.api.api_server import run_server
        run_server(host='127.0.0.1', port=9000, reload=True)
        mock_uvicorn_run.assert_called_once()
        call_args = mock_uvicorn_run.call_args
        module_path = call_args[0][0] if call_args[0] else call_args[1].get('app')
        assert module_path == 'sgscanner.api.api_server:app', f"Expected 'sgscanner.api.api_server:app', got '{module_path}'"
        assert call_args[1]['host'] == '127.0.0.1'
        assert call_args[1]['port'] == 9000
        assert call_args[1]['reload'] is True

class TestApiCliMain:

    @patch('uvicorn.run')
    def test_api_cli_calls_uvicorn_with_correct_path(self, mock_uvicorn_run):
        import sys
        from unittest.mock import patch as mock_patch
        with mock_patch.object(sys, 'argv', ['skill-scanner-api']):
            from sgscanner.api.api_cli import main
            main()
        mock_uvicorn_run.assert_called_once()
        call_args = mock_uvicorn_run.call_args
        module_path = call_args[0][0] if call_args[0] else call_args[1].get('app')
        assert module_path == 'sgscanner.api.api:app', f"Expected 'sgscanner.api.api:app', got '{module_path}'"

class TestModulePathConsistency:

    def test_no_old_skillanalyzer_references(self):
        api_dir = Path(__file__).parent.parent / 'sgscanner' / 'api'
        for py_file in api_dir.glob('*.py'):
            content = py_file.read_text()
            if 'skillanalyzer' in content.lower():
                for i, line in enumerate(content.split('\n'), 1):
                    if 'skillanalyzer' in line.lower() and 'uvicorn' in line.lower():
                        pytest.fail(f"Found old 'skillanalyzer' reference at {py_file.name}:{i}: {line.strip()}")

    def test_module_paths_use_sgscanner_package(self):
        api_dir = Path(__file__).parent.parent / 'sgscanner' / 'api'
        for py_file in api_dir.glob('*.py'):
            content = py_file.read_text()
            uvicorn_pattern = 'uvicorn\\.run\\(["\\\']([^"\\\']+)["\\\']'
            matches = re.findall(uvicorn_pattern, content)
            for match in matches:
                assert match.startswith('sgscanner.'), f"Module path '{match}' in {py_file.name} should start with 'sgscanner.'"
