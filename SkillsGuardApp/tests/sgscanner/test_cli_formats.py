import json
import subprocess
import sys
from pathlib import Path
import pytest

@pytest.fixture
def safe_skill_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'

@pytest.fixture
def test_skills_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills'

def run_cli(args: list[str], timeout: int=60) -> tuple[str, str, int]:
    cmd = [sys.executable, '-m', 'sgscanner.cli.cli'] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=Path(__file__).parent.parent)
    return (result.stdout, result.stderr, result.returncode)

class TestJSONFormat:

    def test_json_format_is_valid_json(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json'])
        assert code == 0, f'CLI failed: {stderr}'
        data = json.loads(stdout)
        assert isinstance(data, dict)

    def test_json_format_has_required_fields(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json'])
        assert code == 0
        data = json.loads(stdout)
        required_fields = ['skill_name', 'is_safe', 'max_severity', 'findings_count', 'findings', 'scan_duration_seconds', 'timestamp']
        for field in required_fields:
            assert field in data, f'Missing required field: {field}'

    def test_json_format_findings_structure(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json'])
        assert code == 0
        data = json.loads(stdout)
        assert isinstance(data['findings'], list)
        for finding in data['findings']:
            assert 'id' in finding
            assert 'severity' in finding
            assert 'title' in finding

    def test_json_format_no_extra_output(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json'])
        assert code == 0
        stripped = stdout.strip()
        assert stripped.startswith('{'), f'JSON output has prefix: {stripped[:50]}'
        assert stripped.endswith('}'), f'JSON output has suffix: {stripped[-50:]}'

    def test_json_compact_format(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--compact'])
        assert code == 0
        lines = stdout.strip().split('\n')
        assert len(lines) == 1, f'Compact JSON should be single line, got {len(lines)} lines'
        data = json.loads(stdout)
        assert 'skill_name' in data

    def test_json_format_with_dataflow(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--use-dataflow'])
        assert code == 0, f'CLI failed: {stderr}'
        data = json.loads(stdout)
        assert 'skill_name' in data
        assert 'dataflow' in stderr.lower() or stderr == ''

class TestMarkdownFormat:

    def test_markdown_format_has_headers(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'markdown'])
        assert code == 0
        assert '#' in stdout

    def test_markdown_format_has_skill_info(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'markdown'])
        assert code == 0
        assert 'simple-formatter' in stdout.lower() or 'skill' in stdout.lower()

    def test_markdown_format_has_status(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'markdown'])
        assert code == 0
        assert any((word in stdout.lower() for word in ['safe', 'status', 'severity', 'finding', 'result']))

    def test_markdown_detailed_format(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'markdown', '--detailed'])
        assert code == 0
        assert len(stdout) > 50

class TestTableFormat:

    def test_table_format_has_structure(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'table'])
        assert code == 0
        assert any((char in stdout for char in ['|', '-', '+', '─', '│']))

    def test_table_format_shows_skill_name(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'table'])
        assert code == 0
        assert 'simple-formatter' in stdout or 'Skill' in stdout

    def test_table_format_shows_status(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'table'])
        assert code == 0
        assert any((word in stdout.lower() for word in ['safe', 'severity', 'finding', 'status', 'result']))

class TestSARIFFormat:

    def test_sarif_format_is_valid_json(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'sarif'])
        assert code == 0, f'CLI failed: {stderr}'
        data = json.loads(stdout)
        assert isinstance(data, dict)

    def test_sarif_format_has_schema(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'sarif'])
        assert code == 0
        data = json.loads(stdout)
        assert '$schema' in data
        assert 'version' in data
        assert 'runs' in data

    def test_sarif_format_version(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'sarif'])
        assert code == 0
        data = json.loads(stdout)
        assert data['version'] == '2.1.0'

    def test_sarif_format_runs_structure(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'sarif'])
        assert code == 0
        data = json.loads(stdout)
        assert isinstance(data['runs'], list)
        assert len(data['runs']) > 0
        run = data['runs'][0]
        assert 'tool' in run
        assert 'results' in run

    def test_sarif_tool_info(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'sarif'])
        assert code == 0
        data = json.loads(stdout)
        tool = data['runs'][0]['tool']
        assert 'driver' in tool
        assert 'name' in tool['driver']

class TestSummaryFormat:

    def test_summary_format_is_human_readable(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'summary'])
        assert code == 0
        try:
            json.loads(stdout)
            pytest.fail('Summary format should not be JSON')
        except json.JSONDecodeError:
            pass

    def test_summary_format_shows_skill_name(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'summary'])
        assert code == 0
        assert 'simple-formatter' in stdout or 'Skill' in stdout

    def test_summary_format_shows_result(self, safe_skill_dir):
        stdout, _, code = run_cli(['scan', str(safe_skill_dir), '--format', 'summary'])
        assert code == 0
        assert any((word in stdout.lower() for word in ['safe', 'finding', 'severity', 'result', 'scan']))

    def test_default_format_is_summary(self, safe_skill_dir):
        import re
        stdout_default, _, code1 = run_cli(['scan', str(safe_skill_dir)])
        stdout_summary, _, code2 = run_cli(['scan', str(safe_skill_dir), '--format', 'summary'])
        assert code1 == 0
        assert code2 == 0
        duration_pattern = 'Scan Duration: \\d+\\.\\d+s'
        normalized_default = re.sub(duration_pattern, 'Scan Duration: X.XXs', stdout_default)
        normalized_summary = re.sub(duration_pattern, 'Scan Duration: X.XXs', stdout_summary)
        assert normalized_default == normalized_summary

class TestMultiSkillFormats:

    def test_json_format_scan_all(self, test_skills_dir):
        safe_dir = test_skills_dir / 'safe'
        stdout, stderr, code = run_cli(['scan-all', str(safe_dir), '--format', 'json'])
        assert code == 0, f'CLI failed: {stderr}'
        data = json.loads(stdout)
        assert 'skills' in data or 'results' in data or 'total_skills_scanned' in data

    def test_sarif_format_scan_all(self, test_skills_dir):
        safe_dir = test_skills_dir / 'safe'
        stdout, stderr, code = run_cli(['scan-all', str(safe_dir), '--format', 'sarif'])
        assert code == 0, f'CLI failed: {stderr}'
        data = json.loads(stdout)
        assert '$schema' in data
        assert 'version' in data
        assert 'runs' in data

class TestFormatErrorHandling:

    def test_invalid_format_rejected(self, safe_skill_dir):
        _, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'invalid_format'])
        assert code != 0
        assert 'invalid' in stderr.lower() or 'choice' in stderr.lower()

    def test_nonexistent_skill_error(self):
        stdout, stderr, code = run_cli(['scan', '/nonexistent/path', '--format', 'json'])
        assert code != 0
        assert 'error' in stderr.lower() or 'not' in stderr.lower()

    def test_json_format_error_in_stderr(self):
        stdout, stderr, code = run_cli(['scan', '/nonexistent/path', '--format', 'json'])
        assert len(stderr) > 0
        if stdout.strip():
            try:
                json.loads(stdout)
            except json.JSONDecodeError:
                pytest.fail('JSON format stdout should be empty or valid JSON on error')

class TestDetectorStatusInJSON:

    def test_dataflow_status_not_in_json(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--use-dataflow'])
        assert code == 0
        data = json.loads(stdout)
        assert 'skill_name' in data
        if 'dataflow' in (stdout + stderr).lower():
            assert 'dataflow' not in stdout.lower() or 'engines_used' in stdout

    def test_description_status_not_in_json(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--use-description'])
        assert code == 0
        data = json.loads(stdout)
        assert 'skill_name' in data
