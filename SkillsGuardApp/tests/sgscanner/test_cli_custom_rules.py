import json
import subprocess
import sys
import tempfile
from pathlib import Path
import pytest

@pytest.fixture
def safe_skill_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'

@pytest.fixture
def malicious_skill_dir():
    return Path(__file__).parent.parent / 'evals' / 'skills' / 'command-injection' / 'eval-execution'

@pytest.fixture
def custom_rules_dir(tmp_path):
    rules_dir = tmp_path / 'custom_rules'
    rules_dir.mkdir()
    custom_rule = rules_dir / 'custom_test.yara'
    custom_rule.write_text('\nrule custom_test_pattern\n{\n    meta:\n        description = "Test custom rule"\n        severity = "LOW"\n        category = "policy_violation"\n\n    strings:\n        $test = "custom_test_marker_xyz123"\n\n    condition:\n        $test\n}\n')
    return rules_dir

def run_cli(args: list[str], timeout: int=60) -> tuple[str, str, int]:
    cmd = [sys.executable, '-m', 'sgscanner.cli.cli'] + args
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=Path(__file__).parent.parent)
    return (result.stdout, result.stderr, result.returncode)

class TestYaraMode:

    def test_default_mode_is_balanced(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json'])
        assert code == 0, f'CLI failed: {stderr}'

    def test_strict_mode_accepted(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--yara-mode', 'strict'])
        assert code == 0, f'CLI failed: {stderr}'

    def test_balanced_mode_accepted(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--yara-mode', 'balanced'])
        assert code == 0, f'CLI failed: {stderr}'

    def test_permissive_mode_accepted(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--yara-mode', 'permissive'])
        assert code == 0, f'CLI failed: {stderr}'

    def test_invalid_mode_rejected(self, safe_skill_dir):
        _, stderr, code = run_cli(['scan', str(safe_skill_dir), '--yara-mode', 'invalid_mode'])
        assert code != 0
        assert 'invalid' in stderr.lower() or 'choice' in stderr.lower()

class TestDisableRule:

    def test_disable_single_rule(self, malicious_skill_dir):
        stdout1, _, code1 = run_cli(['scan', str(malicious_skill_dir), '--format', 'json'])
        assert code1 == 0
        data1 = json.loads(stdout1)
        findings1 = data1.get('findings', [])
        if findings1:
            rule_to_disable = findings1[0].get('rule_id', '')
            if rule_to_disable:
                stdout2, _, code2 = run_cli(['scan', str(malicious_skill_dir), '--format', 'json', '--disable-rule', rule_to_disable])
                assert code2 == 0
                data2 = json.loads(stdout2)
                findings2 = data2.get('findings', [])
                disabled_count = sum((1 for f in findings1 if f.get('rule_id') == rule_to_disable))
                assert len(findings2) == len(findings1) - disabled_count

    def test_disable_multiple_rules(self, malicious_skill_dir):
        stdout, _, code = run_cli(['scan', str(malicious_skill_dir), '--format', 'json', '--disable-rule', 'COMMAND_INJECTION_EVAL', '--disable-rule', 'MANIFEST_MISSING_LICENSE'])
        assert code == 0
        data = json.loads(stdout)
        findings = data.get('findings', [])
        for finding in findings:
            assert finding.get('rule_id') != 'COMMAND_INJECTION_EVAL'
            assert finding.get('rule_id') != 'MANIFEST_MISSING_LICENSE'

    def test_disable_nonexistent_rule(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--disable-rule', 'NONEXISTENT_RULE_XYZ'])
        assert code == 0

    def test_disable_yara_rule(self, malicious_skill_dir):
        stdout, _, code = run_cli(['scan', str(malicious_skill_dir), '--format', 'json', '--disable-rule', 'YARA_script_injection'])
        assert code == 0
        data = json.loads(stdout)
        findings = data.get('findings', [])
        for finding in findings:
            assert finding.get('rule_id') != 'YARA_script_injection'

class TestCustomRules:

    def test_custom_rules_directory(self, safe_skill_dir, custom_rules_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--custom-rules', str(custom_rules_dir)])
        assert code == 0, f'CLI failed: {stderr}'

    def test_custom_rules_invalid_path(self, safe_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--custom-rules', '/nonexistent/path/to/rules'])
        assert code == 0
        assert 'not found' in stderr.lower() or 'could not load' in stderr.lower()

class TestScanAllCustomOptions:

    def test_scan_all_with_yara_mode(self):
        test_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe'
        stdout, stderr, code = run_cli(['scan-all', str(test_dir), '--format', 'json', '--yara-mode', 'permissive'])
        assert code == 0, f'CLI failed: {stderr}'

    def test_scan_all_with_disable_rule(self):
        test_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe'
        stdout, stderr, code = run_cli(['scan-all', str(test_dir), '--format', 'json', '--disable-rule', 'MANIFEST_MISSING_LICENSE'])
        assert code == 0, f'CLI failed: {stderr}'

class TestCustomRulesIntegration:

    def test_mode_and_disable_combined(self, malicious_skill_dir):
        stdout, stderr, code = run_cli(['scan', str(malicious_skill_dir), '--format', 'json', '--yara-mode', 'strict', '--disable-rule', 'MANIFEST_MISSING_LICENSE'])
        assert code == 0, f'CLI failed: {stderr}'
        data = json.loads(stdout)
        findings = data.get('findings', [])
        for finding in findings:
            assert finding.get('rule_id') != 'MANIFEST_MISSING_LICENSE'

    def test_all_options_combined(self, safe_skill_dir, custom_rules_dir):
        stdout, stderr, code = run_cli(['scan', str(safe_skill_dir), '--format', 'json', '--yara-mode', 'balanced', '--custom-rules', str(custom_rules_dir), '--disable-rule', 'SOME_RULE'])
        assert code == 0, f'CLI failed: {stderr}'
