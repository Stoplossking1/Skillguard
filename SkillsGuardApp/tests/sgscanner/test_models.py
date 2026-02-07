import pytest
from sgscanner.models import Finding, Severity, ThreatCategory

class TestFindingModel:

    def test_finding_with_analyzer_field(self):
        finding = Finding(id='test_001', rule_id='TEST_RULE', category=ThreatCategory.COMMAND_INJECTION, severity=Severity.HIGH, title='Test Finding', description='A test finding', analyzer='pattern')
        assert finding.engine == 'pattern'
        assert finding.engine == 'pattern'

    def test_finding_analyzer_defaults_to_none(self):
        finding = Finding(id='test_002', rule_id='TEST_RULE', category=ThreatCategory.COMMAND_INJECTION, severity=Severity.HIGH, title='Test Finding', description='A test finding')
        assert finding.engine is None

    def test_finding_to_dict_includes_analyzer(self):
        finding = Finding(id='test_003', rule_id='TEST_RULE', category=ThreatCategory.DATA_EXFILTRATION, severity=Severity.CRITICAL, title='Test Finding', description='A test finding', analyzer='dataflow')
        finding_dict = finding.serialize()
        assert 'analyzer' in finding_dict
        assert 'detector' in finding_dict
        assert finding_dict['analyzer'] == 'dataflow'
        assert finding_dict['detector'] == 'dataflow'

    def test_finding_to_dict_analyzer_none_when_not_set(self):
        finding = Finding(id='test_004', rule_id='TEST_RULE', category=ThreatCategory.PROMPT_INJECTION, severity=Severity.MEDIUM, title='Test Finding', description='A test finding')
        finding_dict = finding.serialize()
        assert 'analyzer' in finding_dict
        assert finding_dict['analyzer'] is None
        assert 'detector' in finding_dict
        assert finding_dict['detector'] is None

    @pytest.mark.parametrize('analyzer_value', ['pattern', 'semantic', 'dataflow', 'aidefense', 'virustotal', 'cross_skill', 'description', 'meta'])
    def test_finding_accepts_all_analyzer_values(self, analyzer_value):
        finding = Finding(id=f'test_{analyzer_value}', rule_id='TEST_RULE', category=ThreatCategory.POLICY_VIOLATION, severity=Severity.LOW, title='Test Finding', description='A test finding', analyzer=analyzer_value)
        assert finding.engine == analyzer_value
        finding_dict = finding.serialize()
        assert finding_dict['analyzer'] == analyzer_value
        assert finding_dict['detector'] == analyzer_value

    def test_finding_to_dict_contains_all_expected_keys(self):
        finding = Finding(id='test_keys', rule_id='TEST_RULE', category=ThreatCategory.MALWARE, severity=Severity.CRITICAL, title='Test Finding', description='A test finding', file_path='test.py', line_number=42, snippet='dangerous_code()', remediation='Fix the code', analyzer='pattern', metadata={'key': 'value'})
        finding_dict = finding.serialize()
        expected_keys = {'id', 'rule_id', 'category', 'severity', 'title', 'description', 'file_path', 'line_number', 'snippet', 'remediation', 'analyzer', 'detector', 'metadata'}
        assert set(finding_dict.keys()) == expected_keys

    def test_finding_to_dict_json_serializable(self):
        import json
        finding = Finding(id='test_json', rule_id='TEST_RULE', category=ThreatCategory.COMMAND_INJECTION, severity=Severity.HIGH, title='Test Finding', description='A test finding', analyzer='semantic', metadata={'confidence': 0.95})
        finding_dict = finding.serialize()
        json_str = json.dumps(finding_dict)
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed['analyzer'] == 'semantic'
        assert parsed['detector'] == 'semantic'
