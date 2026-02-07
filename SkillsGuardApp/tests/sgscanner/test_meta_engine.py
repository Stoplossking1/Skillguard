import json
import os
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch
import pytest
from sgscanner.models import Finding, Severity, Skill, SkillFile, SkillManifest, ThreatCategory

class TestMetaVerdict:

    def test_empty_result(self):
        from sgscanner.engines.meta import MetaVerdict
        result = MetaVerdict()
        assert result.validated_findings == []
        assert result.false_positives == []
        assert result.missed_threats == []
        assert result.priority_order == []
        assert result.correlations == []
        assert result.recommendations == []
        assert result.overall_risk_assessment == {}

    def test_to_dict(self):
        from sgscanner.engines.meta import MetaVerdict
        result = MetaVerdict(validated_findings=[{'id': '1', 'severity': 'HIGH'}], false_positives=[{'id': '2', 'reason': 'false positive'}], missed_threats=[{'title': 'new threat'}], overall_risk_assessment={'risk_level': 'HIGH', 'summary': 'Test'})
        result_dict = result.serialize()
        assert result_dict['validated_findings'] == [{'id': '1', 'severity': 'HIGH'}]
        assert result_dict['false_positives'] == [{'id': '2', 'reason': 'false positive'}]
        assert result_dict['missed_threats'] == [{'title': 'new threat'}]
        assert result_dict['summary']['validated_count'] == 1
        assert result_dict['summary']['false_positive_count'] == 1
        assert result_dict['summary']['missed_threats_count'] == 1

    def test_get_validated_findings(self):
        from sgscanner.engines.meta import MetaVerdict
        skill = MagicMock(spec=Skill)
        skill.name = 'test-skill'
        result = MetaVerdict(validated_findings=[{'id': 'test_1', 'rule_id': 'TEST_RULE', 'category': 'prompt_injection', 'severity': 'HIGH', 'title': 'Test Finding', 'description': 'Test description', 'confidence': 'HIGH', 'confidence_reason': 'Multiple signals'}])
        findings = result.get_validated_findings(skill)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].category == ThreatCategory.PROMPT_INJECTION
        assert findings[0].title == 'Test Finding'
        assert findings[0].metadata.get('meta_validated') is True
        assert findings[0].metadata.get('meta_confidence') == 'HIGH'

    def test_get_missed_threats(self):
        from sgscanner.engines.meta import MetaVerdict
        skill = MagicMock(spec=Skill)
        skill.name = 'test-skill'
        result = MetaVerdict(missed_threats=[{'aitech': 'AITech-1.1', 'severity': 'HIGH', 'title': 'Missed Prompt Injection', 'description': 'Detected by meta-analysis', 'detection_reason': 'Semantic analysis'}])
        findings = result.get_missed_threats(skill)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert findings[0].title == 'Missed Prompt Injection'
        assert findings[0].analyzer == 'meta'
        assert findings[0].metadata.get('meta_detected') is True

class TestMetaEngineInit:

    @pytest.fixture
    def mock_litellm(self):
        with patch('sgscanner.detectors.meta_detector.LITELLM_AVAILABLE', True):
            with patch('sgscanner.detectors.meta_detector.acompletion', AsyncMock()):
                yield

    def test_separate_meta_api_key(self, mock_litellm):
        with patch.dict(os.environ, {'SG_META_LLM_API_KEY': 'test-meta-key-for-testing', 'SG_META_LLM_MODEL': 'gpt-4o', 'SG_LLM_API_KEY': 'test-regular-key-for-testing', 'SG_LLM_MODEL': 'claude-3-5-sonnet'}, clear=True):
            from sgscanner.engines.meta import MetaEngine
            analyzer = MetaEngine()
            assert analyzer.api_key == 'test-meta-key-for-testing'
            assert analyzer.model == 'gpt-4o'

    def test_fallback_to_llm_key(self, mock_litellm):
        with patch.dict(os.environ, {'SG_LLM_API_KEY': 'test-regular-key-for-testing', 'SG_LLM_MODEL': 'claude-3-5-sonnet'}, clear=True):
            from sgscanner.engines.meta import MetaEngine
            analyzer = MetaEngine()
            assert analyzer.api_key == 'test-regular-key-for-testing'
            assert analyzer.model == 'claude-3-5-sonnet'

    def test_explicit_parameters_override_env(self, mock_litellm):
        with patch.dict(os.environ, {'SG_META_LLM_API_KEY': 'test-env-key-for-testing', 'SG_META_LLM_MODEL': 'env-model'}, clear=True):
            from sgscanner.engines.meta import MetaEngine
            analyzer = MetaEngine(api_key='test-explicit-key-for-testing', model='explicit-model')
            assert analyzer.api_key == 'test-explicit-key-for-testing'
            assert analyzer.model == 'explicit-model'

class TestApplyMetaAnalysis:

    def test_marks_false_positives_with_metadata(self):
        from sgscanner.engines.meta import MetaVerdict, apply_meta_filtering
        skill = MagicMock(spec=Skill)
        skill.name = 'test-skill'
        original_findings = [Finding(id='finding_0', rule_id='RULE_1', category=ThreatCategory.PROMPT_INJECTION, severity=Severity.HIGH, title='Real Finding', description='This is a real threat', analyzer='pattern'), Finding(id='finding_1', rule_id='RULE_2', category=ThreatCategory.OBFUSCATION, severity=Severity.MEDIUM, title='False Positive', description='This is a false positive', analyzer='pattern')]
        meta_result = MetaVerdict(validated_findings=[{'_index': 0, 'id': 'finding_0', 'confidence': 'HIGH'}], false_positives=[{'_index': 1, 'id': 'finding_1', 'false_positive_reason': 'Pattern match without malicious context'}], priority_order=[0])
        result = apply_meta_filtering(original_findings, meta_result, skill)
        assert len(result) == 2
        assert result[0].id == 'finding_0'
        assert result[0].metadata.get('meta_false_positive') is False
        assert result[0].metadata.get('meta_confidence') == 'HIGH'
        assert result[0].metadata.get('meta_priority') == 1
        assert result[1].id == 'finding_1'
        assert result[1].metadata.get('meta_false_positive') is True
        assert result[1].metadata.get('meta_reason') == 'Pattern match without malicious context'

    def test_adds_missed_threats(self):
        from sgscanner.engines.meta import MetaVerdict, apply_meta_filtering
        skill = MagicMock(spec=Skill)
        skill.name = 'test-skill'
        original_findings = []
        meta_result = MetaVerdict(validated_findings=[], false_positives=[], missed_threats=[{'aitech': 'AITech-8.2', 'severity': 'CRITICAL', 'title': 'Hidden Data Exfiltration', 'description': 'Credential theft detected', 'detection_reason': 'Semantic analysis found credential access + network call'}])
        result = apply_meta_filtering(original_findings, meta_result, skill)
        assert len(result) == 1
        assert result[0].title == 'Hidden Data Exfiltration'
        assert result[0].analyzer == 'meta'
        assert result[0].metadata.get('meta_detected') is True
        assert result[0].metadata.get('meta_false_positive') is False

class TestReporterCompatibility:

    @pytest.fixture
    def sample_scan_result(self):
        from sgscanner.models import ScanResult
        findings = [Finding(id='meta_finding_1', rule_id='META_VALIDATED', category=ThreatCategory.DATA_EXFILTRATION, severity=Severity.HIGH, title='Data Exfiltration via Network', description='Skill sends sensitive data to external server', file_path='scripts/helper.py', line_number=42, snippet="requests.post(url, json={'creds': creds})", remediation='Remove the network call or sanitize data', analyzer='meta', metadata={'meta_validated': True, 'meta_confidence': 'HIGH', 'meta_exploitability': 'Easy', 'meta_impact': 'Critical', 'aitech': 'AITech-8.2'})]
        return ScanResult(skill_name='test-skill', skill_directory='/tmp/test-skill', findings=findings, scan_duration_seconds=1.5, engines_used=['pattern_detector', 'semantic_detector', 'meta_detector'])

    def test_json_reporter(self, sample_scan_result):
        from sgscanner.reports.json_reporter import JSONReporter
        reporter = JSONReporter(pretty=True)
        output = reporter.generate_report(sample_scan_result)
        data = json.loads(output)
        assert 'findings' in data
        assert len(data['findings']) == 1
        assert data['findings'][0]['analyzer'] == 'meta'
        assert data['findings'][0]['metadata']['meta_validated'] is True
        assert 'meta_detector' in data['engines_used']

    def test_sarif_reporter(self, sample_scan_result):
        from sgscanner.reports.sarif_reporter import SARIFReporter
        reporter = SARIFReporter()
        output = reporter.generate_report(sample_scan_result)
        sarif = json.loads(output)
        assert sarif['$schema'] is not None
        assert len(sarif['runs']) == 1
        results = sarif['runs'][0]['results']
        assert len(results) == 1
        assert 'meta' in results[0]['message']['text'].lower() or results[0]['ruleId'] == 'META_VALIDATED'

    def test_markdown_reporter(self, sample_scan_result):
        from sgscanner.reports.markdown_reporter import MarkdownReporter
        reporter = MarkdownReporter(detailed=True)
        output = reporter.generate_report(sample_scan_result)
        assert 'Data Exfiltration' in output
        assert 'meta' in output.lower()
        assert 'HIGH' in output

    def test_table_reporter(self, sample_scan_result):
        from sgscanner.reports.table_reporter import TableReporter
        reporter = TableReporter()
        output = reporter.generate_report(sample_scan_result)
        assert 'Data Exfiltration' in output
        assert 'HIGH' in output

class TestAITechTaxonomy:

    def test_aitech_codes_in_prompt(self):
        from sgscanner.taxonomy.threats import ThreatMapping
        prompt_path = Path(__file__).parent.parent / 'sgscanner' / 'data' / 'prompts' / 'skill_meta_analysis_prompt.md'
        if not prompt_path.exists():
            pytest.skip('Prompt file not found')
        prompt_content = prompt_path.read_text()
        expected_codes = ['AITech-1.1', 'AITech-1.2', 'AITech-4.3', 'AITech-8.2', 'AITech-9.1', 'AITech-12.1', 'AITech-13.1', 'AITech-15.1']
        for code in expected_codes:
            assert code in prompt_content, f'AITech code {code} missing from prompt'
            mapping = ThreatMapping.get_threat_mapping_by_aitech(code)
            assert mapping is not None

    def test_threat_category_mapping(self):
        from sgscanner.taxonomy.threats import ThreatMapping
        aitech_codes = ['AITech-1.1', 'AITech-1.2', 'AITech-4.3', 'AITech-8.2', 'AITech-9.1', 'AITech-12.1', 'AITech-13.1', 'AITech-15.1']
        for code in aitech_codes:
            category = ThreatMapping.get_threat_category_from_aitech(code)
            try:
                ThreatCategory(category)
            except ValueError:
                pytest.fail(f'AITech code {code} maps to invalid category: {category}')
