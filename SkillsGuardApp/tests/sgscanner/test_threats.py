from unittest.mock import patch
import pytest
from sgscanner.taxonomy.threats import BEHAVIORAL_THREAT_MAPPING, LLM_THREAT_MAPPING, YARA_THREAT_MAPPING, ThreatMapping, get_threat_category, get_threat_severity

class TestThreatMappingStructure:

    def test_llm_threats_defined(self):
        assert ThreatMapping.LLM_THREATS is not None
        assert len(ThreatMapping.LLM_THREATS) > 0

    def test_yara_threats_defined(self):
        assert ThreatMapping.YARA_THREATS is not None
        assert len(ThreatMapping.YARA_THREATS) > 0

    def test_dataflow_threats_defined(self):
        assert ThreatMapping.BEHAVIORAL_THREATS is not None
        assert len(ThreatMapping.BEHAVIORAL_THREATS) > 0

class TestThreatMappingContent:

    def test_prompt_injection_mapping(self):
        threat = ThreatMapping.LLM_THREATS['PROMPT INJECTION']
        assert threat['scanner_category'] == 'PROMPT INJECTION'
        assert threat['severity'] == 'HIGH'
        assert threat['aitech'] == 'AITech-1.1'
        assert threat['aitech_name'] == 'Direct Prompt Injection'
        assert 'aisubtech' in threat
        assert 'description' in threat

    def test_data_exfiltration_mapping(self):
        threat = ThreatMapping.LLM_THREATS['DATA EXFILTRATION']
        assert threat['scanner_category'] == 'SECURITY VIOLATION'
        assert threat['severity'] == 'HIGH'
        assert threat['aitech'] == 'AITech-8.2'
        assert 'Data Exfiltration' in threat['aitech_name']

    def test_command_injection_mapping(self):
        threat = ThreatMapping.LLM_THREATS['COMMAND INJECTION']
        assert threat['severity'] == 'CRITICAL'
        assert threat['aitech'] == 'AITech-9.1'
        assert 'Injection' in threat['aisubtech_name']

    def test_all_threats_have_required_fields(self):
        required_fields = ['scanner_category', 'severity', 'aitech', 'aitech_name', 'aisubtech', 'aisubtech_name', 'description']
        for detector_name, threats_dict in [('SEMANTIC', ThreatMapping.LLM_THREATS), ('PATTERN', ThreatMapping.YARA_THREATS), ('DATAFLOW', ThreatMapping.BEHAVIORAL_THREATS)]:
            for threat_name, threat_info in threats_dict.items():
                for field in required_fields:
                    assert field in threat_info, f"{detector_name} threat '{threat_name}' missing field '{field}'"

class TestGetThreatMapping:

    def test_get_semantic_threat_mapping(self):
        mapping = ThreatMapping.get_threat_mapping('semantic', 'PROMPT INJECTION')
        assert mapping is not None
        assert mapping['severity'] == 'HIGH'
        assert mapping['aitech'] == 'AITech-1.1'

    def test_get_yara_threat_mapping(self):
        mapping = ThreatMapping.get_threat_mapping('yara', 'CODE EXECUTION')
        assert mapping is not None
        assert 'severity' in mapping
        assert 'aitech' in mapping

    def test_get_dataflow_threat_mapping(self):
        mapping = ThreatMapping.get_threat_mapping('dataflow', 'PROMPT INJECTION')
        assert mapping is not None
        assert mapping['severity'] == 'HIGH'

    def test_get_pattern_threat_mapping(self):
        mapping = ThreatMapping.get_threat_mapping('pattern', 'INJECTION ATTACK')
        assert mapping is not None
        assert 'severity' in mapping

    def test_unknown_detector_raises_error(self):
        with pytest.raises(ValueError, match='Unknown detector'):
            ThreatMapping.get_threat_mapping('unknown_detector', 'PROMPT INJECTION')

    def test_unknown_threat_returns_generic(self):
        mapping = ThreatMapping.get_threat_mapping('semantic', 'UNKNOWN_THREAT')
        assert mapping is not None
        assert mapping['scanner_category'] == 'UNKNOWN'
        assert mapping['aitech'] == 'AITech-99.9'

class TestSimplifiedMappings:

    def test_llm_threat_mapping_exists(self):
        assert LLM_THREAT_MAPPING is not None
        assert len(LLM_THREAT_MAPPING) > 0

    def test_yara_threat_mapping_exists(self):
        assert YARA_THREAT_MAPPING is not None
        assert len(YARA_THREAT_MAPPING) > 0

    def test_dataflow_threat_mapping_exists(self):
        assert BEHAVIORAL_THREAT_MAPPING is not None
        assert len(BEHAVIORAL_THREAT_MAPPING) > 0

    def test_simplified_mapping_structure(self):
        for threat_name, threat_info in LLM_THREAT_MAPPING.items():
            assert 'threat_category' in threat_info
            assert 'threat_type' in threat_info
            assert 'severity' in threat_info

class TestHelperFunctions:

    def test_get_threat_severity(self):
        severity = get_threat_severity('semantic', 'PROMPT INJECTION')
        assert severity == 'HIGH'
        severity = get_threat_severity('semantic', 'COMMAND INJECTION')
        assert severity == 'CRITICAL'

    def test_get_threat_severity_unknown_returns_default(self):
        severity = get_threat_severity('semantic', 'NONEXISTENT_THREAT')
        assert severity == 'MEDIUM'

    def test_get_threat_category(self):
        category = get_threat_category('semantic', 'PROMPT INJECTION')
        assert category == 'PROMPT INJECTION'
        category = get_threat_category('semantic', 'DATA EXFILTRATION')
        assert category == 'SECURITY VIOLATION'

    def test_get_threat_category_unknown_returns_unknown(self):
        category = get_threat_category('semantic', 'NONEXISTENT_THREAT')
        assert category == 'UNKNOWN'

class TestAITechTaxonomy:

    def test_aitech_codes_format(self):
        for threats_dict in [ThreatMapping.LLM_THREATS, ThreatMapping.YARA_THREATS, ThreatMapping.BEHAVIORAL_THREATS]:
            for threat_name, threat_info in threats_dict.items():
                aitech = threat_info['aitech']
                aisubtech = threat_info['aisubtech']
                if aitech is not None:
                    assert aitech.startswith('AITech-')
                    assert '.' in aitech
                if aisubtech is not None:
                    assert aisubtech.startswith('AISubtech-')
                    assert aisubtech.count('.') >= 2

    def test_consistent_aitech_across_detectors(self):
        llm_prompt = ThreatMapping.LLM_THREATS['PROMPT INJECTION']
        yara_prompt = ThreatMapping.YARA_THREATS['PROMPT INJECTION']
        dataflow_prompt = ThreatMapping.BEHAVIORAL_THREATS['PROMPT INJECTION']
        assert llm_prompt['aitech'] == yara_prompt['aitech'] == dataflow_prompt['aitech']
        assert llm_prompt['aitech'] == 'AITech-1.1'

class TestSeverityLevels:

    def test_valid_severity_levels(self):
        valid_severities = {'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO'}
        for threats_dict in [ThreatMapping.LLM_THREATS, ThreatMapping.YARA_THREATS, ThreatMapping.BEHAVIORAL_THREATS]:
            for threat_name, threat_info in threats_dict.items():
                assert threat_info['severity'] in valid_severities, f"Threat '{threat_name}' has invalid severity: {threat_info['severity']}"

    def test_critical_threats_are_critical(self):
        command_inj = ThreatMapping.LLM_THREATS['COMMAND INJECTION']
        assert command_inj['severity'] in ['CRITICAL', 'HIGH']
        data_exfil = ThreatMapping.LLM_THREATS['DATA EXFILTRATION']
        assert data_exfil['severity'] in ['CRITICAL', 'HIGH']
