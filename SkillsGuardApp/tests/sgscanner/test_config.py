import os
from pathlib import Path
from unittest.mock import patch
import pytest
from sgscanner.config.config import Config
from sgscanner.config.constants import ScanOrchestratorConstants

class TestConfigInitialization:

    def test_config_with_defaults(self):
        env_without_llm = {k: v for k, v in os.environ.items() if not k.startswith('SG_LLM')}
        with patch.dict('os.environ', env_without_llm, clear=True):
            config = Config()
            assert config.llm_model == 'claude-3-5-sonnet-20241022'
            assert config.llm_max_tokens == 4000
            assert config.llm_temperature == 0.0
            assert config.enable_pattern_detector

    def test_config_with_custom_values(self):
        config = Config(llm_model='gpt-4o', llm_max_tokens=8000, llm_temperature=0.5, enable_semantic_detector=True)
        assert config.llm_model == 'gpt-4o'
        assert config.llm_max_tokens == 8000
        assert config.llm_temperature == 0.5
        assert config.enable_semantic_detector

    def test_config_from_env_variables(self):
        with patch.dict('os.environ', {'SG_LLM_API_KEY': 'test-key-123', 'SG_LLM_MODEL': 'claude-3-opus-20240229', 'AWS_REGION': 'us-west-2', 'ENABLE_LLM_ANALYZER': 'true'}):
            config = Config.from_env()
            assert config.llm_provider_api_key == 'test-key-123'
            assert config.llm_model == 'claude-3-opus-20240229'
            assert config.aws_region_name == 'us-west-2'
            assert config.enable_semantic_detector

    def test_config_api_key_uses_sgscanner_env(self):
        with patch.dict('os.environ', {'SG_LLM_API_KEY': 'scanner-key'}):
            config = Config()
            assert config.llm_provider_api_key == 'scanner-key'

class TestConfigAWS:

    def test_aws_region_configuration(self):
        config = Config(aws_region_name='eu-west-1')
        assert config.aws_region_name == 'eu-west-1'

    def test_aws_profile_configuration(self):
        config = Config(aws_profile_name='production')
        assert config.aws_profile_name == 'production'

    def test_aws_session_token(self):
        config = Config(aws_session_token='temp-session-token')
        assert config.aws_session_token == 'temp-session-token'

    def test_aws_from_environment(self):
        with patch.dict('os.environ', {'AWS_REGION': 'ap-southeast-1', 'AWS_PROFILE': 'dev', 'AWS_SESSION_TOKEN': 'session-123'}):
            config = Config.from_env()
            assert config.aws_region_name == 'ap-southeast-1'
            assert config.aws_profile_name == 'dev'
            assert config.aws_session_token == 'session-123'

class TestConfigAnalyzerToggles:

    def test_analyzer_defaults(self):
        config = Config()
        assert config.enable_pattern_detector
        assert not config.enable_semantic_detector
        assert not config.enable_dataflow_detector

    def test_enable_all_analyzers(self):
        config = Config(enable_pattern_detector=True, enable_semantic_detector=True, enable_dataflow_detector=True)
        assert config.enable_pattern_detector
        assert config.enable_semantic_detector
        assert config.enable_dataflow_detector

    def test_analyzer_toggles_from_env(self):
        with patch.dict('os.environ', {'ENABLE_STATIC_ANALYZER': 'false', 'ENABLE_LLM_ANALYZER': 'true', 'ENABLE_BEHAVIORAL_ANALYZER': '1'}):
            config = Config.from_env()
            assert not config.enable_pattern_detector
            assert config.enable_semantic_detector
            assert config.enable_dataflow_detector

class TestConstants:

    def test_constants_paths_exist(self):
        assert ScanOrchestratorConstants.PROJECT_ROOT is not None
        assert ScanOrchestratorConstants.PACKAGE_ROOT is not None
        assert ScanOrchestratorConstants.PROMPTS_DIR is not None
        assert ScanOrchestratorConstants.DATA_DIR is not None

    def test_get_prompts_path(self):
        path = ScanOrchestratorConstants.get_prompts_path()
        assert path is not None
        assert 'prompts' in str(path)

    def test_get_data_path(self):
        path = ScanOrchestratorConstants.get_data_path()
        assert path is not None
        assert 'data' in str(path)

    def test_get_yara_rules_path(self):
        path = ScanOrchestratorConstants.get_yara_rules_path()
        assert path is not None
        assert 'yara_rules' in str(path)

    def test_severity_constants(self):
        assert ScanOrchestratorConstants.SEVERITY_CRITICAL == 'CRITICAL'
        assert ScanOrchestratorConstants.SEVERITY_HIGH == 'HIGH'
        assert ScanOrchestratorConstants.SEVERITY_MEDIUM == 'MEDIUM'
        assert ScanOrchestratorConstants.SEVERITY_LOW == 'LOW'

    def test_threat_category_constants(self):
        assert ScanOrchestratorConstants.THREAT_PROMPT_INJECTION == 'prompt_injection'
        assert ScanOrchestratorConstants.THREAT_COMMAND_INJECTION == 'command_injection'
        assert ScanOrchestratorConstants.THREAT_DATA_EXFILTRATION == 'data_exfiltration'

class TestConfigFromFile:

    def test_loads_from_env_file(self, tmp_path):
        env_file = tmp_path / '.env'
        env_file.write_text('\nSG_LLM_API_KEY=test-key-from-file\nSG_LLM_MODEL=claude-3-opus-20240229\nAWS_REGION=eu-central-1\nENABLE_LLM_ANALYZER=true\n        ')
        config = Config.from_file(env_file)
        assert config.llm_provider_api_key == 'test-key-from-file'
        assert config.llm_model == 'claude-3-opus-20240229'
        assert config.aws_region_name == 'eu-central-1'
        assert config.enable_semantic_detector

    def test_handles_nonexistent_env_file(self, tmp_path):
        nonexistent = tmp_path / 'nonexistent.env'
        config = Config.from_file(nonexistent)
        assert config is not None
        assert config.llm_model is not None
