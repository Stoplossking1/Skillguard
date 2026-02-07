import os
from dataclasses import dataclass
from pathlib import Path

@dataclass
class Config:
    llm_provider_api_key: str | None = None
    llm_model: str = 'claude-3-5-sonnet-20241022'
    llm_base_url: str | None = None
    llm_api_version: str | None = None
    llm_max_tokens: int = 4000
    llm_temperature: float = 0.0
    llm_rate_limit_delay: float = 2.0
    llm_max_retries: int = 3
    llm_timeout: int = 120
    aws_region_name: str = 'us-east-1'
    aws_profile_name: str | None = None
    aws_session_token: str | None = None
    enable_static_analyzer: bool = True
    enable_llm_analyzer: bool = False
    enable_behavioral_analyzer: bool = False
    enable_aidefense: bool = False
    enable_pattern_detector: bool | None = None
    enable_semantic_detector: bool | None = None
    enable_dataflow_detector: bool | None = None
    enable_aidefense_detector: bool | None = None
    virustotal_api_key: str | None = None
    virustotal_upload_files: bool = False
    aidefense_api_key: str | None = None
    max_file_size_mb: int = 10
    scan_timeout_seconds: int = 300
    output_format: str = 'summary'
    detailed_output: bool = False

    def __post_init__(self):

        def read_env_flag(name: str) -> bool | None:
            value = os.getenv(name)
            if value is None:
                return None
            normalized = value.strip().lower()
            if normalized in ('true', '1', 'yes', 'on'):
                return True
            if normalized in ('false', '0', 'no', 'off'):
                return False
            return None
        if self.enable_pattern_detector is None:
            self.enable_pattern_detector = self.enable_static_analyzer
        else:
            self.enable_static_analyzer = self.enable_pattern_detector
        if self.enable_semantic_detector is None:
            self.enable_semantic_detector = self.enable_llm_analyzer
        else:
            self.enable_llm_analyzer = self.enable_semantic_detector
        if self.enable_dataflow_detector is None:
            self.enable_dataflow_detector = self.enable_behavioral_analyzer
        else:
            self.enable_behavioral_analyzer = self.enable_dataflow_detector
        if self.enable_aidefense_detector is None:
            self.enable_aidefense_detector = self.enable_aidefense
        else:
            self.enable_aidefense = self.enable_aidefense_detector
        if self.llm_provider_api_key is None:
            self.llm_provider_api_key = os.getenv('SG_LLM_API_KEY')
        if self.llm_model == 'claude-3-5-sonnet-20241022':
            if (env_model := os.getenv('SG_LLM_MODEL')):
                self.llm_model = env_model
        if (env_region := os.getenv('AWS_REGION')):
            self.aws_region_name = env_region
        if (env_profile := os.getenv('AWS_PROFILE')):
            self.aws_profile_name = env_profile
        if (env_session := os.getenv('AWS_SESSION_TOKEN')):
            self.aws_session_token = env_session
        pattern_env = read_env_flag('ENABLE_PATTERN_DETECTOR')
        static_env = read_env_flag('ENABLE_STATIC_ANALYZER')
        if pattern_env is not None:
            self.enable_pattern_detector = pattern_env
        elif static_env is not None:
            self.enable_pattern_detector = static_env
        semantic_env = read_env_flag('ENABLE_SEMANTIC_DETECTOR')
        llm_env = read_env_flag('ENABLE_LLM_ANALYZER')
        if semantic_env is not None:
            self.enable_semantic_detector = semantic_env
        elif llm_env is not None:
            self.enable_semantic_detector = llm_env
        dataflow_env = read_env_flag('ENABLE_DATAFLOW_DETECTOR')
        behavioral_env = read_env_flag('ENABLE_BEHAVIORAL_ANALYZER')
        if dataflow_env is not None:
            self.enable_dataflow_detector = dataflow_env
        elif behavioral_env is not None:
            self.enable_dataflow_detector = behavioral_env
        aidefense_env = read_env_flag('ENABLE_AIDEFENSE_DETECTOR')
        aidefense_legacy_env = read_env_flag('ENABLE_AIDEFENSE')
        if aidefense_env is not None:
            self.enable_aidefense_detector = aidefense_env
        elif aidefense_legacy_env is not None:
            self.enable_aidefense_detector = aidefense_legacy_env
        self.enable_static_analyzer = bool(self.enable_pattern_detector)
        self.enable_llm_analyzer = bool(self.enable_semantic_detector)
        self.enable_behavioral_analyzer = bool(self.enable_dataflow_detector)
        self.enable_aidefense = bool(self.enable_aidefense_detector)
        if self.virustotal_api_key is None:
            self.virustotal_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        if os.getenv('VIRUSTOTAL_UPLOAD_FILES', '').lower() in ('true', '1'):
            self.virustotal_upload_files = True
        if self.aidefense_api_key is None:
            self.aidefense_api_key = os.getenv('AI_DEFENSE_API_KEY')

    @classmethod
    def from_env(cls) -> 'Config':
        return cls()

    @classmethod
    def from_file(cls, config_file: Path) -> 'Config':
        if config_file.exists():
            with open(config_file) as f:
                for line in f:
                    line = line.strip()
                    if line and (not line.startswith('#')) and ('=' in line):
                        key, value = line.split('=', 1)
                        os.environ[key.strip()] = value.strip()
        return cls.from_env()
