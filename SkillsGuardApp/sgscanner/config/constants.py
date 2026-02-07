from pathlib import Path

class ScanOrchestratorConstants:
    VERSION = '0.2.0'
    PROJECT_ROOT = Path(__file__).parent.parent.parent
    PACKAGE_ROOT = Path(__file__).parent.parent
    DATA_DIR = PACKAGE_ROOT / 'data'
    PROMPTS_DIR = DATA_DIR / 'prompts'
    YARA_RULES_DIR = DATA_DIR / 'yara_rules'
    RULES_DIR = PACKAGE_ROOT / 'rules'
    DEFAULT_MAX_FILE_SIZE_MB = 10
    DEFAULT_SCAN_TIMEOUT = 300
    DEFAULT_LLM_MODEL = 'claude-3-5-sonnet-20241022'
    DEFAULT_LLM_MAX_TOKENS = 4000
    DEFAULT_LLM_TEMPERATURE = 0.0
    SEVERITY_CRITICAL = 'CRITICAL'
    SEVERITY_HIGH = 'HIGH'
    SEVERITY_MEDIUM = 'MEDIUM'
    SEVERITY_LOW = 'LOW'
    SEVERITY_INFO = 'INFO'
    SEVERITY_SAFE = 'SAFE'
    THREAT_PROMPT_INJECTION = 'prompt_injection'
    THREAT_COMMAND_INJECTION = 'command_injection'
    THREAT_DATA_EXFILTRATION = 'data_exfiltration'
    THREAT_UNAUTHORIZED_TOOL = 'unauthorized_tool_use'
    THREAT_OBFUSCATION = 'obfuscation'
    THREAT_HARDCODED_SECRETS = 'hardcoded_secrets'
    THREAT_SOCIAL_ENGINEERING = 'social_engineering'
    THREAT_RESOURCE_ABUSE = 'resource_abuse'

    @classmethod
    def get_prompts_path(cls) -> Path:
        return cls.PROMPTS_DIR

    @classmethod
    def get_rules_path(cls) -> Path:
        return cls.RULES_DIR

    @classmethod
    def get_data_path(cls) -> Path:
        return cls.DATA_DIR

    @classmethod
    def get_yara_rules_path(cls) -> Path:
        return cls.YARA_RULES_DIR
