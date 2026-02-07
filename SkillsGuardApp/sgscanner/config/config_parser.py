import os
from pathlib import Path
from ..utils.logging_config import get_logger
from .config import Config
from .constants import ScanOrchestratorConstants
logger = get_logger(__name__)

def parse_config_from_env() -> Config:
    config = Config()
    config.llm_provider_api_key = os.getenv('SG_LLM_API_KEY')
    config.llm_model = os.getenv('SG_LLM_MODEL', 'claude-3-5-sonnet-20241022')
    if os.getenv('USE_SEMANTIC_DETECTOR', '').lower() == 'true' or os.getenv('USE_LLM_ANALYZER', '').lower() == 'true':
        config.enable_semantic_detector = True
        config.enable_llm_analyzer = True
    if os.getenv('USE_DATAFLOW_DETECTOR', '').lower() == 'true' or os.getenv('USE_BEHAVIORAL_ANALYZER', '').lower() == 'true':
        config.enable_dataflow_detector = True
        config.enable_behavioral_analyzer = True
    output_format = os.getenv('OUTPUT_FORMAT', 'summary').lower()
    if output_format in ['json', 'markdown', 'summary', 'table']:
        config.output_format = output_format
    if os.getenv('VERBOSE', '').lower() == 'true':
        config.detailed_output = True
    return config

def parse_config_file(config_path: str | None=None) -> Config:
    config = parse_config_from_env()
    if not config_path:
        default_paths = [Path.home() / '.sgscanner' / 'config.yaml', Path.home() / '.sgscanner' / 'config.json', Path.cwd() / '.sgscanner.yaml', Path.cwd() / '.sgscanner.json']
        for path in default_paths:
            if path.exists():
                config_path = str(path)
                logger.debug(f'Found config file: {config_path}')
                break
    if config_path and Path(config_path).exists():
        logger.debug(f'Loading config from: {config_path}')
    return config

class ConfigParser:

    def __init__(self):
        self.constants = ScanOrchestratorConstants

    def parse(self, config_path: str | None=None) -> Config:
        return parse_config_file(config_path)

    def get_default_config(self) -> Config:
        return Config()
