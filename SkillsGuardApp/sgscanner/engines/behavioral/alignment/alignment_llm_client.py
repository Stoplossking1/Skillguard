import asyncio
import logging
import os
try:
    from litellm import acompletion
    LITELLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LITELLM_AVAILABLE = False
    acompletion = None

class AlignmentLLMClient:
    DEFAULT_MAX_RETRIES = 3
    DEFAULT_RETRY_BASE_DELAY = 2
    PROMPT_LENGTH_THRESHOLD = 50000

    def __init__(self, model: str='gemini/gemini-2.0-flash', api_key: str | None=None, base_url: str | None=None, api_version: str | None=None, temperature: float=0.1, max_tokens: int=4096, timeout: int=120):
        if not LITELLM_AVAILABLE:
            raise ImportError('litellm is required for alignment verification. Install with: pip install litellm')
        self._api_key = api_key or self._resolve_api_key(model)
        if not self._api_key and (not self._is_bedrock_model(model)):
            raise ValueError('LLM provider API key is required for alignment verification')
        self._model = model
        self._base_url = base_url
        self._api_version = api_version
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout
        self.logger = logging.getLogger('sg.' + __name__)
        self.logger.debug(f'AlignmentLLMClient initialized with model: {self._model}')

    def _resolve_api_key(self, model: str) -> str | None:
        model_lower = model.lower()
        if 'vertex' in model_lower:
            return os.environ.get('GOOGLE_APPLICATION_CREDENTIALS')
        elif 'ollama' in model_lower:
            return None
        return os.environ.get('SG_LLM_API_KEY')

    def _is_bedrock_model(self, model: str) -> bool:
        return 'bedrock' in model.lower()

    async def verify_alignment(self, prompt: str) -> str:
        prompt_length = len(prompt)
        self.logger.debug(f'Prompt length: {prompt_length} characters')
        if prompt_length > self.PROMPT_LENGTH_THRESHOLD:
            self.logger.warning(f'Large prompt detected: {prompt_length} characters (threshold: {self.PROMPT_LENGTH_THRESHOLD}) - may be truncated by LLM')
        max_retries = self.DEFAULT_MAX_RETRIES
        base_delay = self.DEFAULT_RETRY_BASE_DELAY
        for attempt in range(max_retries):
            try:
                return await self._make_llm_request(prompt)
            except Exception as e:
                if attempt < max_retries - 1:
                    delay = base_delay * 2 ** attempt
                    self.logger.warning(f'LLM request failed (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {delay}s...')
                    await asyncio.sleep(delay)
                else:
                    self.logger.error(f'LLM request failed after {max_retries} attempts: {e}')
                    raise

    async def _make_llm_request(self, prompt: str) -> str:
        try:
            request_params = {'model': self._model, 'messages': [{'role': 'system', 'content': 'You are a security expert analyzing agent skills. You receive complete dataflow analysis and code context. Analyze if the skill description accurately describes what the code actually does. Respond ONLY with valid JSON. Do not include any markdown formatting or code blocks.'}, {'role': 'user', 'content': prompt}], 'max_tokens': self._max_tokens, 'temperature': self._temperature, 'timeout': self._timeout}
            if self._api_key:
                request_params['api_key'] = self._api_key
            if not self._model.startswith('azure/'):
                request_params['response_format'] = {'type': 'json_object'}
            if self._base_url:
                request_params['api_base'] = self._base_url
            if self._api_version:
                request_params['api_version'] = self._api_version
            self.logger.debug(f'Sending alignment verification request to {self._model}')
            response = await acompletion(**request_params)
            content = response.choices[0].message.content
            if not content or not content.strip():
                self.logger.warning(f'Empty response from LLM model {self._model}')
                self.logger.debug(f'Full response object: {response}')
            else:
                self.logger.debug(f'LLM response length: {len(content)} chars')
            return content if content else ''
        except Exception as e:
            self.logger.error(f'LLM alignment verification failed: {e}', exc_info=True)
            raise
