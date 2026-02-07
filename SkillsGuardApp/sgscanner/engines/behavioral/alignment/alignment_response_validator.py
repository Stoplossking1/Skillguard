import json
import logging
from typing import Any

class AlignmentResponseValidator:

    def __init__(self):
        self.logger = logging.getLogger('sg.' + __name__)

    def validate(self, response: str) -> dict[str, Any] | None:
        if not response or not response.strip():
            self.logger.warning('Empty response from LLM')
            return None
        try:
            data = json.loads(response)
            if not isinstance(data, dict):
                self.logger.warning(f'Response is not a JSON object: {type(data)}')
                return None
            if not self._has_required_fields(data):
                self.logger.warning(f'Response missing required fields. Got: {list(data.keys())}')
                return None
            self.logger.debug(f'LLM response validated: mismatch_detected={data.get('mismatch_detected')}')
            return data
        except json.JSONDecodeError as e:
            self.logger.warning(f'Invalid JSON response: {e}')
            self.logger.debug(f'Raw response (first 500 chars): {response[:500]}')
            return self._extract_json_from_markdown(response)
        except Exception as e:
            self.logger.error(f'Unexpected error validating response: {e}')
            return None

    def _has_required_fields(self, data: dict[str, Any]) -> bool:
        required_fields = ['mismatch_detected']
        if not all((field in data for field in required_fields)):
            return False
        if data.get('mismatch_detected'):
            mismatch_required = ['confidence', 'summary']
            if not all((field in data for field in mismatch_required)):
                return False
        return True

    def _extract_json_from_markdown(self, response: str) -> dict[str, Any] | None:
        try:
            if '```json' in response:
                start = response.find('```json') + 7
                end = response.find('```', start)
                json_str = response[start:end].strip()
            elif '```' in response:
                start = response.find('```') + 3
                end = response.find('```', start)
                json_str = response[start:end].strip()
            else:
                return None
            data = json.loads(json_str)
            if isinstance(data, dict) and self._has_required_fields(data):
                return data
        except Exception:
            pass
        return None
