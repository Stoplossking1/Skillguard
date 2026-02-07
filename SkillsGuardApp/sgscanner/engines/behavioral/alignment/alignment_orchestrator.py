import logging
from typing import Any
from ....static_analysis.context_extractor import SkillFunctionContext
from .alignment_llm_client import AlignmentLLMClient
from .alignment_prompt_builder import AlignmentPromptBuilder
from .alignment_response_validator import AlignmentResponseValidator
from .threat_vulnerability_classifier import ThreatVulnerabilityClassifier

class AlignmentOrchestrator:

    def __init__(self, llm_model: str='gemini/gemini-2.0-flash', llm_api_key: str | None=None, llm_base_url: str | None=None, llm_temperature: float=0.1, llm_max_tokens: int=4096, llm_timeout: int=120):
        self.logger = logging.getLogger('sg.' + __name__)
        self.prompt_builder = AlignmentPromptBuilder()
        self.llm_client = AlignmentLLMClient(model=llm_model, api_key=llm_api_key, base_url=llm_base_url, temperature=llm_temperature, max_tokens=llm_max_tokens, timeout=llm_timeout)
        self.response_validator = AlignmentResponseValidator()
        self.threat_vuln_classifier = ThreatVulnerabilityClassifier(model=llm_model, api_key=llm_api_key, base_url=llm_base_url)
        self.stats = {'total_analyzed': 0, 'mismatches_detected': 0, 'no_mismatch': 0, 'skipped_invalid_response': 0, 'skipped_error': 0}
        self.logger.debug('AlignmentOrchestrator initialized')

    async def check_alignment(self, func_context: SkillFunctionContext, skill_description: str | None=None) -> tuple[dict[str, Any], SkillFunctionContext] | None:
        self.stats['total_analyzed'] += 1
        try:
            self.logger.debug(f'Building alignment prompt for {func_context.name}')
            try:
                prompt = self.prompt_builder.build_prompt(func_context, skill_description=skill_description)
            except Exception as e:
                self.logger.error(f'Prompt building failed for {func_context.name}: {e}', exc_info=True)
                self.stats['skipped_error'] += 1
                raise
            self.logger.debug(f'Querying LLM for alignment verification of {func_context.name}')
            try:
                response = await self.llm_client.verify_alignment(prompt)
            except Exception as e:
                self.logger.error(f'LLM verification failed for {func_context.name}: {e}', exc_info=True)
                self.stats['skipped_error'] += 1
                raise
            self.logger.debug(f'Validating alignment response for {func_context.name}')
            try:
                result = self.response_validator.validate(response)
            except Exception as e:
                self.logger.error(f'Response validation failed for {func_context.name}: {e}', exc_info=True)
                self.stats['skipped_error'] += 1
                raise
            if not result:
                self.logger.warning(f'Invalid response for {func_context.name}, skipping')
                self.stats['skipped_invalid_response'] += 1
                return None
            if result.get('mismatch_detected'):
                self.logger.debug(f'Alignment mismatch detected in {func_context.name}')
                self.stats['mismatches_detected'] += 1
                threat_name = result.get('threat_name', '')
                if threat_name != 'GENERAL DESCRIPTION-CODE MISMATCH':
                    self.logger.debug(f'Classifying finding as threat or vulnerability for {func_context.name}')
                    try:
                        classification = await self.threat_vuln_classifier.classify_finding(threat_name=result.get('threat_name', 'UNKNOWN'), severity=result.get('severity', 'UNKNOWN'), summary=result.get('summary', ''), description_claims=result.get('description_claims', ''), actual_behavior=result.get('actual_behavior', ''), security_implications=result.get('security_implications', ''), dataflow_evidence=result.get('dataflow_evidence', ''))
                        if classification:
                            result['threat_vulnerability_classification'] = classification['classification']
                            self.logger.debug(f'Classified as {classification['classification']} with {classification['confidence']} confidence')
                        else:
                            self.logger.warning(f'Failed to classify finding for {func_context.name}')
                            result['threat_vulnerability_classification'] = 'UNCLEAR'
                    except Exception as e:
                        self.logger.error(f'Classification failed for {func_context.name}: {e}', exc_info=True)
                        result['threat_vulnerability_classification'] = 'UNCLEAR'
                return (result, func_context)
            else:
                self.logger.debug(f'No alignment mismatch in {func_context.name}')
                self.stats['no_mismatch'] += 1
                return None
        except Exception as e:
            self.logger.error(f'Alignment check failed for {func_context.name}: {e}')
            self.stats['skipped_error'] += 1
            return None

    def get_statistics(self) -> dict[str, int]:
        return self.stats.copy()
