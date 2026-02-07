import asyncio
import hashlib
import logging
import os
from pathlib import Path
from typing import Any
from ..models import Finding, Severity, Skill, ThreatCategory
from ..static_analysis.context_extractor import ContextExtractor, SkillFunctionContext, SkillScriptContext
from ..static_analysis.interprocedural.call_graph_analyzer import CallGraphAnalyzer
from ..static_analysis.interprocedural.cross_file_analyzer import CrossFileAnalyzer, CrossFileCorrelation
from .base import ScanEngine
from .registry import register_engine
logger = logging.getLogger('sg.' + __name__)

@register_engine(name='dataflow_detector', description='Static dataflow analysis for Python files', aliases=('behavioral_analyzer',), metadata={'expose_api': True, 'expose_cli': True, 'order': 20})
class DataflowEngine(ScanEngine):
    engine_id = 'dataflow_detector'

    def __init__(self, use_static_analysis: bool=True, use_alignment_verification: bool=False, llm_model: str | None=None, llm_api_key: str | None=None):
        super().__init__()
        if not use_static_analysis:
            logger.warning('use_static_analysis=False is deprecated and ignored. Static analysis is required for the dataflow detector to function.')
        self.use_static_analysis = True
        self.use_alignment_verification = use_alignment_verification
        self.context_extractor = ContextExtractor()
        self.alignment_orchestrator = None
        if use_alignment_verification:
            try:
                from .behavioral.alignment import AlignmentOrchestrator
                model = llm_model or os.environ.get('SG_LLM_MODEL', 'gemini/gemini-2.0-flash')
                api_key = llm_api_key or os.environ.get('SG_LLM_API_KEY')
                if api_key:
                    self.alignment_orchestrator = AlignmentOrchestrator(llm_model=model, llm_api_key=api_key)
                    logger.info('Alignment verification enabled with %s', model)
                else:
                    logger.warning('Alignment verification requested but no API key found')
            except ImportError as e:
                logger.warning('Alignment verification not available: %s', e)

    def run(self, skill: Skill) -> list[Finding]:
        return self._analyze_static(skill)

    def _analyze_static(self, skill: Skill) -> list[Finding]:
        findings = []
        cross_file = CrossFileAnalyzer()
        call_graph_analyzer = CallGraphAnalyzer()
        skill_description = None
        if skill.manifest:
            skill_description = skill.manifest.description
        for script_file in skill.get_scripts():
            if script_file.file_type != 'python':
                continue
            content = script_file.read_content()
            if not content:
                continue
            call_graph_analyzer.add_file(script_file.path, content)
            try:
                context = self.context_extractor.extract_context(script_file.path, content)
                cross_file.add_file_context(script_file.relative_path, context)
                script_findings = self._generate_findings_from_context(context, skill)
                findings.extend(script_findings)
                if self.alignment_orchestrator:
                    alignment_findings = self._run_alignment_verification(script_file.path, content, skill_description)
                    findings.extend(alignment_findings)
            except Exception as e:
                logger.warning('Failed to analyze %s: %s', script_file.relative_path, e)
        call_graph_analyzer.build_call_graph()
        correlations = cross_file.analyze_correlations()
        correlation_findings = self._generate_findings_from_correlations(correlations, skill)
        findings.extend(correlation_findings)
        return findings

    def _run_alignment_verification(self, file_path: Path, source_code: str, skill_description: str | None) -> list[Finding]:
        findings = []
        if not self.alignment_orchestrator:
            return findings
        try:
            function_contexts = self.context_extractor.extract_function_contexts(file_path, source_code)
            for func_context in function_contexts:
                try:
                    result = asyncio.get_event_loop().run_until_complete(self.alignment_orchestrator.check_alignment(func_context, skill_description))
                    if result:
                        analysis, ctx = result
                        finding = self._create_alignment_finding(analysis, ctx, str(file_path))
                        if finding:
                            findings.append(finding)
                except Exception as e:
                    logger.warning('Alignment check failed for %s: %s', func_context.name, e)
        except Exception as e:
            logger.warning('Alignment verification failed for %s: %s', file_path, e)
        return findings

    def _create_alignment_finding(self, analysis: dict[str, Any], func_context: SkillFunctionContext, file_path: str) -> Finding | None:
        try:
            threat_name = analysis.get('threat_name', 'ALIGNMENT_MISMATCH').upper()
            severity_str = analysis.get('severity', 'MEDIUM').upper()
            severity_map = {'CRITICAL': RiskLevel.CRITICAL, 'HIGH': RiskLevel.HIGH, 'MEDIUM': RiskLevel.MEDIUM, 'LOW': RiskLevel.LOW, 'INFO': RiskLevel.LOW}
            severity = severity_map.get(severity_str, RiskLevel.MEDIUM)
            category_map = {'DATA EXFILTRATION': ThreatClass.DATA_EXFILTRATION, 'CREDENTIAL THEFT': ThreatClass.DATA_EXFILTRATION, 'COMMAND INJECTION': ThreatClass.COMMAND_INJECTION, 'HIDDEN FUNCTIONALITY': ThreatClass.POLICY_VIOLATION, 'ALIGNMENT_MISMATCH': ThreatClass.POLICY_VIOLATION}
            category = category_map.get(threat_name, ThreatClass.POLICY_VIOLATION)
            description_claims = analysis.get('description_claims', '')
            actual_behavior = analysis.get('actual_behavior', '')
            summary = analysis.get('summary', f'Alignment mismatch in {func_context.name}')
            if description_claims and actual_behavior:
                description = f"{summary}. Description claims: '{description_claims}'. Actual behavior: {actual_behavior}"
            else:
                description = summary
            return Issue(id=self._generate_id(f'ALIGNMENT_{threat_name}', f'{file_path}:{func_context.name}'), rule_id=f'BEHAVIOR_ALIGNMENT_{threat_name.replace(' ', '_')}', category=category, severity=severity, title=f'Alignment mismatch: {threat_name} in {func_context.name}', description=description, file_path=file_path, line_number=func_context.line_number, remediation=f'Review function {func_context.name} and ensure documentation matches implementation', engine='dataflow', metadata={'function_name': func_context.name, 'threat_name': threat_name, 'confidence': analysis.get('confidence'), 'security_implications': analysis.get('security_implications'), 'dataflow_evidence': analysis.get('dataflow_evidence'), 'classification': analysis.get('threat_vulnerability_classification')})
        except Exception as e:
            logger.warning('Failed to create alignment finding: %s', e)
            return None

    def _generate_findings_from_context(self, context: SkillScriptContext, skill: Skill) -> list[Finding]:
        findings = []
        if context.has_network and context.has_env_var_access:
            findings.append(Issue(id=self._generate_id('ENV_VAR_EXFILTRATION', context.file_path), rule_id='BEHAVIOR_ENV_VAR_EXFILTRATION', category=ThreatClass.DATA_EXFILTRATION, severity=RiskLevel.CRITICAL, title='Environment variable access with network calls detected', description=f'Script accesses environment variables and makes network calls in {context.file_path}', file_path=context.file_path, remediation='Remove environment variable harvesting or network transmission', engine='dataflow', metadata={'has_network': context.has_network, 'has_env_access': context.has_env_var_access, 'suspicious_urls': context.suspicious_urls}))
        if context.has_credential_access:
            findings.append(Issue(id=self._generate_id('CREDENTIAL_FILE_ACCESS', context.file_path), rule_id='BEHAVIOR_CREDENTIAL_FILE_ACCESS', category=ThreatClass.DATA_EXFILTRATION, severity=RiskLevel.HIGH, title='Credential file access detected', description=f'Script accesses credential files in {context.file_path}', file_path=context.file_path, remediation='Remove access to ~/.aws, ~/.ssh, or other credential files', engine='dataflow'))
        if context.has_env_var_access:
            findings.append(Issue(id=self._generate_id('ENV_VAR_HARVESTING', context.file_path), rule_id='BEHAVIOR_ENV_VAR_HARVESTING', category=ThreatClass.DATA_EXFILTRATION, severity=RiskLevel.MEDIUM, title='Environment variable harvesting detected', description=f'Script iterates through environment variables in {context.file_path}', file_path=context.file_path, remediation='Remove environment variable collection unless explicitly required and documented', engine='dataflow'))
        if context.suspicious_urls:
            for url in context.suspicious_urls:
                findings.append(Issue(id=self._generate_id('SUSPICIOUS_URL', url), rule_id='BEHAVIOR_SUSPICIOUS_URL', category=ThreatClass.DATA_EXFILTRATION, severity=RiskLevel.HIGH, title=f'Suspicious URL detected: {url}', description='Script contains suspicious URL that may be used for data exfiltration', file_path=context.file_path, remediation="Review URL and ensure it's legitimate and documented", engine='dataflow', metadata={'url': url}))
        if context.has_eval_exec and context.has_subprocess:
            findings.append(Issue(id=self._generate_id('EVAL_SUBPROCESS', context.file_path), rule_id='BEHAVIOR_EVAL_SUBPROCESS', category=ThreatClass.COMMAND_INJECTION, severity=RiskLevel.CRITICAL, title='eval/exec combined with subprocess detected', description=f'Dangerous combination of code execution and system commands in {context.file_path}', file_path=context.file_path, remediation='Remove eval/exec or use safer alternatives', engine='dataflow'))
        return findings

    def _generate_id(self, prefix: str, context: str) -> str:
        combined = f'{prefix}:{context}'
        hash_obj = hashlib.sha256(combined.encode())
        return f'{prefix}_{hash_obj.hexdigest()[:10]}'

    def _generate_findings_from_correlations(self, correlations: list[CrossFileCorrelation], skill: Skill) -> list[Finding]:
        findings = []
        for correlation in correlations:
            severity_map = {'CRITICAL': RiskLevel.CRITICAL, 'HIGH': RiskLevel.HIGH, 'MEDIUM': RiskLevel.MEDIUM}
            severity = severity_map.get(correlation.severity, RiskLevel.MEDIUM)
            category_map = {'exfiltration_chain': ThreatClass.DATA_EXFILTRATION, 'credential_network_separation': ThreatClass.DATA_EXFILTRATION, 'env_var_exfiltration': ThreatClass.DATA_EXFILTRATION}
            category = category_map.get(correlation.threat_type, ThreatClass.POLICY_VIOLATION)
            finding = Issue(id=self._generate_id(f'CROSSFILE_{correlation.threat_type.upper()}', '_'.join(correlation.files_involved)), rule_id=f'BEHAVIOR_CROSSFILE_{correlation.threat_type.upper()}', category=category, severity=severity, title=f'Cross-file {correlation.threat_type.replace('_', ' ')}: {len(correlation.files_involved)} files', description=correlation.description, file_path=None, remediation=f'Review data flow across files: {', '.join(correlation.files_involved)}', engine='dataflow', metadata={'files_involved': correlation.files_involved, 'threat_type': correlation.threat_type, 'evidence': correlation.evidence})
            findings.append(finding)
        return findings
