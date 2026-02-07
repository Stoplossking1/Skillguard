import asyncio
import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from ..taxonomy.threat_map import ThreatMapping
from ..models import Finding, Severity, Skill, ThreatCategory
from .base import ScanEngine
from .registry import register_engine
from ..llm.client import ProviderConfig
from ..llm.client import LLMRequestHandler
try:
    from litellm import acompletion
    LITELLM_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    LITELLM_AVAILABLE = False
    acompletion = None

@dataclass
class MetaVerdict:
    validated_findings: list[dict[str, Any]] = field(default_factory=list)
    false_positives: list[dict[str, Any]] = field(default_factory=list)
    missed_threats: list[dict[str, Any]] = field(default_factory=list)
    priority_order: list[int] = field(default_factory=list)
    correlations: list[dict[str, Any]] = field(default_factory=list)
    recommendations: list[dict[str, Any]] = field(default_factory=list)
    overall_risk_assessment: dict[str, Any] = field(default_factory=dict)

    def serialize(self) -> dict[str, Any]:
        return {'validated_findings': self.validated_findings, 'false_positives': self.false_positives, 'missed_threats': self.missed_threats, 'priority_order': self.priority_order, 'correlations': self.correlations, 'recommendations': self.recommendations, 'overall_risk_assessment': self.overall_risk_assessment, 'summary': {'total_original': len(self.validated_findings) + len(self.false_positives), 'validated_count': len(self.validated_findings), 'false_positive_count': len(self.false_positives), 'missed_threats_count': len(self.missed_threats), 'recommendations_count': len(self.recommendations)}}

    def get_validated_findings(self, skill: Skill) -> list[Finding]:
        findings = []
        for finding_data in self.validated_findings:
            try:
                severity_str = finding_data.get('severity', 'MEDIUM').upper()
                severity = Severity(severity_str)
                category_str = finding_data.get('category', 'policy_violation')
                try:
                    category = ThreatCategory(category_str)
                except ValueError:
                    category = ThreatClass.POLICY_VIOLATION
                metadata = dict(finding_data.get('metadata', {}))
                if 'confidence' in finding_data:
                    metadata['meta_confidence'] = finding_data['confidence']
                if 'confidence_reason' in finding_data:
                    metadata['meta_confidence_reason'] = finding_data['confidence_reason']
                if 'exploitability' in finding_data:
                    metadata['meta_exploitability'] = finding_data['exploitability']
                if 'impact' in finding_data:
                    metadata['meta_impact'] = finding_data['impact']
                if 'priority_rank' in finding_data:
                    metadata['meta_priority_rank'] = finding_data['priority_rank']
                metadata['meta_validated'] = True
                finding = Issue(id=finding_data.get('id', f'meta_{skill.name}_{len(findings)}'), rule_id=finding_data.get('rule_id', 'META_VALIDATED'), category=category, severity=severity, title=finding_data.get('title', ''), description=finding_data.get('description', ''), file_path=finding_data.get('file_path'), line_number=finding_data.get('line_number'), snippet=finding_data.get('snippet'), remediation=finding_data.get('remediation'), engine='meta', metadata=metadata)
                findings.append(finding)
            except Exception:
                continue
        return findings

    def get_missed_threats(self, skill: Skill) -> list[Finding]:
        findings = []
        for idx, threat_data in enumerate(self.missed_threats):
            try:
                severity_str = threat_data.get('severity', 'HIGH').upper()
                severity = Severity(severity_str)
                aitech_code = threat_data.get('aitech')
                if aitech_code:
                    category_str = ThreatMapping.get_threat_category_from_aitech(aitech_code)
                else:
                    category_str = threat_data.get('category', 'policy_violation')
                try:
                    category = ThreatCategory(category_str)
                except ValueError:
                    category = ThreatClass.POLICY_VIOLATION
                finding = Issue(id=f'meta_missed_{skill.name}_{idx}', rule_id='META_DETECTED', category=category, severity=severity, title=threat_data.get('title', 'Threat detected by meta-analysis'), description=threat_data.get('description', ''), file_path=threat_data.get('file_path'), line_number=threat_data.get('line_number'), snippet=threat_data.get('evidence'), remediation=threat_data.get('remediation'), engine='meta', metadata={'meta_detected': True, 'detection_reason': threat_data.get('detection_reason', ''), 'meta_confidence': threat_data.get('confidence', 'MEDIUM'), 'aitech': aitech_code})
                findings.append(finding)
            except Exception:
                continue
        return findings

@register_engine(name='meta_detector', description='Second-pass LLM analysis for false positive filtering and finding prioritization', aliases=('meta_analyzer',), metadata={'requires': '2+ detectors, LLM API key', 'features': ['False positive filtering', 'Missed threat detection', 'Priority ranking', 'Correlation analysis', 'Remediation guidance'], 'expose_api': True, 'expose_cli': True, 'order': 50})
class MetaEngine(ScanEngine):
    engine_id = 'meta_detector'

    def __init__(self, model: str | None=None, api_key: str | None=None, max_tokens: int=8000, temperature: float=0.1, max_retries: int=3, timeout: int=180, base_url: str | None=None, api_version: str | None=None, aws_region: str | None=None, aws_profile: str | None=None, aws_session_token: str | None=None):
        super().__init__()
        if not LITELLM_AVAILABLE:
            raise ImportError('LiteLLM is required for MetaEngine. Install with: pip install litellm')
        self.api_key = api_key or os.getenv('SG_META_LLM_API_KEY') or os.getenv('SG_LLM_API_KEY')
        self.model = model or os.getenv('SG_META_LLM_MODEL') or os.getenv('SG_LLM_MODEL') or 'claude-3-5-sonnet-20241022'
        self.base_url = base_url or os.getenv('SG_META_LLM_BASE_URL') or os.getenv('SG_LLM_BASE_URL')
        self.api_version = api_version or os.getenv('SG_META_LLM_API_VERSION') or os.getenv('SG_LLM_API_VERSION')
        self.aws_region = aws_region
        self.aws_profile = aws_profile
        self.aws_session_token = aws_session_token
        self.is_bedrock = self.model and 'bedrock/' in self.model
        if not self.api_key and (not self.is_bedrock):
            raise ValueError('Meta Detector LLM API key not configured. Set SG_META_LLM_API_KEY or SG_LLM_API_KEY environment variable.')
        if self.model and self.model.startswith('azure/'):
            if not self.base_url:
                raise ValueError('Azure OpenAI base URL not configured for meta detector. Set SG_META_LLM_BASE_URL environment variable.')
            if not self.api_version:
                raise ValueError('Azure OpenAI API version not configured for meta detector. Set SG_META_LLM_API_VERSION environment variable.')
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.max_retries = max_retries
        self.timeout = timeout
        self._load_prompts()

    def _load_prompts(self):
        prompts_dir = Path(__file__).parent.parent.parent / 'data' / 'prompts'
        meta_prompt_file = prompts_dir / 'skill_meta_analysis_prompt.md'
        try:
            if meta_prompt_file.exists():
                self.system_prompt = meta_prompt_file.read_text(encoding='utf-8')
            else:
                print(f'Warning: Meta-analysis prompt not found at {meta_prompt_file}')
                self.system_prompt = self._get_default_system_prompt()
        except Exception as e:
            print(f'Warning: Failed to load meta-analysis prompt: {e}')
            self.system_prompt = self._get_default_system_prompt()

    def _get_default_system_prompt(self) -> str:
        return 'You are a senior security analyst performing meta-analysis on Agent Skill security findings.\nYour role is to review findings from multiple detectors, identify false positives,\nprioritize by actual risk, correlate related issues, and provide actionable recommendations.\n\nRespond with JSON containing your analysis following the required schema.'

    def run(self, skill: Skill) -> list[Finding]:
        return []

    async def analyze_with_findings(self, skill: Skill, findings: list[Finding], engines_used: list[str]) -> MetaVerdict:
        if not findings:
            return MetaVerdict(overall_risk_assessment={'risk_level': 'SAFE', 'summary': 'No security findings to analyze - skill appears safe.'})
        random_id = secrets.token_hex(16)
        start_tag = f'<!---SKILL_CONTENT_START_{random_id}--->'
        end_tag = f'<!---SKILL_CONTENT_END_{random_id}--->'
        skill_context = self._build_skill_context(skill)
        findings_data = self._serialize_findings(findings)
        user_prompt = self._build_user_prompt(skill=skill, skill_context=skill_context, findings_data=findings_data, engines_used=engines_used, start_tag=start_tag, end_tag=end_tag)
        try:
            response = await self._make_llm_request(self.system_prompt, user_prompt)
            result = self._parse_response(response, findings)
            print(f'Meta-analysis complete: {len(result.validated_findings)} validated, {len(result.false_positives)} false positives filtered, {len(result.missed_threats)} new threats detected')
            return result
        except Exception as e:
            print(f'Meta-analysis failed: {e}')
            return MetaVerdict(validated_findings=[self._finding_to_dict(f) for f in findings], overall_risk_assessment={'risk_level': 'UNKNOWN', 'summary': f'Meta-analysis failed: {str(e)}. Original findings preserved.'})

    def _build_skill_context(self, skill: Skill) -> str:
        lines = []
        lines.append(f'## Skill: {skill.name}')
        lines.append(f'**Description:** {skill.description}')
        lines.append(f'**Directory:** {skill.directory}')
        lines.append('')
        lines.append('### Manifest')
        lines.append(f'- License: {skill.manifest.license or 'Not specified'}')
        lines.append(f'- Compatibility: {skill.manifest.compatibility or 'Not specified'}')
        lines.append(f'- Allowed Tools: {(', '.join(skill.manifest.allowed_tools) if skill.manifest.allowed_tools else 'Not specified')}')
        lines.append('')
        lines.append('### SKILL.md Instructions (Full)')
        max_instruction_size = 50000
        if len(skill.instruction_body) > max_instruction_size:
            lines.append(f'```markdown\n{skill.instruction_body[:max_instruction_size]}\n... [TRUNCATED - {len(skill.instruction_body)} chars total]\n```')
        else:
            lines.append(f'```markdown\n{skill.instruction_body}\n```')
        lines.append('')
        lines.append('### Files in Skill Package')
        for f in skill.files:
            lines.append(f'- {f.relative_path} ({f.file_type}, {f.size_bytes} bytes)')
        lines.append('')
        lines.append('### File Contents')
        code_extensions = {'.py', '.sh', '.bash', '.js', '.ts', '.rb', '.pl', '.yaml', '.yml', '.json', '.toml'}
        max_file_size = 30000
        total_code_size = 0
        max_total_code_size = 150000
        for f in skill.files:
            if total_code_size >= max_total_code_size:
                lines.append('\n... [REMAINING FILES OMITTED - total code size limit reached]')
                break
            file_ext = Path(f.relative_path).suffix.lower()
            if file_ext in code_extensions or f.file_type in ['python', 'bash', 'script']:
                try:
                    file_path = Path(skill.directory) / f.relative_path
                    if file_path.exists() and file_path.is_file():
                        content = file_path.read_text(encoding='utf-8', errors='replace')
                        if len(content) > max_file_size:
                            content = content[:max_file_size] + f'\n... [TRUNCATED - {len(content)} chars total]'
                        lines.append(f'\n#### {f.relative_path}')
                        lines.append(f'```{file_ext.lstrip('.') or 'text'}\n{content}\n```')
                        total_code_size += len(content)
                except Exception:
                    pass
        lines.append('')
        if skill.referenced_files:
            lines.append('### Referenced Files')
            for ref in skill.referenced_files:
                lines.append(f'- {ref}')
            lines.append('')
        return '\n'.join(lines)

    def _serialize_findings(self, findings: list[Finding]) -> str:
        findings_list = []
        for i, f in enumerate(findings):
            findings_list.append({'_index': i, 'id': f.id, 'rule_id': f.rule_id, 'category': f.category.value, 'severity': f.severity.value, 'title': f.title, 'description': f.description, 'file_path': f.file_path, 'line_number': f.line_number, 'snippet': f.snippet[:500] if f.snippet else None, 'engine': f.engine, 'metadata': f.metadata})
        return json.dumps(findings_list, indent=2)

    def _finding_to_dict(self, finding: Finding) -> dict[str, Any]:
        return {'id': finding.id, 'rule_id': finding.rule_id, 'category': finding.category.value, 'severity': finding.severity.value, 'title': finding.title, 'description': finding.description, 'file_path': finding.file_path, 'line_number': finding.line_number, 'snippet': finding.snippet, 'remediation': finding.remediation, 'engine': finding.engine, 'engine': finding.engine, 'metadata': finding.metadata}

    def _build_user_prompt(self, skill: Skill, skill_context: str, findings_data: str, engines_used: list[str], start_tag: str, end_tag: str) -> str:
        num_findings = findings_data.count('"_index"')
        return f"""## Meta-Analysis Request\n\nYou have {num_findings} findings from {len(engines_used)} detectors. Your job is to **filter the noise and prioritize what matters**.\n\n**IMPORTANT**: You have FULL ACCESS to the skill content below - including complete SKILL.md and all code files. Use this to VERIFY findings are accurate.\n\n### Detectors Used\n{', '.join(engines_used)}\n\n### Skill Context (FULL CONTENT)\n{start_tag}\n{skill_context}\n{end_tag}\n\n### Findings from Detectors ({num_findings} total)\n```json\n{findings_data}\n```\n\n### Your Task (IN ORDER OF IMPORTANCE)\n\n1. **FILTER FALSE POSITIVES** (Most Important)\n   - VERIFY each finding against the actual code above. If the code doesn't match the claim → FALSE POSITIVE\n   - Pattern matches without actual malicious behavior → FALSE POSITIVE\n   - Pattern-only findings not confirmed by semantic/dataflow → likely FALSE POSITIVE\n   - Reading internal files, using standard libraries normally → FALSE POSITIVE\n   - Aim to filter 30-70% of pattern detector findings as noise\n\n2. **PRIORITIZE BY ACTUAL RISK**\n   - What should the developer fix FIRST? Put it at index 0 in priority_order\n   - CRITICAL: Active data exfiltration, credential theft\n   - HIGH: Command injection, prompt injection with clear exploitation path\n   - MEDIUM: Potential issues that need more context\n   - LOW/Filter: Informational, style, missing optional metadata\n\n3. **CONSOLIDATE RELATED FINDINGS**\n   - Multiple findings about the same issue = ONE entry in correlations\n   - Example: "Reads AWS creds" + "Makes HTTP POST" + "Sends data" = ONE "Credential Exfiltration" issue\n\n4. **MAKE ACTIONABLE**\n   - Every recommendation needs a specific fix (code example if possible)\n   - "Don't do X" is not actionable. "Replace X with Y" is actionable.\n\n5. **DETECT MISSED THREATS** (ONLY if obvious)\n   - This should be RARE. Leave missed_threats EMPTY unless there's something critical and obvious.\n   - Don't invent problems to fill this field.\n\nRespond with a JSON object following the schema in the system prompt."""

    async def _make_llm_request(self, system_prompt: str, user_prompt: str) -> str:
        messages = [{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_prompt}]
        api_params = {'model': self.model, 'messages': messages, 'temperature': self.temperature, 'max_tokens': self.max_tokens, 'timeout': float(self.timeout)}
        if self.api_key:
            api_params['api_key'] = self.api_key
        if self.base_url:
            api_params['api_base'] = self.base_url
        if self.api_version:
            api_params['api_version'] = self.api_version
        if self.aws_region:
            api_params['aws_region_name'] = self.aws_region
        if self.aws_session_token:
            api_params['aws_session_token'] = self.aws_session_token
        if self.aws_profile:
            api_params['aws_profile_name'] = self.aws_profile
        last_exception = None
        for attempt in range(self.max_retries):
            try:
                response = await acompletion(**api_params)
                return response.choices[0].message.content
            except Exception as e:
                last_exception = e
                error_msg = str(e).lower()
                is_retryable = any((keyword in error_msg for keyword in ['timeout', 'tls', 'connection', 'network', 'rate limit', 'throttle', '429', '503', '504']))
                if attempt < self.max_retries - 1 and is_retryable:
                    delay = 2 ** attempt * 1.0
                    print(f'Meta-analysis LLM request failed (attempt {attempt + 1}): {e}')
                    await asyncio.sleep(delay)
                else:
                    raise last_exception
        raise last_exception

    def _parse_response(self, response: str, original_findings: list[Finding]) -> MetaVerdict:
        try:
            json_data = self._extract_json_from_response(response)
            result = MetaVerdict(validated_findings=json_data.get('validated_findings', []), false_positives=json_data.get('false_positives', []), missed_threats=json_data.get('missed_threats', []), priority_order=json_data.get('priority_order', []), correlations=json_data.get('correlations', []), recommendations=json_data.get('recommendations', []), overall_risk_assessment=json_data.get('overall_risk_assessment', {}))
            self._enrich_findings(result, original_findings)
            return result
        except (json.JSONDecodeError, ValueError) as e:
            print(f'Failed to parse meta-analysis response: {e}')
            return MetaVerdict(validated_findings=[self._finding_to_dict(f) for f in original_findings], overall_risk_assessment={'risk_level': 'UNKNOWN', 'summary': 'Failed to parse meta-analysis response'})

    def _extract_json_from_response(self, response: str) -> dict[str, Any]:
        if not response or not response.strip():
            raise ValueError('Empty response from LLM')
        try:
            return json.loads(response.strip())
        except json.JSONDecodeError:
            pass
        try:
            json_start = '```json'
            json_end = '```'
            start_idx = response.find(json_start)
            if start_idx != -1:
                content_start = start_idx + len(json_start)
                end_idx = response.find(json_end, content_start)
                if end_idx != -1:
                    json_str = response[content_start:end_idx].strip()
                    return json.loads(json_str)
        except json.JSONDecodeError:
            pass
        try:
            start_idx = response.find('{')
            if start_idx != -1:
                brace_count = 0
                end_idx = -1
                for i in range(start_idx, len(response)):
                    if response[i] == '{':
                        brace_count += 1
                    elif response[i] == '}':
                        brace_count -= 1
                        if brace_count == 0:
                            end_idx = i + 1
                            break
                if end_idx != -1:
                    json_content = response[start_idx:end_idx]
                    return json.loads(json_content)
        except json.JSONDecodeError:
            pass
        raise ValueError('No valid JSON found in response')

    def _enrich_findings(self, result: MetaVerdict, original_findings: list[Finding]) -> None:
        original_lookup = {i: self._finding_to_dict(f) for i, f in enumerate(original_findings)}
        for finding in result.validated_findings:
            idx = finding.get('_index')
            if idx is not None and idx in original_lookup:
                original = original_lookup[idx]
                for key, value in original.items():
                    if key not in finding:
                        finding[key] = value
        for finding in result.false_positives:
            idx = finding.get('_index')
            if idx is not None and idx in original_lookup:
                original = original_lookup[idx]
                for key, value in original.items():
                    if key not in finding:
                        finding[key] = value

def apply_meta_filtering(original_findings: list[Finding], meta_result: MetaVerdict, skill: Skill) -> list[Finding]:
    fp_data: dict[int, dict[str, Any]] = {}
    for fp in meta_result.false_positives:
        if '_index' in fp:
            fp_data[fp['_index']] = {'reason': fp.get('reason') or fp.get('false_positive_reason') or 'Identified as likely false positive', 'confidence': fp.get('confidence')}
    enrichments: dict[int, dict[str, Any]] = {}
    priority_lookup: dict[int, int] = {}
    for rank, idx in enumerate(meta_result.priority_order, start=1):
        priority_lookup[idx] = rank
    for vf in meta_result.validated_findings:
        idx = vf.get('_index')
        if idx is not None:
            enrichments[idx] = {'meta_validated': True, 'meta_confidence': vf.get('confidence'), 'meta_confidence_reason': vf.get('confidence_reason'), 'meta_exploitability': vf.get('exploitability'), 'meta_impact': vf.get('impact')}
    result_findings = []
    for i, finding in enumerate(original_findings):
        if finding.metadata is None:
            finding.metadata = {}
        if i in fp_data:
            finding.metadata['meta_false_positive'] = True
            finding.metadata['meta_reason'] = fp_data[i]['reason']
            if fp_data[i].get('confidence') is not None:
                finding.metadata['meta_confidence'] = fp_data[i]['confidence']
        else:
            finding.metadata['meta_false_positive'] = False
            if i in enrichments:
                for key, value in enrichments[i].items():
                    if value is not None:
                        finding.metadata[key] = value
            else:
                finding.metadata['meta_reviewed'] = True
        if i in priority_lookup:
            finding.metadata['meta_priority'] = priority_lookup[i]
        result_findings.append(finding)
    missed_findings = meta_result.get_missed_threats(skill)
    for mf in missed_findings:
        if mf.metadata is None:
            mf.metadata = {}
        mf.metadata['meta_false_positive'] = False
    result_findings.extend(missed_findings)
    return result_findings
