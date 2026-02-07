import asyncio
import hashlib
import json
import os
from typing import Any
try:
    import httpx
    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False
from ..models import Finding, Severity, Skill, ThreatCategory
from ..taxonomy.threat_map import ThreatMapping
from .base import ScanEngine
from .registry import register_engine
AI_DEFENSE_API_URL = 'https://us.api.inspect.aidefense.security.skillsguard.com/api/v1'
DEFAULT_ENABLED_RULES = [{'rule_name': 'Prompt Injection'}, {'rule_name': 'Harassment'}, {'rule_name': 'Hate Speech'}, {'rule_name': 'Profanity'}, {'rule_name': 'Sexual Content & Exploitation'}, {'rule_name': 'Social Division & Polarization'}, {'rule_name': 'Violence & Public Safety Threats'}, {'rule_name': 'Code Detection'}]

@register_engine(name='aidefense_detector', description='SkillsGuard AI Defense cloud-based threat detection', aliases=('aidefense_analyzer',), metadata={'requires_api_key': True, 'expose_api': True, 'expose_cli': True, 'order': 40})
class AIDefenseEngine(ScanEngine):
    engine_id = 'aidefense_detector'
    supports_async = True

    def __init__(self, api_key: str | None=None, api_url: str | None=None, timeout: int=60, max_retries: int=3, enabled_rules: list[dict[str, str]] | None=None, include_rules: bool=True):
        super().__init__()
        if not HTTPX_AVAILABLE:
            raise ImportError('httpx is required for AI Defense detector. Install with: pip install httpx')
        self.api_key = api_key or os.getenv('AI_DEFENSE_API_KEY')
        if not self.api_key:
            raise ValueError('AI Defense API key required. Set AI_DEFENSE_API_KEY environment variable or pass api_key parameter.')
        self.api_url = api_url or os.getenv('AI_DEFENSE_API_URL', AI_DEFENSE_API_URL)
        self.timeout = timeout
        self.max_retries = max_retries
        self.enabled_rules = enabled_rules or DEFAULT_ENABLED_RULES
        self.include_rules = include_rules
        self._client = None

    def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout), headers={'X-SkillsGuard-AI-Defense-API-Key': self.api_key, 'Content-Type': 'application/json', 'Accept': 'application/json'})
        return self._client

    async def _close_client(self):
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _get_payload(self, messages: list[dict[str, str]], metadata: dict[str, Any] | None=None, include_rules: bool | None=None, rules_override: list[dict[str, str]] | None=None) -> dict[str, Any]:
        payload = {'messages': messages}
        if metadata:
            payload['metadata'] = metadata
        if include_rules is None:
            include_rules = self.include_rules
        if include_rules:
            rules_to_use = rules_override if rules_override is not None else self.enabled_rules
            if rules_to_use:
                payload['config'] = {'enabled_rules': rules_to_use}
        return payload

    def _get_rules_for_content_type(self, content_type: str) -> list[dict[str, str]]:
        if content_type == 'code':
            return [rule for rule in self.enabled_rules if rule.get('rule_name') != 'Code Detection']
        else:
            return self.enabled_rules

    def run(self, skill: Skill) -> list[Finding]:
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.run_async(skill))
        finally:
            loop.run_until_complete(self._close_client())

    async def run_async(self, skill: Skill) -> list[Finding]:
        findings = []
        try:
            skill_md_findings = await self._analyze_prompt_content(skill.instruction_body, skill.name, 'SKILL.md', 'skill_instructions')
            findings.extend(skill_md_findings)
            manifest_findings = await self._analyze_prompt_content(f'Name: {skill.manifest.name}\nDescription: {skill.manifest.description}', skill.name, 'manifest', 'skill_manifest')
            findings.extend(manifest_findings)
            for md_file in skill.get_markdown_files():
                content = md_file.read_content()
                if content:
                    md_findings = await self._analyze_prompt_content(content, skill.name, md_file.relative_path, 'markdown_content')
                    findings.extend(md_findings)
            for script_file in skill.get_scripts():
                content = script_file.read_content()
                if content:
                    code_findings = await self._analyze_code_content(content, skill.name, script_file.relative_path, script_file.file_type)
                    findings.extend(code_findings)
        except Exception as e:
            print(f'AI Defense API analysis failed for {skill.name}: {e}')
        return findings

    async def _analyze_prompt_content(self, content: str, skill_name: str, file_path: str, content_type: str) -> list[Finding]:
        if not content or not content.strip():
            return []
        findings = []
        try:
            messages = [{'role': 'user', 'content': content[:10000]}]
            metadata = {'source': 'sgscanner', 'skill_name': skill_name, 'file_path': file_path, 'content_type': content_type}
            rules_for_prompts = self._get_rules_for_content_type(content_type)
            payload = self._get_payload(messages, metadata, include_rules=True, rules_override=rules_for_prompts)
            response = await self._make_api_request(endpoint='/inspect/chat', payload=payload)
            if response:
                is_safe = response.get('is_safe', True)
                classifications = response.get('classifications', [])
                rules = response.get('rules', [])
                action = response.get('action', '').lower()
                for classification in classifications:
                    if classification and classification != 'NONE_VIOLATION':
                        severity = self._map_classification_to_severity(classification)
                        findings.append(Issue(id=self._generate_id(f'AIDEFENSE_{classification}', file_path), rule_id=f'AIDEFENSE_{classification}', category=self._map_violation_category(classification), severity=severity, title=f'{classification.replace('_', ' ').title()} detected', description=f'AI Defense detected {classification.replace('_', ' ').lower()} in {file_path}', file_path=file_path, remediation='Review and address the security concern flagged by AI Defense', engine='aidefense', metadata={'classification': classification, 'content_type': content_type, 'is_safe': is_safe, 'action': action}))
                for rule in rules:
                    rule_name = rule.get('rule_name', 'Unknown')
                    rule_classification = rule.get('classification', '')
                    if rule_classification in ('NONE_VIOLATION', ''):
                        continue
                    findings.append(Issue(id=self._generate_id(f'AIDEFENSE_RULE_{rule_name}', file_path), rule_id=f'AIDEFENSE_RULE_{rule_name.upper().replace(' ', '_')}', category=self._map_violation_category(rule_classification), severity=self._map_classification_to_severity(rule_classification), title=f'Rule triggered: {rule_name}', description=f"AI Defense rule '{rule_name}' detected {rule_classification.replace('_', ' ').lower()}", file_path=file_path, remediation=f'Address the {rule_name.lower()} issue detected by AI Defense', engine='aidefense', metadata={'rule_name': rule_name, 'rule_id': rule.get('rule_id'), 'classification': rule_classification, 'entity_types': rule.get('entity_types', [])}))
                if action == 'block' and (not is_safe):
                    if not findings:
                        findings.append(Issue(id=self._generate_id('AIDEFENSE_BLOCKED', file_path), rule_id='AIDEFENSE_BLOCKED', category=ThreatClass.PROMPT_INJECTION, severity=RiskLevel.HIGH, title='Content blocked by AI Defense', description=f'AI Defense blocked content in {file_path} as potentially malicious', file_path=file_path, engine='aidefense', metadata={'action': action, 'content_type': content_type, 'is_safe': is_safe}))
        except Exception as e:
            print(f'AI Defense prompt analysis failed for {file_path}: {e}')
        return findings

    async def _analyze_code_content(self, content: str, skill_name: str, file_path: str, language: str) -> list[Finding]:
        if not content or not content.strip():
            return []
        findings = []
        try:
            messages = [{'role': 'user', 'content': f'# Code Analysis for {file_path}\n```{language}\n{content[:15000]}\n```'}]
            metadata = {'source': 'sgscanner', 'skill_name': skill_name, 'file_path': file_path, 'language': language, 'content_type': 'code'}
            rules_for_code = self._get_rules_for_content_type('code')
            payload = self._get_payload(messages, metadata, include_rules=True, rules_override=rules_for_code)
            response = await self._make_api_request(endpoint='/inspect/chat', payload=payload)
            if response:
                is_safe = response.get('is_safe', True)
                classifications = response.get('classifications', [])
                rules = response.get('rules', [])
                action = response.get('action', '').lower()
                for classification in classifications:
                    if classification and classification != 'NONE_VIOLATION':
                        severity = self._map_classification_to_severity(classification)
                        findings.append(Issue(id=self._generate_id(f'AIDEFENSE_CODE_{classification}', file_path), rule_id=f'AIDEFENSE_CODE_{classification}', category=self._map_violation_category(classification), severity=severity, title=f'Code {classification.replace('_', ' ').lower()} detected', description=f'AI Defense detected {classification.replace('_', ' ').lower()} in {language} code', file_path=file_path, remediation='Review and fix the code issue flagged by AI Defense', engine='aidefense', metadata={'classification': classification, 'language': language, 'is_safe': is_safe}))
                for rule in rules:
                    rule_name = rule.get('rule_name', 'Unknown')
                    rule_classification = rule.get('classification', '')
                    if rule_classification in ('NONE_VIOLATION', ''):
                        continue
                    findings.append(Issue(id=self._generate_id(f'AIDEFENSE_CODE_RULE_{rule_name}', file_path), rule_id=f'AIDEFENSE_CODE_RULE_{rule_name.upper().replace(' ', '_')}', category=self._map_violation_category(rule_classification), severity=self._map_classification_to_severity(rule_classification), title=f'Code rule triggered: {rule_name}', description=f"AI Defense rule '{rule_name}' detected issue in {language} code", file_path=file_path, remediation=f'Address the {rule_name.lower()} issue in the code', engine='aidefense', metadata={'rule_name': rule_name, 'classification': rule_classification, 'language': language}))
                if action == 'block' and (not is_safe) and (not findings):
                    findings.append(Issue(id=self._generate_id('AIDEFENSE_CODE_BLOCKED', file_path), rule_id='AIDEFENSE_CODE_BLOCKED', category=ThreatClass.MALWARE, severity=RiskLevel.HIGH, title='Code blocked by AI Defense', description=f'AI Defense blocked {language} code in {file_path} as potentially malicious', file_path=file_path, engine='aidefense', metadata={'action': action, 'language': language, 'is_safe': is_safe}))
        except Exception as e:
            print(f'AI Defense code analysis failed for {file_path}: {e}')
        return findings

    async def _make_api_request(self, endpoint: str, payload: dict[str, Any]) -> dict[str, Any] | None:
        client = self._get_client()
        url = f'{self.api_url}{endpoint}'
        last_exception = None
        original_payload = payload.copy()
        tried_without_rules = False
        for attempt in range(self.max_retries):
            try:
                response = await client.post(url, json=payload)
                if response.status_code == 200:
                    return response.json()
                elif response.status_code == 400:
                    try:
                        error_json = response.json()
                        error_msg = error_json.get('message', '').lower()
                        if ('already has rules configured' in error_msg or 'pre-configured' in error_msg) and (not tried_without_rules):
                            payload_without_rules = original_payload.copy()
                            if 'config' in payload_without_rules:
                                del payload_without_rules['config']
                            print('AI Defense API key has pre-configured rules, retrying without enabled_rules config...')
                            payload = payload_without_rules
                            tried_without_rules = True
                            continue
                    except (ValueError, KeyError, json.JSONDecodeError):
                        pass
                    print(f'AI Defense API error: {response.status_code} - {response.text}')
                    return None
                elif response.status_code == 429:
                    delay = 2 ** attempt * 1.0
                    print(f'AI Defense API rate limited, retrying in {delay}s...')
                    await asyncio.sleep(delay)
                    continue
                elif response.status_code == 401:
                    raise ValueError('Invalid AI Defense API key')
                elif response.status_code == 403:
                    raise ValueError('AI Defense API access denied - check permissions')
                else:
                    print(f'AI Defense API error: {response.status_code} - {response.text}')
                    return None
            except httpx.TimeoutException:
                last_exception = TimeoutError(f'AI Defense API timeout after {self.timeout}s')
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1.0)
                    continue
            except httpx.RequestError as e:
                last_exception = e
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(1.0)
                    continue
        if last_exception:
            print(f'AI Defense API request failed after {self.max_retries} attempts: {last_exception}')
        return None

    def _convert_api_violation_to_finding(self, violation: dict[str, Any], skill_name: str, file_path: str, content_type: str) -> Finding | None:
        try:
            violation_type = violation.get('type', 'unknown').upper()
            severity_str = violation.get('severity', 'medium').upper()
            severity = self._map_violation_severity(severity_str)
            category = self._map_violation_category(violation_type)
            try:
                aitech_mapping = ThreatMapping.get_threat_mapping('llm', violation_type.replace('_', ' '))
            except (ValueError, KeyError):
                aitech_mapping = {}
            return Issue(id=self._generate_id(f'AIDEFENSE_{violation_type}', file_path), rule_id=f'AIDEFENSE_{violation_type}', category=category, severity=severity, title=violation.get('title', f'AI Defense detected: {violation_type.replace('_', ' ').lower()}'), description=violation.get('description', f'Violation detected in {content_type}'), file_path=file_path, line_number=violation.get('line'), snippet=violation.get('evidence', violation.get('snippet', '')), remediation=violation.get('remediation', 'Review and address the security concern'), engine='aidefense', metadata={'violation_type': violation_type, 'confidence': violation.get('confidence'), 'aitech': aitech_mapping.get('aitech'), 'aitech_name': aitech_mapping.get('aitech_name')})
        except Exception as e:
            print(f'Failed to convert AI Defense violation: {e}')
            return None

    def _map_violation_severity(self, severity_str: str) -> Severity:
        severity_map = {'CRITICAL': RiskLevel.CRITICAL, 'HIGH': RiskLevel.HIGH, 'MEDIUM': RiskLevel.MEDIUM, 'LOW': RiskLevel.LOW, 'INFO': RiskLevel.INFO, 'INFORMATIONAL': RiskLevel.INFO, 'NONE_SEVERITY': RiskLevel.MEDIUM}
        return severity_map.get(severity_str.upper(), RiskLevel.MEDIUM)

    def _map_classification_to_severity(self, classification: str) -> Severity:
        classification = classification.upper()
        severity_map = {'SECURITY_VIOLATION': RiskLevel.HIGH, 'PRIVACY_VIOLATION': RiskLevel.HIGH, 'SAFETY_VIOLATION': RiskLevel.MEDIUM, 'RELEVANCE_VIOLATION': RiskLevel.LOW, 'NONE_VIOLATION': RiskLevel.INFO}
        return severity_map.get(classification, RiskLevel.MEDIUM)

    def _map_violation_category(self, violation_type: str) -> ThreatCategory:
        violation_type = violation_type.upper()
        mapping = {'SECURITY_VIOLATION': ThreatClass.PROMPT_INJECTION, 'PRIVACY_VIOLATION': ThreatClass.DATA_EXFILTRATION, 'SAFETY_VIOLATION': ThreatClass.SOCIAL_ENGINEERING, 'RELEVANCE_VIOLATION': ThreatClass.POLICY_VIOLATION, 'PROMPT_INJECTION': ThreatClass.PROMPT_INJECTION, 'JAILBREAK': ThreatClass.PROMPT_INJECTION, 'TOOL_POISONING': ThreatClass.PROMPT_INJECTION, 'DATA_EXFILTRATION': ThreatClass.DATA_EXFILTRATION, 'DATA_LEAK': ThreatClass.DATA_EXFILTRATION, 'COMMAND_INJECTION': ThreatClass.COMMAND_INJECTION, 'CODE_INJECTION': ThreatClass.COMMAND_INJECTION, 'CREDENTIAL_THEFT': ThreatClass.HARDCODED_SECRETS, 'MALWARE': ThreatClass.MALWARE, 'SOCIAL_ENGINEERING': ThreatClass.SOCIAL_ENGINEERING, 'OBFUSCATION': ThreatClass.OBFUSCATION}
        return mapping.get(violation_type, ThreatClass.POLICY_VIOLATION)

    def _convert_api_threat_to_finding(self, threat: dict[str, Any], skill_name: str, file_path: str, content_type: str) -> Finding | None:
        return self._convert_api_violation_to_finding(threat, skill_name, file_path, content_type)

    def _convert_api_vulnerability_to_finding(self, vuln: dict[str, Any], skill_name: str, file_path: str, language: str) -> Finding | None:
        try:
            vuln_type = vuln.get('type', 'unknown').upper()
            severity_str = vuln.get('severity', 'MEDIUM').upper()
            severity_map = {'CRITICAL': RiskLevel.CRITICAL, 'HIGH': RiskLevel.HIGH, 'MEDIUM': RiskLevel.MEDIUM, 'LOW': RiskLevel.LOW, 'INFO': RiskLevel.INFO}
            severity = severity_map.get(severity_str, RiskLevel.MEDIUM)
            category = self._map_vuln_type_to_category(vuln_type)
            return Issue(id=self._generate_id(f'AIDEFENSE_VULN_{vuln_type}', f'{file_path}_{vuln.get('line', 0)}'), rule_id=f'AIDEFENSE_VULN_{vuln_type}', category=category, severity=severity, title=vuln.get('title', f'Vulnerability: {vuln_type}'), description=vuln.get('description', f'Security vulnerability in {language} code'), file_path=file_path, line_number=vuln.get('line'), snippet=vuln.get('snippet', ''), remediation=vuln.get('remediation', 'Fix the security vulnerability'), engine='aidefense', metadata={'vuln_type': vuln_type, 'cwe': vuln.get('cwe'), 'language': language})
        except Exception as e:
            print(f'Failed to convert AI Defense vulnerability: {e}')
            return None

    def _map_threat_type_to_category(self, threat_type: str) -> ThreatCategory:
        mapping = {'PROMPT_INJECTION': ThreatClass.PROMPT_INJECTION, 'PROMPT INJECTION': ThreatClass.PROMPT_INJECTION, 'JAILBREAK': ThreatClass.PROMPT_INJECTION, 'TOOL_POISONING': ThreatClass.PROMPT_INJECTION, 'TOOL POISONING': ThreatClass.PROMPT_INJECTION, 'DATA_EXFILTRATION': ThreatClass.DATA_EXFILTRATION, 'DATA EXFILTRATION': ThreatClass.DATA_EXFILTRATION, 'COMMAND_INJECTION': ThreatClass.COMMAND_INJECTION, 'COMMAND INJECTION': ThreatClass.COMMAND_INJECTION, 'CREDENTIAL_THEFT': ThreatClass.HARDCODED_SECRETS, 'MALWARE': ThreatClass.MALWARE, 'SOCIAL_ENGINEERING': ThreatClass.SOCIAL_ENGINEERING, 'OBFUSCATION': ThreatClass.OBFUSCATION}
        return mapping.get(threat_type.upper(), ThreatClass.POLICY_VIOLATION)

    def _map_vuln_type_to_category(self, vuln_type: str) -> ThreatCategory:
        mapping = {'INJECTION': ThreatClass.COMMAND_INJECTION, 'SQL_INJECTION': ThreatClass.COMMAND_INJECTION, 'COMMAND_INJECTION': ThreatClass.COMMAND_INJECTION, 'XSS': ThreatClass.COMMAND_INJECTION, 'PATH_TRAVERSAL': ThreatClass.DATA_EXFILTRATION, 'SENSITIVE_DATA': ThreatClass.HARDCODED_SECRETS, 'HARDCODED_SECRET': ThreatClass.HARDCODED_SECRETS, 'INSECURE_FUNCTION': ThreatClass.COMMAND_INJECTION}
        return mapping.get(vuln_type.upper(), ThreatClass.POLICY_VIOLATION)

    def _map_pattern_to_category(self, pattern_type: str | None) -> ThreatCategory:
        if not pattern_type:
            return ThreatClass.POLICY_VIOLATION
        pattern_type = pattern_type.upper()
        mapping = {'EXFILTRATION': ThreatClass.DATA_EXFILTRATION, 'BACKDOOR': ThreatClass.MALWARE, 'CREDENTIAL_THEFT': ThreatClass.HARDCODED_SECRETS, 'OBFUSCATION': ThreatClass.OBFUSCATION, 'INJECTION': ThreatClass.COMMAND_INJECTION}
        return mapping.get(pattern_type, ThreatClass.MALWARE)

    def _map_confidence_to_severity(self, confidence: float) -> Severity:
        if confidence >= 0.9:
            return RiskLevel.CRITICAL
        elif confidence >= 0.7:
            return RiskLevel.HIGH
        elif confidence >= 0.5:
            return RiskLevel.MEDIUM
        elif confidence >= 0.3:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO

    def _generate_id(self, prefix: str, context: str) -> str:
        combined = f'{prefix}:{context}'
        hash_obj = hashlib.sha256(combined.encode())
        return f'{prefix}_{hash_obj.hexdigest()[:10]}'
