import re
from ..models import Finding, Severity, Skill, ThreatCategory
from .base import ScanEngine
from .registry import register_engine

@register_engine(name='cross_skill_detector', description='Cross-skill coordination analysis for multi-skill attacks', aliases=('cross_sgscanner',), metadata={'expose_api': False, 'expose_cli': False, 'order': 90})
class CrossSkillEngine(ScanEngine):
    engine_id = 'cross_skill_detector'

    def __init__(self):
        super().__init__()
        self._skills: list[Skill] = []

    def run(self, skill: Skill) -> list[Finding]:
        return []

    def analyze_skill_set(self, skills: list[Skill]) -> list[Finding]:
        if len(skills) < 2:
            return []
        self._skills = skills
        findings = []
        findings.extend(self._detect_data_relay_pattern())
        findings.extend(self._detect_shared_external_urls())
        findings.extend(self._detect_complementary_triggers())
        findings.extend(self._detect_shared_suspicious_patterns())
        return findings

    def _detect_data_relay_pattern(self) -> list[Finding]:
        findings = []
        collectors: list[tuple[Skill, set[str]]] = []
        exfiltrators: list[tuple[Skill, set[str]]] = []
        COLLECTION_PATTERNS = ['credential', 'password', 'secret', 'api[_-]?key', 'token', '\\.env', 'config', 'ssh', 'private', '\\.pem', '~/.ssh', '/etc/passwd', '/etc/shadow', 'keychain', 'wallet', 'cookie']
        EXFIL_PATTERNS = ['requests\\.(post|put)', 'urllib\\.request', 'httpx\\.(post|put)', 'socket\\.send', 'aiohttp.*post', 'webhook', 'discord\\.com/api/webhooks', 'ngrok', 'localhost\\.run']
        for skill in self._skills:
            skill_content = self._get_skill_content(skill)
            collection_hits = set()
            for pattern in COLLECTION_PATTERNS:
                if re.search(pattern, skill_content, re.IGNORECASE):
                    collection_hits.add(pattern)
            if collection_hits:
                collectors.append((skill, collection_hits))
            exfil_hits = set()
            for pattern in EXFIL_PATTERNS:
                if re.search(pattern, skill_content, re.IGNORECASE):
                    exfil_hits.add(pattern)
            if exfil_hits:
                exfiltrators.append((skill, exfil_hits))
        if collectors and exfiltrators:
            collector_names = [s.name for s, _ in collectors]
            exfil_names = [s.name for s, _ in exfiltrators]
            if set(collector_names) != set(exfil_names):
                findings.append(Issue(id=f'CROSS_SKILL_RELAY_{hash(tuple(collector_names + exfil_names)) & 4294967295:08x}', rule_id='CROSS_SKILL_DATA_RELAY', category=ThreatClass.DATA_EXFILTRATION, severity=RiskLevel.HIGH, title='Potential data relay attack pattern detected', description=f'Skills appear to form a data relay chain. Collectors ({', '.join(collector_names)}) access sensitive data while exfiltrators ({', '.join(exfil_names)}) send data to external destinations. This pattern may indicate a coordinated attack.', file_path='(cross-skill analysis)', remediation='Review these skills together to ensure they are not collaborating to exfiltrate sensitive data. Consider disabling one or both skills.', engine='cross_skill', metadata={'collectors': collector_names, 'exfiltrators': exfil_names}))
        return findings

    def _detect_shared_external_urls(self) -> list[Finding]:
        findings = []
        skill_urls: dict[str, list[str]] = {}
        for skill in self._skills:
            content = self._get_skill_content(skill)
            urls = self._extract_urls(content)
            for url in urls:
                domain = self._extract_domain(url)
                if domain and (not self._is_common_domain(domain)):
                    if domain not in skill_urls:
                        skill_urls[domain] = []
                    if skill.name not in skill_urls[domain]:
                        skill_urls[domain].append(skill.name)
        for domain, skill_names in skill_urls.items():
            if len(skill_names) >= 2:
                findings.append(Issue(id=f'CROSS_SKILL_URL_{hash(domain) & 4294967295:08x}', rule_id='CROSS_SKILL_SHARED_URL', category=ThreatClass.DATA_EXFILTRATION, severity=RiskLevel.MEDIUM, title='Multiple skills reference the same external domain', description=f"Domain '{domain}' is referenced by {len(skill_names)} skills: {', '.join(skill_names)}. Multiple skills pointing to the same external resource may indicate coordinated C2 or exfiltration.", file_path='(cross-skill analysis)', remediation='Review why multiple skills reference this domain and ensure it is a legitimate, trusted resource.', engine='cross_skill', metadata={'domain': domain, 'skills': skill_names}))
        return findings

    def _detect_complementary_triggers(self) -> list[Finding]:
        findings = []
        COLLECTION_KEYWORDS = {'gather', 'collect', 'read', 'scan', 'find', 'search', 'extract', 'parse', 'load', 'get', 'fetch', 'retrieve'}
        SENDING_KEYWORDS = {'send', 'upload', 'post', 'submit', 'transfer', 'sync', 'backup', 'export', 'share', 'publish', 'notify'}
        collectors = []
        senders = []
        for skill in self._skills:
            desc_lower = skill.description.lower()
            desc_words = set(re.findall('\\b[a-z]+\\b', desc_lower))
            if desc_words & COLLECTION_KEYWORDS:
                collectors.append(skill)
            if desc_words & SENDING_KEYWORDS:
                senders.append(skill)
        if collectors and senders:
            for collector in collectors:
                for sender in senders:
                    if collector.name != sender.name:
                        coll_words = set(re.findall('\\b[a-z]+\\b', collector.description.lower()))
                        send_words = set(re.findall('\\b[a-z]+\\b', sender.description.lower()))
                        EXCLUDE_WORDS = COLLECTION_KEYWORDS | SENDING_KEYWORDS | {'the', 'a', 'an', 'is', 'are', 'to', 'for', 'and', 'or', 'in', 'with'}
                        shared_context = (coll_words & send_words) - EXCLUDE_WORDS
                        if len(shared_context) >= 2:
                            findings.append(Issue(id=f'CROSS_SKILL_COMPLEMENTARY_{hash(collector.name + sender.name) & 4294967295:08x}', rule_id='CROSS_SKILL_COMPLEMENTARY_TRIGGERS', category=ThreatClass.SOCIAL_ENGINEERING, severity=RiskLevel.LOW, title='Skills have complementary descriptions', description=f"Skill '{collector.name}' (collector) and '{sender.name}' (sender) have complementary descriptions with shared context: {', '.join(shared_context)}. This may be intentional design or could indicate coordinated behavior.", file_path='(cross-skill analysis)', remediation='Review these skills to ensure they are not designed to work together maliciously', engine='cross_skill', metadata={'collector': collector.name, 'sender': sender.name, 'shared_context': list(shared_context)}))
        return findings

    def _detect_shared_suspicious_patterns(self) -> list[Finding]:
        findings = []
        SUSPICIOUS_PATTERNS = [('base64\\.b64decode', 'base64_decode'), ('exec\\s*\\(', 'exec_call'), ('eval\\s*\\(', 'eval_call'), ('\\\\x[0-9a-fA-F]{2}', 'hex_escape'), ('chr\\([0-9]+\\)', 'chr_call'), ('getattr\\s*\\([^)]+,\\s*[\'\\"][^\'\\"]+[\'\\"]\\s*\\)', 'dynamic_getattr')]
        skill_patterns: dict[str, list[str]] = {}
        for skill in self._skills:
            content = self._get_skill_content(skill)
            for pattern, name in SUSPICIOUS_PATTERNS:
                if re.search(pattern, content):
                    if name not in skill_patterns:
                        skill_patterns[name] = []
                    if skill.name not in skill_patterns[name]:
                        skill_patterns[name].append(skill.name)
        for pattern_name, skill_names in skill_patterns.items():
            if len(skill_names) >= 2:
                findings.append(Issue(id=f'CROSS_SKILL_PATTERN_{hash(pattern_name + str(skill_names)) & 4294967295:08x}', rule_id='CROSS_SKILL_SHARED_PATTERN', category=ThreatClass.OBFUSCATION, severity=RiskLevel.MEDIUM, title='Multiple skills share suspicious code pattern', description=f"Pattern '{pattern_name}' found in {len(skill_names)} skills: {', '.join(skill_names)}. Shared suspicious patterns may indicate skills from the same malicious source.", file_path='(cross-skill analysis)', remediation='Review these skills carefully - shared obfuscation or encoding patterns often indicate malicious intent.', engine='cross_skill', metadata={'pattern': pattern_name, 'skills': skill_names}))
        return findings

    def _get_skill_content(self, skill: Skill) -> str:
        content_parts = [skill.description, skill.instruction_body]
        for skill_file in skill.files:
            try:
                file_content = skill_file.read_content()
                if file_content:
                    content_parts.append(file_content)
            except Exception:
                pass
        return '\n'.join(content_parts)

    def _extract_urls(self, content: str) -> list[str]:
        url_pattern = 'https?://[^\\s<>"\\\')\\]]+[^\\s<>"\\\')\\]\\.,]'
        return re.findall(url_pattern, content)

    def _extract_domain(self, url: str) -> str:
        match = re.match('https?://([^/]+)', url)
        if match:
            return match.group(1).lower()
        return ''

    def _is_common_domain(self, domain: str) -> bool:
        COMMON_DOMAINS = {'github.com', 'githubusercontent.com', 'gitlab.com', 'pypi.org', 'npmjs.com', 'python.org', 'crates.io', 'rubygems.org', 'packagist.org', 'anthropic.com', 'openai.com', 'claude.com', 'google.com', 'googleapis.com', 'microsoft.com', 'azure.com', 'amazon.com', 'amazonaws.com', 'aws.amazon.com', 'stackoverflow.com', 'docs.python.org', 'developer.mozilla.org', 'mdn.io', 'apache.org', 'www.apache.org', 'opensource.org', 'creativecommons.org', 'w3.org', 'www.w3.org', 'ietf.org', 'schemas.openxmlformats.org', 'schemas.microsoft.com', 'purl.org', 'dublincore.org', 'xmlsoft.org', 'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'ajax.googleapis.com'}
        for common in COMMON_DOMAINS:
            if domain == common or domain.endswith('.' + common):
                return True
        return False
