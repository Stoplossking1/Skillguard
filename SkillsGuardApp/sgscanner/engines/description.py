import re
from ..models import Finding, Severity, Skill, ThreatCategory
from .base import ScanEngine
from .registry import register_engine

@register_engine(name='description_detector', description='Detects overly generic skill descriptions', aliases=('trigger_analyzer',), metadata={'expose_cli': True, 'order': 60})
class DescriptionEngine(ScanEngine):
    engine_id = 'description_detector'
    GENERIC_PATTERNS = ['^help\\s*(me|you|with\\s+anything)?\\s*$', '^(a|an|the)?\\s*assistant\\s*$', '^(a|an|the)?\\s*helper\\s*$', '^(I |this )?(can |will )?do\\s+(anything|everything)\\s*(for you)?\\.?$', '^general\\s+purpose\\s+(assistant|tool|skill)\\s*$', '^universal\\s+(assistant|tool|skill)\\s*$', '^default\\s+(assistant|tool|skill)\\s*$', '^use\\s+(this|me)\\s+for\\s+(everything|anything)\\s*$']
    GENERIC_WORDS = {'help', 'helper', 'helps', 'helping', 'assist', 'assistant', 'assists', 'assisting', 'do', 'does', 'doing', 'thing', 'things', 'stuff', 'general', 'generic', 'universal', 'any', 'anything', 'everything', 'something', 'all', 'various', 'multiple', 'many', 'useful', 'handy', 'convenient', 'tool', 'utility'}
    SPECIFIC_INDICATORS = {'convert', 'parse', 'format', 'validate', 'generate', 'analyze', 'create', 'build', 'compile', 'transform', 'extract', 'process', 'calculate', 'compute', 'summarize', 'translate', 'encode', 'decode', 'json', 'yaml', 'xml', 'csv', 'markdown', 'html', 'css', 'sql', 'python', 'javascript', 'typescript', 'rust', 'go', 'java', 'api', 'database', 'file', 'image', 'pdf', 'document', 'git', 'docker', 'kubernetes', 'aws', 'azure', 'gcp', 'code', 'test', 'documentation', 'report', 'log', 'config', 'user', 'data', 'request', 'response', 'error', 'exception'}

    def __init__(self):
        super().__init__()
        self._compiled_patterns = [re.compile(p, re.IGNORECASE) for p in self.GENERIC_PATTERNS]

    def run(self, skill: Skill) -> list[Finding]:
        findings = []
        findings.extend(self._check_generic_patterns(skill))
        findings.extend(self._check_description_specificity(skill))
        findings.extend(self._check_keyword_baiting(skill))
        return findings

    def _check_generic_patterns(self, skill: Skill) -> list[Finding]:
        findings = []
        description = skill.description.strip()
        for pattern in self._compiled_patterns:
            if pattern.match(description):
                findings.append(Issue(id=f'TRIGGER_GENERIC_{hash(description) & 4294967295:08x}', rule_id='TRIGGER_OVERLY_GENERIC', category=ThreatClass.SOCIAL_ENGINEERING, severity=RiskLevel.MEDIUM, title='Skill description is overly generic', description=f"Description '{description[:50]}...' matches a generic pattern. This may cause the skill to trigger for unrelated user requests, potentially hijacking conversations.", file_path='SKILL.md', remediation='Make the description more specific by describing exactly what the skill does, what inputs it accepts, and what outputs it produces.', engine='description'))
                break
        return findings

    def _check_description_specificity(self, skill: Skill) -> list[Finding]:
        findings = []
        description = skill.description.strip()
        words = re.findall('\\b[a-zA-Z]+\\b', description.lower())
        if len(words) < 5:
            findings.append(Issue(id=f'TRIGGER_SHORT_{hash(description) & 4294967295:08x}', rule_id='TRIGGER_DESCRIPTION_TOO_SHORT', category=ThreatClass.SOCIAL_ENGINEERING, severity=RiskLevel.LOW, title='Skill description is too short', description=f'Description has only {len(words)} words. Short descriptions may not provide enough context for the agent to determine when this skill should be used.', file_path='SKILL.md', remediation="Expand the description to at least 10-20 words explaining the skill's purpose, capabilities, and appropriate use cases.", engine='description'))
            return findings
        generic_count = sum((1 for w in words if w in self.GENERIC_WORDS))
        specific_count = sum((1 for w in words if w in self.SPECIFIC_INDICATORS))
        generic_ratio = generic_count / len(words) if words else 0
        if generic_ratio > 0.4 and specific_count < 2:
            findings.append(Issue(id=f'TRIGGER_VAGUE_{hash(description) & 4294967295:08x}', rule_id='TRIGGER_VAGUE_DESCRIPTION', category=ThreatClass.SOCIAL_ENGINEERING, severity=RiskLevel.LOW, title='Skill description lacks specificity', description=f'Description contains {generic_count} generic words ({generic_ratio:.0%}) and only {specific_count} specific indicators. This may cause imprecise skill matching.', file_path='SKILL.md', remediation='Replace generic terms with specific technical terms that describe exactly what file types, technologies, or operations this skill handles.', engine='description'))
        return findings

    def _check_keyword_baiting(self, skill: Skill) -> list[Finding]:
        findings = []
        description = skill.description.strip()
        keyword_lists = re.findall('[a-zA-Z]+(?:\\s*,\\s*[a-zA-Z]+){7,}', description)
        if keyword_lists:
            context_before = description[:description.find(keyword_lists[0])].lower()
            if 'example' in context_before or 'such as' in context_before or 'including' in context_before:
                return findings
            words = [w.strip().lower() for w in keyword_lists[0].split(',')]
            unique_ratio = len(set(words)) / len(words) if words else 1
            if unique_ratio < 0.7 or description.strip().startswith(keyword_lists[0][:20]):
                findings.append(Issue(id=f'TRIGGER_KEYWORD_BAIT_{hash(description) & 4294967295:08x}', rule_id='TRIGGER_KEYWORD_BAITING', category=ThreatClass.SOCIAL_ENGINEERING, severity=RiskLevel.MEDIUM, title='Skill description may contain keyword baiting', description='Description contains suspiciously long keyword list that may be an attempt to trigger the skill for many unrelated queries.', file_path='SKILL.md', remediation="Replace keyword lists with natural language sentences that describe the skill's actual capabilities.", engine='description'))
        return findings

    def get_specificity_score(self, description: str) -> float:
        words = re.findall('\\b[a-zA-Z]+\\b', description.lower())
        if not words:
            return 0.0
        generic_count = sum((1 for w in words if w in self.GENERIC_WORDS))
        specific_count = sum((1 for w in words if w in self.SPECIFIC_INDICATORS))
        word_score = min(len(words) / 20, 1.0)
        generic_penalty = generic_count / len(words) if words else 0
        specific_bonus = min(specific_count / 5, 0.5)
        score = word_score - generic_penalty + specific_bonus
        return max(0.0, min(1.0, score))
