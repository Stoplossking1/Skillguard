import re
from pathlib import Path
from typing import Any
import yaml
from ..models import Severity, ThreatCategory

class SecurityRule:

    def __init__(self, rule_data: dict[str, Any]):
        self.id = rule_data['id']
        self.category = ThreatCategory(rule_data['category'])
        self.severity = Severity(rule_data['severity'])
        self.patterns = rule_data['patterns']
        self.exclude_patterns = rule_data.get('exclude_patterns', [])
        self.file_types = rule_data.get('file_types', [])
        self.description = rule_data['description']
        self.remediation = rule_data.get('remediation', '')
        self.compiled_patterns = []
        for pattern in self.patterns:
            try:
                self.compiled_patterns.append(re.compile(pattern))
            except re.error as e:
                print(f"Warning: Failed to compile pattern '{pattern}' for rule {self.id}: {e}")
        self.compiled_exclude_patterns = []
        for pattern in self.exclude_patterns:
            try:
                self.compiled_exclude_patterns.append(re.compile(pattern))
            except re.error as e:
                print(f"Warning: Failed to compile exclude pattern '{pattern}' for rule {self.id}: {e}")

    def matches_file_type(self, file_type: str) -> bool:
        if not self.file_types:
            return True
        return file_type in self.file_types

    def scan_content(self, content: str, file_path: str | None=None) -> list[dict[str, Any]]:
        matches = []
        lines = content.split('\n')
        for line_num, line in enumerate(lines, start=1):
            excluded = False
            for exclude_pattern in self.compiled_exclude_patterns:
                if exclude_pattern.search(line):
                    excluded = True
                    break
            if excluded:
                continue
            for pattern in self.compiled_patterns:
                match = pattern.search(line)
                if match:
                    matches.append({'line_number': line_num, 'line_content': line.strip(), 'matched_pattern': pattern.pattern, 'matched_text': match.group(0), 'file_path': file_path})
        return matches

class RuleLoader:

    def __init__(self, rules_file: Path | None=None):
        if rules_file is None:
            from ...data import DATA_DIR
            rules_file = DATA_DIR / 'rules' / 'signatures.yaml'
        self.rules_file = rules_file
        self.rules: list[SecurityRule] = []
        self.rules_by_id: dict[str, SecurityRule] = {}
        self.rules_by_category: dict[ThreatCategory, list[SecurityRule]] = {}

    def load_rules(self) -> list[SecurityRule]:
        try:
            with open(self.rules_file, encoding='utf-8') as f:
                rules_data = yaml.safe_load(f)
        except Exception as e:
            raise RuntimeError(f'Failed to load rules from {self.rules_file}: {e}')
        self.rules = []
        self.rules_by_id = {}
        self.rules_by_category = {}
        for rule_data in rules_data:
            try:
                rule = SecurityRule(rule_data)
                self.rules.append(rule)
                self.rules_by_id[rule.id] = rule
                if rule.category not in self.rules_by_category:
                    self.rules_by_category[rule.category] = []
                self.rules_by_category[rule.category].append(rule)
            except Exception as e:
                print(f'Warning: Failed to load rule {rule_data.get('id', 'unknown')}: {e}')
        return self.rules

    def get_rule(self, rule_id: str) -> SecurityRule | None:
        return self.rules_by_id.get(rule_id)

    def get_rules_for_file_type(self, file_type: str) -> list[SecurityRule]:
        return [rule for rule in self.rules if rule.matches_file_type(file_type)]

    def get_rules_for_category(self, category: ThreatCategory) -> list[SecurityRule]:
        return self.rules_by_category.get(category, [])
