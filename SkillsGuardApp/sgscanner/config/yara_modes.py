from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

class YaraMode(Enum):
    STRICT = 'strict'
    BALANCED = 'balanced'
    PERMISSIVE = 'permissive'
    CUSTOM = 'custom'

@dataclass
class UnicodeStegConfig:
    zerowidth_threshold_with_decode: int = 50
    zerowidth_threshold_alone: int = 200
    detect_rtl_override: bool = True
    detect_ltl_override: bool = True
    detect_line_separators: bool = True
    detect_unicode_tags: bool = True
    detect_variation_selectors: bool = True

@dataclass
class CredentialHarvestingConfig:
    filter_placeholder_patterns: bool = True
    detect_ai_api_keys: bool = True
    detect_aws_keys: bool = True
    detect_ssh_keys: bool = True
    detect_env_exfiltration: bool = True

@dataclass
class ToolChainingConfig:
    filter_api_documentation: bool = True
    filter_generic_http_verbs: bool = True
    filter_email_field_mentions: bool = True
    detect_read_send: bool = True
    detect_collect_exfil: bool = True
    detect_env_network: bool = True

@dataclass
class YaraModeConfig:
    mode: YaraMode = YaraMode.BALANCED
    description: str = ''
    unicode_steg: UnicodeStegConfig = field(default_factory=UnicodeStegConfig)
    credential_harvesting: CredentialHarvestingConfig = field(default_factory=CredentialHarvestingConfig)
    tool_chaining: ToolChainingConfig = field(default_factory=ToolChainingConfig)
    enabled_rules: set[str] = field(default_factory=set)
    disabled_rules: set[str] = field(default_factory=set)

    @classmethod
    def strict(cls) -> 'YaraModeConfig':
        return cls(mode=YaraMode.STRICT, description='Maximum security - flags more potential threats', unicode_steg=UnicodeStegConfig(zerowidth_threshold_with_decode=20, zerowidth_threshold_alone=100), credential_harvesting=CredentialHarvestingConfig(filter_placeholder_patterns=False), tool_chaining=ToolChainingConfig(filter_api_documentation=False, filter_generic_http_verbs=False))

    @classmethod
    def balanced(cls) -> 'YaraModeConfig':
        return cls(mode=YaraMode.BALANCED, description='Balanced detection - default mode', unicode_steg=UnicodeStegConfig(zerowidth_threshold_with_decode=50, zerowidth_threshold_alone=200), credential_harvesting=CredentialHarvestingConfig(filter_placeholder_patterns=True), tool_chaining=ToolChainingConfig(filter_api_documentation=True, filter_generic_http_verbs=True, filter_email_field_mentions=True))

    @classmethod
    def permissive(cls) -> 'YaraModeConfig':
        return cls(mode=YaraMode.PERMISSIVE, description='Minimal false positives - may miss some threats', unicode_steg=UnicodeStegConfig(zerowidth_threshold_with_decode=100, zerowidth_threshold_alone=500, detect_line_separators=False), credential_harvesting=CredentialHarvestingConfig(filter_placeholder_patterns=True), tool_chaining=ToolChainingConfig(filter_api_documentation=True, filter_generic_http_verbs=True, filter_email_field_mentions=True), disabled_rules={'capability_inflation_generic', 'indirect_prompt_injection_generic'})

    @classmethod
    def custom(cls, unicode_steg: UnicodeStegConfig | None=None, credential_harvesting: CredentialHarvestingConfig | None=None, tool_chaining: ToolChainingConfig | None=None, enabled_rules: set[str] | None=None, disabled_rules: set[str] | None=None) -> 'YaraModeConfig':
        return cls(mode=YaraMode.CUSTOM, description='Custom user-defined configuration', unicode_steg=unicode_steg or UnicodeStegConfig(), credential_harvesting=credential_harvesting or CredentialHarvestingConfig(), tool_chaining=tool_chaining or ToolChainingConfig(), enabled_rules=enabled_rules or set(), disabled_rules=disabled_rules or set())

    @classmethod
    def from_mode_name(cls, mode_name: str) -> 'YaraModeConfig':
        mode_map = {'strict': cls.strict, 'balanced': cls.balanced, 'permissive': cls.permissive}
        if mode_name.lower() in mode_map:
            return mode_map[mode_name.lower()]()
        raise ValueError(f'Unknown mode: {mode_name}. Use: strict, balanced, permissive, or custom')

    def is_rule_enabled(self, rule_name: str) -> bool:
        if self.enabled_rules and rule_name not in self.enabled_rules:
            return False
        if rule_name in self.disabled_rules:
            return False
        return True

    def serialize(self) -> dict:
        return {'mode': self.mode.value, 'description': self.description, 'unicode_steg': {'zerowidth_threshold_with_decode': self.unicode_steg.zerowidth_threshold_with_decode, 'zerowidth_threshold_alone': self.unicode_steg.zerowidth_threshold_alone, 'detect_rtl_override': self.unicode_steg.detect_rtl_override, 'detect_ltl_override': self.unicode_steg.detect_ltl_override, 'detect_line_separators': self.unicode_steg.detect_line_separators, 'detect_unicode_tags': self.unicode_steg.detect_unicode_tags, 'detect_variation_selectors': self.unicode_steg.detect_variation_selectors}, 'credential_harvesting': {'filter_placeholder_patterns': self.credential_harvesting.filter_placeholder_patterns, 'detect_ai_api_keys': self.credential_harvesting.detect_ai_api_keys, 'detect_aws_keys': self.credential_harvesting.detect_aws_keys, 'detect_ssh_keys': self.credential_harvesting.detect_ssh_keys, 'detect_env_exfiltration': self.credential_harvesting.detect_env_exfiltration}, 'tool_chaining': {'filter_api_documentation': self.tool_chaining.filter_api_documentation, 'filter_generic_http_verbs': self.tool_chaining.filter_generic_http_verbs, 'filter_email_field_mentions': self.tool_chaining.filter_email_field_mentions, 'detect_read_send': self.tool_chaining.detect_read_send, 'detect_collect_exfil': self.tool_chaining.detect_collect_exfil, 'detect_env_network': self.tool_chaining.detect_env_network}, 'enabled_rules': list(self.enabled_rules), 'disabled_rules': list(self.disabled_rules)}
DEFAULT_YARA_MODE = YaraModeConfig.balanced()
MODE_DESCRIPTIONS = {'strict': '\nSTRICT Mode - Maximum Security\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n• Lower detection thresholds\n• Minimal post-processing filters\n• Flags more potential threats\n• Higher false positive rate acceptable\n\nUse for: Untrusted skills, security audits, compliance\n', 'balanced': '\nBALANCED Mode - Default\n━━━━━━━━━━━━━━━━━━━━━━━\n• Moderate detection thresholds\n• Context-aware post-processing\n• Good tradeoff between FP and TP\n• Suitable for most use cases\n\nUse for: Regular scanning, CI/CD, development\n', 'permissive': '\nPERMISSIVE Mode - Minimal False Positives\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n• Higher detection thresholds\n• Aggressive filtering\n• Focus on critical threats only\n• May miss some edge-case threats\n\nUse for: Trusted skills, high FP disruption\n'}
