import pytest
from sgscanner.config.yara_modes import CredentialHarvestingConfig, ToolChainingConfig, UnicodeStegConfig, YaraMode, YaraModeConfig
from sgscanner.engines.pattern import PatternEngine

class TestYaraModeConfig:

    def test_balanced_mode_is_default(self):
        config = YaraModeConfig()
        assert config.mode == YaraMode.BALANCED

    def test_strict_mode_has_lower_thresholds(self):
        strict = YaraModeConfig.strict()
        balanced = YaraModeConfig.balanced()
        assert strict.unicode_steg.zerowidth_threshold_with_decode < balanced.unicode_steg.zerowidth_threshold_with_decode
        assert strict.unicode_steg.zerowidth_threshold_alone < balanced.unicode_steg.zerowidth_threshold_alone
        assert not strict.credential_harvesting.filter_placeholder_patterns

    def test_permissive_mode_has_higher_thresholds(self):
        permissive = YaraModeConfig.permissive()
        balanced = YaraModeConfig.balanced()
        assert permissive.unicode_steg.zerowidth_threshold_with_decode > balanced.unicode_steg.zerowidth_threshold_with_decode
        assert permissive.unicode_steg.zerowidth_threshold_alone > balanced.unicode_steg.zerowidth_threshold_alone

    def test_permissive_mode_disables_rules(self):
        permissive = YaraModeConfig.permissive()
        assert len(permissive.disabled_rules) > 0
        assert 'capability_inflation_generic' in permissive.disabled_rules

    def test_from_mode_name_creates_correct_mode(self):
        strict = YaraModeConfig.from_mode_name('strict')
        assert strict.mode == YaraMode.STRICT
        balanced = YaraModeConfig.from_mode_name('balanced')
        assert balanced.mode == YaraMode.BALANCED
        permissive = YaraModeConfig.from_mode_name('permissive')
        assert permissive.mode == YaraMode.PERMISSIVE

    def test_from_mode_name_case_insensitive(self):
        strict1 = YaraModeConfig.from_mode_name('STRICT')
        strict2 = YaraModeConfig.from_mode_name('Strict')
        strict3 = YaraModeConfig.from_mode_name('strict')
        assert strict1.mode == strict2.mode == strict3.mode == YaraMode.STRICT

    def test_from_mode_name_invalid_raises(self):
        with pytest.raises(ValueError, match='Unknown mode'):
            YaraModeConfig.from_mode_name('invalid_mode')

    def test_is_rule_enabled_with_no_config(self):
        config = YaraModeConfig()
        assert config.is_rule_enabled('credential_harvesting_generic')
        assert config.is_rule_enabled('tool_chaining_abuse_generic')
        assert config.is_rule_enabled('any_rule_name')

    def test_is_rule_enabled_with_disabled_rules(self):
        config = YaraModeConfig(disabled_rules={'test_rule'})
        assert not config.is_rule_enabled('test_rule')
        assert config.is_rule_enabled('other_rule')

    def test_is_rule_enabled_with_enabled_rules(self):
        config = YaraModeConfig(enabled_rules={'allowed_rule'})
        assert config.is_rule_enabled('allowed_rule')
        assert not config.is_rule_enabled('other_rule')

    def test_custom_mode_creation(self):
        custom_unicode = UnicodeStegConfig(zerowidth_threshold_alone=1000, detect_line_separators=False)
        config = YaraModeConfig.custom(unicode_steg=custom_unicode, disabled_rules={'noisy_rule'})
        assert config.mode == YaraMode.CUSTOM
        assert config.unicode_steg.zerowidth_threshold_alone == 1000
        assert not config.unicode_steg.detect_line_separators
        assert 'noisy_rule' in config.disabled_rules

    def test_to_dict_serialization(self):
        config = YaraModeConfig.balanced()
        data = config.serialize()
        assert data['mode'] == 'balanced'
        assert 'unicode_steg' in data
        assert 'credential_harvesting' in data
        assert 'tool_chaining' in data
        assert 'disabled_rules' in data

class TestPatternEngineWithModes:

    def test_default_mode_is_balanced(self):
        analyzer = PatternEngine()
        assert analyzer.yara_mode.mode == YaraMode.BALANCED

    def test_accepts_string_mode(self):
        analyzer = PatternEngine(yara_mode='strict')
        assert analyzer.yara_mode.mode == YaraMode.STRICT

    def test_accepts_config_object(self):
        config = YaraModeConfig.permissive()
        analyzer = PatternEngine(yara_mode=config)
        assert analyzer.yara_mode.mode == YaraMode.PERMISSIVE

    def test_strict_mode_flags_more(self):
        strict_config = YaraModeConfig.strict()
        balanced_config = YaraModeConfig.balanced()
        assert not strict_config.credential_harvesting.filter_placeholder_patterns
        assert balanced_config.credential_harvesting.filter_placeholder_patterns

class TestModeDescriptions:

    def test_all_modes_have_descriptions(self):
        strict = YaraModeConfig.strict()
        balanced = YaraModeConfig.balanced()
        permissive = YaraModeConfig.permissive()
        assert strict.description
        assert balanced.description
        assert permissive.description

    def test_descriptions_are_distinct(self):
        strict = YaraModeConfig.strict()
        balanced = YaraModeConfig.balanced()
        permissive = YaraModeConfig.permissive()
        descriptions = {strict.description, balanced.description, permissive.description}
        assert len(descriptions) == 3
