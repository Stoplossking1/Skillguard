import json
import re
from pathlib import Path
import pytest
from sgscanner.taxonomy.skillsguard_ai_taxonomy import VALID_AISUBTECH_CODES, VALID_AITECH_CODES, get_aisubtech_name, get_aitech_name
from sgscanner.taxonomy.threats import ThreatMapping

class TestTaxonomyValidation:
    PLACEHOLDER_CODE = '99.9'

    def _get_all_codes_from_threats(self) -> list[tuple[str, str, str | None, str | None]]:
        results = []
        threat_dicts = [('LLM_THREATS', ThreatMapping.LLM_THREATS), ('YARA_THREATS', ThreatMapping.YARA_THREATS), ('BEHAVIORAL_THREATS', ThreatMapping.BEHAVIORAL_THREATS)]
        for dict_name, threats in threat_dicts:
            for threat_name, info in threats.items():
                results.append((dict_name, threat_name, info.get('aitech'), info.get('aisubtech')))
        return results

    def test_all_aitech_codes_exist_in_taxonomy(self):
        invalid_codes = []
        for dict_name, threat_name, aitech, _ in self._get_all_codes_from_threats():
            if aitech and self.PLACEHOLDER_CODE not in aitech:
                if aitech not in VALID_AITECH_CODES:
                    invalid_codes.append(f"{dict_name}['{threat_name}']: '{aitech}' not in taxonomy")
        assert not invalid_codes, f'Found {len(invalid_codes)} invalid AITech code(s):\n' + '\n'.join((f'  - {e}' for e in invalid_codes))

    def test_all_aisubtech_codes_exist_in_taxonomy(self):
        invalid_codes = []
        for dict_name, threat_name, _, aisubtech in self._get_all_codes_from_threats():
            if aisubtech and self.PLACEHOLDER_CODE not in aisubtech:
                if aisubtech not in VALID_AISUBTECH_CODES:
                    invalid_codes.append(f"{dict_name}['{threat_name}']: '{aisubtech}' not in taxonomy")
        assert not invalid_codes, f'Found {len(invalid_codes)} invalid AISubtech code(s):\n' + '\n'.join((f'  - {e}' for e in invalid_codes))

    def test_aitech_code_format(self):
        pattern = re.compile('^AITech-\\d+\\.\\d+$')
        invalid_format = []
        for dict_name, threat_name, aitech, _ in self._get_all_codes_from_threats():
            if aitech and (not pattern.match(aitech)):
                invalid_format.append(f"{dict_name}['{threat_name}']: '{aitech}' invalid format")
        assert not invalid_format, f'Found {len(invalid_format)} malformed AITech code(s):\n' + '\n'.join((f'  - {e}' for e in invalid_format))

    def test_aisubtech_code_format(self):
        pattern = re.compile('^AISubtech-\\d+\\.\\d+\\.\\d+$')
        invalid_format = []
        for dict_name, threat_name, _, aisubtech in self._get_all_codes_from_threats():
            if aisubtech and (not pattern.match(aisubtech)):
                invalid_format.append(f"{dict_name}['{threat_name}']: '{aisubtech}' invalid format")
        assert not invalid_format, f'Found {len(invalid_format)} malformed AISubtech code(s):\n' + '\n'.join((f'  - {e}' for e in invalid_format))

    def test_aisubtech_parent_matches_aitech(self):
        mismatches = []
        for dict_name, threat_name, aitech, aisubtech in self._get_all_codes_from_threats():
            if aitech and aisubtech:
                if self.PLACEHOLDER_CODE in aitech or self.PLACEHOLDER_CODE in aisubtech:
                    continue
                aisubtech_parent = '.'.join(aisubtech.replace('AISubtech-', '').split('.')[:2])
                aitech_suffix = aitech.replace('AITech-', '')
                if aisubtech_parent != aitech_suffix:
                    mismatches.append(f"{dict_name}['{threat_name}']: AITech={aitech} but AISubtech={aisubtech}")
        assert not mismatches, f'Found {len(mismatches)} AITech/AISubtech parent mismatch(es):\n' + '\n'.join((f'  - {e}' for e in mismatches))

class TestTaxonomyCompleteness:

    def test_taxonomy_has_aitech_codes(self):
        assert len(VALID_AITECH_CODES) > 0, 'Taxonomy file has no AITech codes'
        assert len(VALID_AITECH_CODES) >= 40, 'Expected at least 40 AITech codes'

    def test_taxonomy_has_aisubtech_codes(self):
        assert len(VALID_AISUBTECH_CODES) > 0, 'Taxonomy file has no AISubtech codes'
        assert len(VALID_AISUBTECH_CODES) >= 100, 'Expected at least 100 AISubtech codes'

    def test_known_codes_present(self):
        assert 'AITech-1.1' in VALID_AITECH_CODES, 'Missing Direct Prompt Injection'
        assert 'AITech-8.2' in VALID_AITECH_CODES, 'Missing Data Exfiltration'
        assert 'AITech-9.1' in VALID_AITECH_CODES, 'Missing System Manipulation'
        assert 'AITech-12.1' in VALID_AITECH_CODES, 'Missing Tool Exploitation'
        assert 'AITech-13.1' in VALID_AITECH_CODES, 'Missing Disruption of Availability'
        assert 'AISubtech-1.1.1' in VALID_AISUBTECH_CODES, 'Missing Instruction Manipulation'
        assert 'AISubtech-8.2.3' in VALID_AISUBTECH_CODES, 'Missing Data Exfiltration via Agent Tooling'

class TestTaxonomyHelpers:

    def test_is_valid_aitech(self):
        from sgscanner.taxonomy.skillsguard_ai_taxonomy import is_valid_aitech
        assert is_valid_aitech('AITech-1.1') is True
        assert is_valid_aitech('AITech-99.99') is False
        assert is_valid_aitech('invalid') is False

    def test_is_valid_aisubtech(self):
        from sgscanner.taxonomy.skillsguard_ai_taxonomy import is_valid_aisubtech
        assert is_valid_aisubtech('AISubtech-1.1.1') is True
        assert is_valid_aisubtech('AISubtech-99.99.99') is False
        assert is_valid_aisubtech('invalid') is False

    def test_get_aitech_name(self):
        assert get_aitech_name('AITech-1.1') == 'Direct Prompt Injection'
        assert get_aitech_name('AITech-8.2') == 'Data Exfiltration / Exposure'
        assert get_aitech_name('AITech-99.99') is None

    def test_get_aisubtech_name(self):
        assert get_aisubtech_name('AISubtech-1.1.1') == 'Instruction Manipulation (Direct Prompt Injection)'
        assert get_aisubtech_name('AISubtech-99.99.99') is None

class TestLLMEngineTaxonomy:
    AITECH_PATTERN = re.compile('AITech-\\d+\\.\\d+')
    AISUBTECH_PATTERN = re.compile('AISubtech-\\d+\\.\\d+\\.\\d+')
    FILES_TO_SCAN = ['sgscanner/core/detectors/semantic_detector.py', 'sgscanner/data/prompts/llm_response_schema.json', 'sgscanner/data/prompts/skill_meta_analysis_prompt.md', 'sgscanner/data/prompts/skill_threat_analysis_prompt.md']

    def _get_project_root(self) -> Path:
        return Path(__file__).parent.parent

    def _extract_codes_from_file(self, filepath: Path) -> list[tuple[str, int, str]]:
        if not filepath.exists():
            return []
        results = []
        content = filepath.read_text()
        for line_num, line in enumerate(content.splitlines(), start=1):
            for match in self.AITECH_PATTERN.finditer(line):
                results.append((match.group(), line_num, line.strip()[:80]))
            for match in self.AISUBTECH_PATTERN.finditer(line):
                results.append((match.group(), line_num, line.strip()[:80]))
        return results

    def test_semantic_detector_aitech_codes_valid(self):
        root = self._get_project_root()
        invalid_codes = []
        files_scanned = 0
        for file_path in self.FILES_TO_SCAN:
            full_path = root / file_path
            if not full_path.exists():
                continue
            files_scanned += 1
            codes = self._extract_codes_from_file(full_path)
            for code, line_num, _ in codes:
                if code.startswith('AITech-'):
                    if code not in VALID_AITECH_CODES:
                        invalid_codes.append(f"{file_path}:{line_num}: '{code}' not in taxonomy")
                elif code.startswith('AISubtech-'):
                    if code not in VALID_AISUBTECH_CODES:
                        invalid_codes.append(f"{file_path}:{line_num}: '{code}' not in taxonomy")
        if files_scanned == 0:
            pytest.skip('No LLM analyzer files found to scan')
        assert not invalid_codes, f'Found {len(invalid_codes)} invalid AITech/AISubtech code(s) in LLM files:\n' + '\n'.join((f'  - {e}' for e in invalid_codes))

    def test_llm_response_schema_enum_valid(self):
        root = self._get_project_root()
        schema_path = root / 'sgscanner/data/prompts/llm_response_schema.json'
        if not schema_path.exists():
            pytest.skip('LLM response schema not found')
        schema = json.loads(schema_path.read_text())
        invalid_codes = []
        try:
            aitech_enum = schema.get('properties', {}).get('threats', {}).get('items', {}).get('properties', {}).get('aitech', {}).get('enum', [])
            for code in aitech_enum:
                if code not in VALID_AITECH_CODES:
                    invalid_codes.append(f"'{code}' in schema enum not in taxonomy")
        except (KeyError, TypeError):
            pass
        assert not invalid_codes, f'Found {len(invalid_codes)} invalid AITech code(s) in schema enum:\n' + '\n'.join((f'  - {e}' for e in invalid_codes))
