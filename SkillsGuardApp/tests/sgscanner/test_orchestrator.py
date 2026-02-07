from pathlib import Path
import pytest
from sgscanner.models import Severity
from sgscanner.pipeline.orchestrator import ScanOrchestrator, scan_skill

@pytest.fixture
def example_skills_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills'

@pytest.fixture
def scanner():
    return ScanOrchestrator()

def test_scan_single_skill(scanner, example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    result = scanner.inspect(skill_dir)
    assert result.skill_name == 'simple-formatter'
    assert result.scan_duration_seconds > 0
    assert len(result.engines_used) > 0
    assert 'pattern_detector' in result.engines_used

def test_scan_result_is_safe_property(scanner, example_skills_dir):
    safe_dir = example_skills_dir / 'safe' / 'simple-formatter'
    safe_result = scanner.inspect(safe_dir)
    assert safe_result.is_safe
    malicious_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    malicious_result = scanner.inspect(malicious_dir)
    assert not malicious_result.is_safe

def test_scan_result_max_severity(scanner, example_skills_dir):
    malicious_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    result = scanner.inspect(malicious_dir)
    assert result.max_severity in [Severity.CRITICAL, Severity.HIGH]

def test_inspect_directory(scanner, example_skills_dir):
    report = scanner.inspect_directory(example_skills_dir, recursive=True)
    assert report.total_skills_scanned >= 2
    assert len(report.scan_results) >= 2
    assert report.safe_count >= 1
    assert report.critical_count > 0 or report.high_count > 0

def test_scan_result_to_dict(scanner, example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    result = scanner.inspect(skill_dir)
    result_dict = result.serialize()
    assert 'skill_name' in result_dict
    assert 'is_safe' in result_dict
    assert 'findings' in result_dict
    assert 'max_severity' in result_dict
    assert isinstance(result_dict['findings'], list)

def test_report_to_dict(scanner, example_skills_dir):
    report = scanner.inspect_directory(example_skills_dir)
    report_dict = report.serialize()
    assert 'summary' in report_dict
    assert 'results' in report_dict
    assert 'total_skills_scanned' in report_dict['summary']
    assert isinstance(report_dict['results'], list)

def test_convenience_function(example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    result = inspect_skill(skill_dir)
    assert result.skill_name == 'simple-formatter'
    assert result.scan_duration_seconds > 0

def test_scanner_list_detectors(scanner):
    detectors = scanner.list_engines()
    assert len(detectors) > 0
    assert 'pattern_detector' in detectors

def test_findings_include_detector_field(scanner, example_skills_dir):
    malicious_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    result = scanner.inspect(malicious_dir)
    assert len(result.findings) > 0
    for finding in result.findings:
        assert finding.engine is not None, f'Finding {finding.id} has no detector field'
        assert isinstance(finding.engine, str), f'Finding {finding.id} detector should be a string'
        assert len(finding.engine) > 0, f'Finding {finding.id} has empty detector field'

def test_findings_to_dict_includes_detector_in_json(scanner, example_skills_dir):
    malicious_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    result = scanner.inspect(malicious_dir)
    result_dict = result.serialize()
    assert len(result_dict['findings']) > 0
    for finding_dict in result_dict['findings']:
        assert 'detector' in finding_dict, f'detector field missing from finding JSON: {finding_dict.get('id', 'unknown')}'
        assert finding_dict['detector'] is not None, f'detector field is None for finding: {finding_dict.get('id', 'unknown')}'
        assert isinstance(finding_dict['detector'], str), f'detector should be string in JSON for finding: {finding_dict.get('id', 'unknown')}'

def test_pattern_detector_findings_labeled_correctly(scanner, example_skills_dir):
    malicious_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    result = scanner.inspect(malicious_dir)
    result_dict = result.serialize()
    pattern_findings = [f for f in result_dict['findings'] if f.get('detector') == 'pattern']
    assert len(pattern_findings) > 0, 'Expected to find findings from pattern detector'
    for finding in pattern_findings:
        assert finding['detector'] == 'pattern'
