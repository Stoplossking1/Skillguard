from pathlib import Path
import pytest
from sgscanner.engines.pattern import PatternEngine
from sgscanner.loader import SkillIngester
from sgscanner.models import Severity, ThreatCategory

@pytest.fixture
def example_skills_dir():
    return Path(__file__).parent.parent.parent / 'evals' / 'test_skills'

@pytest.fixture
def loader():
    return SkillIngester()

@pytest.fixture
def analyzer():
    return PatternEngine()

def test_safe_skill_has_no_critical_findings(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(critical_findings) == 0
    assert len(high_findings) == 0

def test_malicious_skill_detected(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    exfil_findings = [f for f in findings if f.category == ThreatCategory.DATA_EXFILTRATION]
    assert len(exfil_findings) > 0
    injection_findings = [f for f in findings if f.category == ThreatCategory.COMMAND_INJECTION]
    assert len(injection_findings) > 0

def test_prompt_injection_detected(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'prompt-injection'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    prompt_inj_findings = [f for f in findings if f.category == ThreatCategory.PROMPT_INJECTION]
    assert len(prompt_inj_findings) > 0
    high_findings = [f for f in findings if f.severity == Severity.HIGH]
    assert len(high_findings) > 0

def test_analyzer_detects_network_usage(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    network_findings = [f for f in findings if 'requests' in str(f.description).lower() or 'network' in str(f.description).lower()]
    assert len(network_findings) > 0

def test_analyzer_detects_sensitive_file_access(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    assert len(findings) > 0

def test_finding_has_required_fields(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    assert len(findings) > 0
    for finding in findings:
        assert finding.id is not None
        assert finding.rule_id is not None
        assert finding.category is not None
        assert finding.severity is not None
        assert finding.title is not None
        assert finding.description is not None

def test_pattern_detector_findings_have_detector_field(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    assert len(findings) > 0
    for finding in findings:
        assert finding.engine == 'pattern', f"Expected analyzer='pattern', got '{finding.engine}'"
        assert finding.engine == 'pattern', f"Expected detector='pattern', got '{finding.engine}'"

def test_pattern_detector_findings_to_dict_includes_detector(loader, analyzer, example_skills_dir):
    skill_dir = example_skills_dir / 'malicious' / 'exfiltrator'
    skill = loader.ingest(skill_dir)
    findings = analyzer.run(skill)
    assert len(findings) > 0
    for finding in findings:
        finding_dict = finding.serialize()
        assert 'analyzer' in finding_dict, 'analyzer field missing from to_dict() output'
        assert 'detector' in finding_dict, 'detector field missing from to_dict() output'
        assert finding_dict['analyzer'] == 'pattern', f"Expected analyzer='pattern', got '{finding_dict['analyzer']}'"
        assert finding_dict['detector'] == 'pattern', f"Expected detector='pattern', got '{finding_dict['detector']}'"
