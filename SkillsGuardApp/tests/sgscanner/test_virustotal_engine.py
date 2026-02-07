import os
from pathlib import Path
import pytest
from sgscanner.engines.virustotal import VirusTotalEngine
from sgscanner.loader import SkillIngester
from sgscanner.models import Severity, ThreatCategory

@pytest.fixture
def example_skills_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills'

@pytest.fixture
def vt_analyzer_disabled():
    return VirusTotalEngine(api_key=None, enabled=False)

@pytest.fixture
def vt_analyzer_mock():
    return VirusTotalEngine(api_key='test_key_for_testing', enabled=True)

@pytest.fixture
def vt_analyzer_real():
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        pytest.skip('VIRUSTOTAL_API_KEY environment variable not set')
    return VirusTotalEngine(api_key=api_key, enabled=True)

def test_vt_analyzer_disabled_returns_empty(vt_analyzer_disabled, example_skills_dir):
    loader = SkillIngester()
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    skill = loader.ingest(skill_dir)
    findings = vt_analyzer_disabled.run(skill)
    assert findings == []

def test_binary_file_detection(vt_analyzer_mock):
    assert vt_analyzer_mock._is_binary_file('test.png')
    assert vt_analyzer_mock._is_binary_file('document.pdf')
    assert vt_analyzer_mock._is_binary_file('archive.zip')
    assert vt_analyzer_mock._is_binary_file('image.jpg')
    assert vt_analyzer_mock._is_binary_file('program.exe')
    assert not vt_analyzer_mock._is_binary_file('script.py')
    assert not vt_analyzer_mock._is_binary_file('README.md')
    assert not vt_analyzer_mock._is_binary_file('code.js')
    assert not vt_analyzer_mock._is_binary_file('style.css')
    assert not vt_analyzer_mock._is_binary_file('config.json')
    assert not vt_analyzer_mock._is_binary_file('data.yaml')
    assert not vt_analyzer_mock._is_binary_file('test.txt')

def test_excluded_extensions(vt_analyzer_mock):
    excluded_exts = ['.py', '.js', '.md', '.txt', '.json', '.yaml', '.html', '.css', '.xml', '.sh', '.sql']
    for ext in excluded_exts:
        assert not vt_analyzer_mock._is_binary_file(f'file{ext}')

def test_binary_extensions(vt_analyzer_mock):
    binary_exts = ['.png', '.jpg', '.pdf', '.zip', '.exe', '.dll', '.doc', '.docx', '.xls', '.xlsx']
    for ext in binary_exts:
        assert vt_analyzer_mock._is_binary_file(f'file{ext}')

def test_unknown_extension_defaults_to_not_binary(vt_analyzer_mock):
    assert not vt_analyzer_mock._is_binary_file('file.xyz')
    assert not vt_analyzer_mock._is_binary_file('file.unknown')
    assert not vt_analyzer_mock._is_binary_file('file.custom')

def test_analyzer_initialization():
    analyzer1 = VirusTotalEngine(api_key=None)
    assert not analyzer1.enabled
    assert not analyzer1.upload_files
    analyzer2 = VirusTotalEngine(api_key='test_key')
    assert analyzer2.enabled
    assert not analyzer2.upload_files
    analyzer3 = VirusTotalEngine(api_key='test_key', upload_files=True)
    assert analyzer3.enabled
    assert analyzer3.upload_files
    analyzer4 = VirusTotalEngine(api_key='test_key', enabled=False)
    assert not analyzer4.enabled

def test_sha256_calculation(tmp_path, vt_analyzer_mock):
    test_file = tmp_path / 'test.bin'
    test_file.write_bytes(b'Hello, World!')
    file_hash = vt_analyzer_mock._calculate_sha256(test_file)
    assert len(file_hash) == 64
    assert all((c in '0123456789abcdef' for c in file_hash))
    file_hash2 = vt_analyzer_mock._calculate_sha256(test_file)
    assert file_hash == file_hash2
    expected_hash = 'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f'
    assert file_hash == expected_hash

def test_no_real_api_calls_in_tests(vt_analyzer_mock, example_skills_dir):
    loader = SkillIngester()
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    skill = loader.ingest(skill_dir)
    try:
        findings = vt_analyzer_mock.run(skill)
        assert isinstance(findings, list)
    except Exception as e:
        assert 'request' in str(e).lower() or 'connection' in str(e).lower()

def test_eicar_skill_structure(example_skills_dir):
    loader = SkillIngester()
    eicar_skill_dir = example_skills_dir / 'malicious' / 'eicar-test'
    if not eicar_skill_dir.exists():
        pytest.skip('EICAR test skill not found')
    skill = loader.ingest(eicar_skill_dir)
    assert skill.name == 'eicar-test'
    binary_files = [f for f in skill.files if 'assets' in f.relative_path]
    assert len(binary_files) > 0, 'Should have at least one file in assets folder'
    print('\n[OK] EICAR test skill structure verified')
    print(f'  Skill name: {skill.name}')
    print(f'  Total files: {len(skill.files)}')
    print(f'  Binary files in assets: {len(binary_files)}')

@pytest.mark.skipif(not os.getenv('VIRUSTOTAL_API_KEY'), reason='Requires VIRUSTOTAL_API_KEY')
def test_virustotal_api_integration(vt_analyzer_real, example_skills_dir):
    loader = SkillIngester()
    eicar_skill_dir = example_skills_dir / 'malicious' / 'eicar-test'
    if not eicar_skill_dir.exists():
        pytest.skip('EICAR test skill not found')
    skill = loader.ingest(eicar_skill_dir)
    binary_files = [f for f in skill.files if vt_analyzer_real._is_binary_file(f.relative_path)]
    if len(binary_files) == 0:
        pytest.skip('No binary files found in test skill')
    findings = vt_analyzer_real.run(skill)
    assert isinstance(findings, list), 'Should return a list of findings'
    print('\n[OK] VirusTotal API integration test passed!')
    print(f'  Binary files scanned: {len(binary_files)}')
    print(f'  Findings: {len(findings)}')
    print(f'  Status: {('Malicious files detected' if findings else 'No known threats (file not in VT database)')}')
