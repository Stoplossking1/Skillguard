import os
from pathlib import Path
import pytest
from dotenv import load_dotenv
from sgscanner.engines.virustotal import VirusTotalEngine
from sgscanner.loader import SkillIngester
from sgscanner.models import Severity, ThreatCategory
load_dotenv()

def test_virustotal_benign_file():
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        pytest.skip('VIRUSTOTAL_API_KEY not set in environment or .env file')
    vt_analyzer = VirusTotalEngine(api_key=api_key, enabled=True, upload_files=True)
    loader = SkillIngester()
    test_skills_dir = Path(__file__).parent.parent / 'evals' / 'test_skills'
    test_skill_dir = test_skills_dir / 'malicious' / 'eicar-test'
    if not test_skill_dir.exists():
        pytest.skip(f'Test skill not found at {test_skill_dir}')
    skill = loader.ingest(test_skill_dir)
    binary_files = [f for f in skill.files if 'assets/' in f.relative_path and f.relative_path.endswith(('.bin', '.com'))]
    if len(binary_files) == 0:
        pytest.skip(f'No binary files found in assets folder. Files: {[f.relative_path for f in skill.files]}')
    print(f'\n{'=' * 70}')
    print('VirusTotal Benign Binary Test')
    print(f'{'=' * 70}')
    print(f'Skill: {skill.name}')
    print(f'Binary files to scan: {len(binary_files)}')
    print(f'Files: {[f.relative_path for f in binary_files]}')
    binary_file = binary_files[0]
    file_path = skill.directory / binary_file.relative_path
    import hashlib
    with open(file_path, 'rb') as f:
        file_hash = hashlib.sha256(f.read()).hexdigest()
    print('\nFile details:')
    print(f'  Path: {binary_file.relative_path}')
    print(f'  SHA256: {file_hash}')
    print(f'  Size: {file_path.stat().st_size} bytes')
    print('\nScanning with VirusTotal (upload enabled)...')
    print(f'{'=' * 70}')
    findings = vt_analyzer.run(skill)
    print(f'\n{'=' * 70}')
    print('SCAN RESULTS')
    print(f'{'=' * 70}')
    print(f'Total findings: {len(findings)}')
    for i, finding in enumerate(findings, 1):
        print(f'\nFinding #{i}:')
        print(f'  Category: {finding.category.value}')
        print(f'  Severity: {finding.severity.value}')
        print(f'  File: {finding.file_path}')
        print(f'  Title: {finding.title}')
        print(f'  Description: {finding.description[:100]}...')
        if finding.references:
            print(f'  VT Link: {finding.references[0]}')
    print(f'\n{'=' * 70}')
    print('TEST RESULT:')
    print(f'{'=' * 70}')
    if len(findings) == 0:
        print('[OK] File is clean (no detections)')
        print('  - File was scanned by VirusTotal')
        print('  - No AV vendors flagged it as malicious')
        print('  - Upload functionality working correctly')
    else:
        print('[WARNING] Unexpected findings for benign binary:')
        for finding in findings:
            print(f'  - {finding.severity.value}: {finding.title}')
            print(f'    File: {finding.file_path}')
    print(f'{'=' * 70}\n')
    assert isinstance(findings, list), 'Should return a list of findings'
    critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) == 0, f'Benign file should not have CRITICAL findings: {critical_findings}'
if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
