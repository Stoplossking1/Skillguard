import os
import secrets
import tempfile
from pathlib import Path
import pytest
from dotenv import load_dotenv
from sgscanner.engines.virustotal import VirusTotalEngine
from sgscanner.loader import SkillIngester
from sgscanner.models import Skill, SkillFile
load_dotenv()

def test_virustotal_upload_fresh_file():
    api_key = os.getenv('VIRUSTOTAL_API_KEY')
    if not api_key:
        pytest.skip('VIRUSTOTAL_API_KEY not set in environment or .env file')
    vt_analyzer = VirusTotalEngine(api_key=api_key, enabled=True, upload_files=True)
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir_path = Path(tmpdir)
        skill_md = tmpdir_path / 'SKILL.md'
        skill_md.write_text('---\nname: vt-upload-test\ndescription: Test skill for VirusTotal upload testing\nlicense: MIT\n---\n\n# Test Skill for VT Upload\n\nThis is a temporary test skill for VirusTotal upload functionality testing.\nIt contains a randomly generated binary file for upload testing.\n')
        assets_dir = tmpdir_path / 'assets'
        assets_dir.mkdir()
        random_data = secrets.token_bytes(1024)
        random_file = assets_dir / 'random_test.bin'
        random_file.write_bytes(random_data)
        import hashlib
        file_hash = hashlib.sha256(random_data).hexdigest()
        print(f'\n{'=' * 70}')
        print('VirusTotal Upload Test (Fresh Random File)')
        print(f'{'=' * 70}')
        print('Generated new random binary file')
        print('  Path: assets/random_test.bin')
        print(f'  SHA256: {file_hash}')
        print(f'  Size: {len(random_data)} bytes')
        print('\nThis file has NEVER been seen by VirusTotal before.')
        print('It should trigger an upload...')
        loader = SkillIngester()
        skill = loader.ingest(tmpdir_path)
        print(f'\n{'=' * 70}')
        print('Scanning with VirusTotal (upload enabled)...')
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
        print(f'\n{'=' * 70}')
        print('TEST RESULT:')
        print(f'{'=' * 70}')
        if len(findings) == 0:
            print('[OK] SUCCESS: File uploaded and scanned cleanly')
            print('   - File was uploaded to VirusTotal')
            print('   - Analysis completed successfully')
            print('   - No AV vendors flagged random data as malicious')
        else:
            print('[WARNING] Unexpected detections on random data:')
            for finding in findings:
                print(f'   - {finding.severity.value}: {finding.title}')
        print(f'{'=' * 70}\n')
        assert isinstance(findings, list), 'Should return a list of findings'
        from sgscanner.models import Severity
        critical_findings = [f for f in findings if f.severity == Severity.CRITICAL]
        assert len(critical_findings) == 0, f'Random data should not be flagged as CRITICAL: {critical_findings}'
if __name__ == '__main__':
    pytest.main([__file__, '-v', '-s'])
