import argparse
import json
import subprocess
import sys
from pathlib import Path
DEFAULT_CONFIG = {'severity_threshold': 'high', 'skills_path': '.claude/skills', 'fail_fast': True, 'use_behavioral': False, 'use_trigger': True}
SEVERITY_LEVELS = {'safe': 0, 'info': 1, 'low': 2, 'medium': 3, 'high': 4, 'critical': 5}

def load_config(repo_root: Path) -> dict:
    config = DEFAULT_CONFIG.copy()
    config_paths = [repo_root / '.sgscannerrc', repo_root / '.sgscannerrc.json', repo_root / 'sgscanner.json']
    for config_path in config_paths:
        if config_path.exists():
            try:
                with open(config_path) as f:
                    user_config = json.load(f)
                    config.update(user_config)
                    break
            except (OSError, json.JSONDecodeError) as e:
                print(f'Warning: Failed to load config from {config_path}: {e}', file=sys.stderr)
    return config

def get_staged_files() -> list[str]:
    try:
        result = subprocess.run(['git', 'diff', '--cached', '--name-only', '--diff-filter=ACMR'], capture_output=True, text=True, check=True)
        return [f.strip() for f in result.stdout.split('\n') if f.strip()]
    except subprocess.CalledProcessError:
        return []

def get_affected_skills(staged_files: list[str], skills_path: str) -> set[Path]:
    affected_skills = set()
    skills_prefix = skills_path.rstrip('/') + '/'
    for file_path in staged_files:
        if file_path.startswith(skills_prefix) or file_path.startswith(skills_path):
            relative = file_path[len(skills_path):].lstrip('/')
            parts = relative.split('/')
            if parts:
                skill_dir = Path(skills_path) / parts[0]
                skill_md = skill_dir / 'SKILL.md'
                if skill_md.exists():
                    affected_skills.add(skill_dir)
        if file_path.endswith('SKILL.md'):
            skill_dir = Path(file_path).parent
            affected_skills.add(skill_dir)
    return affected_skills

def inspect(skill_dir: Path, config: dict) -> dict:
    try:
        from ..engines.base import ScanEngine
        from ..engines.pattern import PatternEngine
        from ..pipeline.orchestrator import ScanOrchestrator
        detectors: list[ScanEngine] = [PatternEngine()]
        if config.get('use_dataflow') or config.get('use_behavioral'):
            try:
                from ..engines.dataflow import DataflowEngine
                detectors.append(DataflowEngine(use_static_analysis=True))
            except ImportError:
                pass
        if config.get('use_description') or config.get('use_trigger'):
            try:
                from ..engines.description import DescriptionEngine
                detectors.append(DescriptionEngine())
            except ImportError:
                pass
        scanner = ScanOrchestrator(detectors=detectors)
        result = scanner.inspect(skill_dir)
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for f in result.findings:
            sev = f.severity.value.lower() if hasattr(f.severity, 'value') else str(f.severity).lower()
            if sev in counts:
                counts[sev] += 1
        return {'skill_name': result.skill_name, 'skill_directory': result.skill_directory, 'findings': [{'rule_id': f.rule_id, 'severity': f.severity.value if hasattr(f.severity, 'value') else str(f.severity), 'title': f.title, 'description': f.description, 'file_path': f.file_path, 'line_number': f.line_number} for f in result.findings], 'critical_count': counts['critical'], 'high_count': counts['high'], 'medium_count': counts['medium'], 'low_count': counts['low']}
    except Exception as e:
        return {'skill_name': skill_dir.name, 'skill_directory': str(skill_dir), 'findings': [], 'error': str(e)}

def check_severity_threshold(result: dict, threshold: str) -> bool:
    threshold_level = SEVERITY_LEVELS.get(threshold.lower(), SEVERITY_LEVELS['high'])
    for finding in result.get('findings', []):
        finding_level = SEVERITY_LEVELS.get(finding['severity'].lower(), 0)
        if finding_level >= threshold_level:
            return True
    return False

def format_finding(finding: dict) -> str:
    severity = finding['severity'].upper()
    title = finding['title']
    location = finding.get('file_path', '')
    if finding.get('line_number'):
        location = f'{location}:{finding['line_number']}'
    return f'  [{severity}] {title}\n    Location: {location}'

def main(args: list[str] | None=None) -> int:
    parser = argparse.ArgumentParser(description='Pre-commit hook for scanning agent skills')
    parser.add_argument('--severity', choices=['critical', 'high', 'medium', 'low'], help='Override severity threshold from config')
    parser.add_argument('--skills-path', help='Override skills path from config')
    parser.add_argument('--all', action='store_true', help='Scan all skills, not just staged ones')
    parser.add_argument('install', nargs='?', help='Install pre-commit hook')
    parsed_args = parser.parse_args(args)
    if parsed_args.install == 'install':
        return install_hook()
    try:
        result = subprocess.run(['git', 'rev-parse', '--show-toplevel'], capture_output=True, text=True, check=True)
        repo_root = Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        print('Error: Not a git repository', file=sys.stderr)
        return 1
    config = load_config(repo_root)
    if parsed_args.severity:
        config['severity_threshold'] = parsed_args.severity
    if parsed_args.skills_path:
        config['skills_path'] = parsed_args.skills_path
    if parsed_args.all:
        skills_dir = repo_root / config['skills_path']
        if skills_dir.exists():
            affected_skills = {d for d in skills_dir.iterdir() if d.is_dir() and (d / 'SKILL.md').exists()}
        else:
            affected_skills = set()
    else:
        staged_files = get_staged_files()
        affected_skills = get_affected_skills(staged_files, config['skills_path'])
    if not affected_skills:
        return 0
    print(f'Scanning {len(affected_skills)} skill(s)...')
    blocked = False
    all_findings = []
    for skill_dir in sorted(affected_skills):
        print(f'\n📦 {skill_dir.name}')
        result = scan_skill(skill_dir, config)
        if result.get('error'):
            print(f'  ⚠️  Error: {result['error']}', file=sys.stderr)
            continue
        findings = result.get('findings', [])
        if not findings:
            print('  ✅ No issues found')
            continue
        if check_severity_threshold(result, config['severity_threshold']):
            blocked = True
            print(f'  🚫 Blocked (threshold: {config['severity_threshold'].upper()})')
        else:
            print(f'  ⚠️  {len(findings)} finding(s) below threshold')
        for finding in findings:
            print(format_finding(finding))
            all_findings.append(finding)
        if blocked and config.get('fail_fast'):
            break
    print(f'\n{'=' * 50}')
    if blocked:
        print('❌ Commit BLOCKED - fix security issues before committing')
        print(f'   Threshold: {config['severity_threshold'].upper()} and above')
        return 1
    elif all_findings:
        print(f'⚠️  {len(all_findings)} finding(s) detected (below threshold)')
        print('   Consider reviewing and fixing these issues')
        return 0
    else:
        print('✅ All skills passed security checks')
        return 0

def install_hook() -> int:
    try:
        result = subprocess.run(['git', 'rev-parse', '--show-toplevel'], capture_output=True, text=True, check=True)
        repo_root = Path(result.stdout.strip())
    except subprocess.CalledProcessError:
        print('Error: Not a git repository', file=sys.stderr)
        return 1
    hooks_dir = repo_root / '.git' / 'hooks'
    hooks_dir.mkdir(exist_ok=True)
    hook_path = hooks_dir / 'pre-commit'
    hook_script = '#!/bin/sh\n# Skill Scanner Pre-commit Hook\n# Automatically scans agent skills for security issues\n\nskill-scanner-pre-commit "$@"\nexit_code=$?\n\nif [ $exit_code -ne 0 ]; then\n    echo ""\n    echo "To bypass this check (not recommended), use: git commit --no-verify"\nfi\n\nexit $exit_code\n'
    if hook_path.exists():
        print(f'Warning: Pre-commit hook already exists at {hook_path}')
        response = input('Overwrite? [y/N] ').strip().lower()
        if response != 'y':
            print('Aborted')
            return 1
    hook_path.write_text(hook_script)
    hook_path.chmod(493)
    print(f'✅ Pre-commit hook installed at {hook_path}')
    print('\nConfiguration:')
    print('  Create .sgscannerrc in your repo root to customize behavior:')
    print('  { "severity_threshold": "high", "skills_path": ".claude/skills" }')
    return 0
if __name__ == '__main__':
    sys.exit(main())
