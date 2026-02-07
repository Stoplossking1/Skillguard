import argparse
import asyncio
import os
import sys
from pathlib import Path
from ..engines.dataflow import DataflowEngine
from ..engines.pattern import PatternEngine
from ..reports.json_reporter import JSONReporter
from ..reports.sarif_reporter import SARIFReporter
from ..pipeline.orchestrator import ScanOrchestrator
try:
    from ..engines.llm_engine import LLMEngine
    SEMANTIC_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    SEMANTIC_AVAILABLE = False
    LLMEngine = None
try:
    from ..engines.meta import MetaEngine, apply_meta_filtering
    META_AVAILABLE = True
except (ImportError, ModuleNotFoundError):
    META_AVAILABLE = False
    MetaEngine = None
    apply_meta_filtering = None
from ..loader import IngestionError
from ..reports.markdown_reporter import MarkdownReporter
from ..reports.table_reporter import TableReporter

def inspect_command(args):
    skill_dir = Path(args.skill_directory)
    if not skill_dir.exists():
        print(f'Error: Directory does not exist: {skill_dir}', file=sys.stderr)
        return 1
    yara_mode = getattr(args, 'yara_mode', 'balanced')
    custom_rules_path = getattr(args, 'custom_rules', None)
    disabled_rules = set(getattr(args, 'disabled_rules', None) or [])
    detectors = [PatternEngine(yara_mode=yara_mode, custom_yara_rules_path=custom_rules_path, disabled_rules=disabled_rules)]
    is_json_output = getattr(args, 'format', 'summary') == 'json'

    def status_print(msg: str) -> None:
        if is_json_output:
            print(msg, file=sys.stderr)
        else:
            print(msg)
    if hasattr(args, 'dataflow') and args.dataflow:
        try:
            dataflow_detector = DataflowEngine(use_static_analysis=True)
            detectors.append(dataflow_detector)
            status_print('Using dataflow detector (static analysis)')
        except Exception as e:
            print(f'Warning: Could not initialize dataflow detector: {e}', file=sys.stderr)
    if hasattr(args, 'semantic') and args.semantic:
        if not SEMANTIC_AVAILABLE:
            print('Warning: Semantic detector requested but dependencies not installed.', file=sys.stderr)
            print('Install with: pip install anthropic openai', file=sys.stderr)
        else:
            try:
                api_key = os.getenv('SG_LLM_API_KEY')
                model = os.getenv('SG_LLM_MODEL') or 'claude-3-5-sonnet-20241022'
                base_url = os.getenv('SG_LLM_BASE_URL')
                api_version = os.getenv('SG_LLM_API_VERSION')
                semantic_detector = LLMEngine(model=model, api_key=api_key, base_url=base_url, api_version=api_version)
                detectors.append(semantic_detector)
                status_print(f'Using semantic detector with model: {model}')
            except Exception as e:
                print(f'Warning: Could not initialize semantic detector: {e}', file=sys.stderr)
    if hasattr(args, 'use_virustotal') and args.use_virustotal:
        vt_api_key = args.vt_api_key or os.getenv('VIRUSTOTAL_API_KEY')
        if not vt_api_key:
            print('Warning: VirusTotal requested but no API key provided.', file=sys.stderr)
            print('Set VIRUSTOTAL_API_KEY environment variable or use --vt-api-key', file=sys.stderr)
        else:
            try:
                from ..engines.virustotal import VirusTotalEngine
                vt_upload = getattr(args, 'vt_upload_files', False)
                vt_detector = VirusTotalEngine(api_key=vt_api_key, enabled=True, upload_files=vt_upload)
                detectors.append(vt_detector)
                mode = 'with file uploads' if vt_upload else 'hash-only mode'
                status_print(f'Using VirusTotal binary file scanner ({mode})')
            except Exception as e:
                print(f'Warning: Could not initialize VirusTotal detector: {e}', file=sys.stderr)
    if hasattr(args, 'use_aidefense') and args.use_aidefense:
        aidefense_api_key = getattr(args, 'aidefense_api_key', None) or os.getenv('AI_DEFENSE_API_KEY')
        if not aidefense_api_key:
            print('Warning: AI Defense requested but no API key provided.', file=sys.stderr)
            print('Set AI_DEFENSE_API_KEY environment variable or use --aidefense-api-key', file=sys.stderr)
        else:
            try:
                from ..engines.aidefense import AIDefenseEngine
                aidefense_api_url = getattr(args, 'aidefense_api_url', None) or os.getenv('AI_DEFENSE_API_URL')
                aidefense_detector = AIDefenseEngine(api_key=aidefense_api_key, api_url=aidefense_api_url)
                detectors.append(aidefense_detector)
                status_print('Using AI Defense detector')
            except Exception as e:
                print(f'Warning: Could not initialize AI Defense detector: {e}', file=sys.stderr)
    if hasattr(args, 'use_description') and args.use_description:
        try:
            from ..engines.description import DescriptionEngine
            description_detector = DescriptionEngine()
            detectors.append(description_detector)
            status_print('Using description detector (specificity analysis)')
        except Exception as e:
            print(f'Warning: Could not initialize description detector: {e}', file=sys.stderr)
    meta_detector = None
    enable_meta = hasattr(args, 'meta') and args.meta
    if enable_meta:
        if not META_AVAILABLE:
            print('Warning: Meta detector requested but dependencies not installed.', file=sys.stderr)
            print('Install with: pip install litellm', file=sys.stderr)
        elif len(detectors) < 2:
            print('Warning: Meta-analysis requires at least 2 detectors. Skipping meta-analysis.', file=sys.stderr)
        else:
            try:
                meta_api_key = os.getenv('SG_META_LLM_API_KEY') or os.getenv('SG_LLM_API_KEY')
                meta_model = os.getenv('SG_META_LLM_MODEL') or os.getenv('SG_LLM_MODEL')
                meta_base_url = os.getenv('SG_META_LLM_BASE_URL') or os.getenv('SG_LLM_BASE_URL')
                meta_api_version = os.getenv('SG_META_LLM_API_VERSION') or os.getenv('SG_LLM_API_VERSION')
                meta_detector = MetaEngine(model=meta_model, api_key=meta_api_key, base_url=meta_base_url, api_version=meta_api_version)
                status_print('Using meta detector for false positive filtering and prioritization')
            except Exception as e:
                print(f'Warning: Could not initialize meta detector: {e}', file=sys.stderr)
    scanner = ScanOrchestrator(engines=detectors)
    try:
        result = scanner.inspect(skill_dir)
        if meta_detector and result.findings:
            status_print('Running meta-analysis to filter false positives...')
            try:
                skill = scanner._ingester.ingest(skill_dir)
                meta_result = asyncio.run(meta_detector.analyze_with_findings(skill=skill, findings=result.findings, engines_used=result.engines_used))
                filtered_findings = apply_meta_filtering(original_findings=result.findings, meta_result=meta_result, skill=skill)
                original_count = len(result.findings)
                result.findings = filtered_findings
                result.engines_used.append('meta_detector')
                fp_count = original_count - len([f for f in filtered_findings if f.engine != 'meta'])
                new_count = len([f for f in filtered_findings if f.engine == 'meta'])
                status_print(f'Meta-analysis complete: {fp_count} false positives filtered, {new_count} new threats detected')
            except Exception as e:
                print(f'Warning: Meta-analysis failed: {e}', file=sys.stderr)
                print('Continuing with original findings.', file=sys.stderr)
        if args.format == 'json':
            reporter = JSONReporter(pretty=not args.compact)
            output = reporter.generate_report(result)
        elif args.format == 'markdown':
            reporter = MarkdownReporter(detailed=args.detailed)
            output = reporter.generate_report(result)
        elif args.format == 'table':
            reporter = TableReporter()
            output = reporter.generate_report(result)
        elif args.format == 'sarif':
            reporter = SARIFReporter()
            output = reporter.generate_report(result)
        else:
            output = generate_summary(result)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f'Report saved to: {args.output}')
        else:
            print(output)
        if not result.is_safe and args.fail_on_findings:
            return 1
        return 0
    except IngestionError as e:
        print(f'Error loading skill: {e}', file=sys.stderr)
        return 1
    except Exception as e:
        print(f'Unexpected error: {e}', file=sys.stderr)
        return 1

def inspect_all_command(args):
    skills_dir = Path(args.skills_directory)
    if not skills_dir.exists():
        print(f'Error: Directory does not exist: {skills_dir}', file=sys.stderr)
        return 1
    yara_mode = getattr(args, 'yara_mode', 'balanced')
    custom_rules_path = getattr(args, 'custom_rules', None)
    disabled_rules = set(getattr(args, 'disabled_rules', None) or [])
    detectors = [PatternEngine(yara_mode=yara_mode, custom_yara_rules_path=custom_rules_path, disabled_rules=disabled_rules)]
    is_json_output = getattr(args, 'format', 'summary') == 'json'

    def status_print(msg: str) -> None:
        if is_json_output:
            print(msg, file=sys.stderr)
        else:
            print(msg)
    if hasattr(args, 'dataflow') and args.dataflow:
        try:
            dataflow_detector = DataflowEngine(use_static_analysis=True)
            detectors.append(dataflow_detector)
            status_print('Using dataflow detector (static analysis)')
        except Exception as e:
            print(f'Warning: Could not initialize dataflow detector: {e}', file=sys.stderr)
    if hasattr(args, 'semantic') and args.semantic and SEMANTIC_AVAILABLE:
        try:
            api_key = os.getenv('SG_LLM_API_KEY')
            model = os.getenv('SG_LLM_MODEL') or 'claude-3-5-sonnet-20241022'
            base_url = os.getenv('SG_LLM_BASE_URL')
            api_version = os.getenv('SG_LLM_API_VERSION')
            semantic_detector = LLMEngine(model=model, api_key=api_key, base_url=base_url, api_version=api_version)
            detectors.append(semantic_detector)
            status_print(f'Using semantic detector with model: {model}')
        except Exception as e:
            print(f'Warning: Could not initialize semantic detector: {e}', file=sys.stderr)
    if hasattr(args, 'use_virustotal') and args.use_virustotal:
        vt_api_key = args.vt_api_key or os.getenv('VIRUSTOTAL_API_KEY')
        vt_upload = getattr(args, 'vt_upload_files', False)
        if not vt_api_key:
            print('Warning: VirusTotal requested but no API key provided.', file=sys.stderr)
            print('Set VIRUSTOTAL_API_KEY environment variable or use --vt-api-key', file=sys.stderr)
        else:
            try:
                from ..engines.virustotal import VirusTotalEngine
                vt_detector = VirusTotalEngine(api_key=vt_api_key, enabled=True, upload_files=vt_upload)
                detectors.append(vt_detector)
                mode = 'with file uploads' if vt_upload else 'hash-only mode'
                status_print(f'Using VirusTotal binary file scanner ({mode})')
            except Exception as e:
                print(f'Warning: Could not initialize VirusTotal detector: {e}', file=sys.stderr)
    if hasattr(args, 'use_aidefense') and args.use_aidefense:
        aidefense_api_key = getattr(args, 'aidefense_api_key', None) or os.getenv('AI_DEFENSE_API_KEY')
        if not aidefense_api_key:
            print('Warning: AI Defense requested but no API key provided.', file=sys.stderr)
            print('Set AI_DEFENSE_API_KEY environment variable or use --aidefense-api-key', file=sys.stderr)
        else:
            try:
                from ..engines.aidefense import AIDefenseEngine
                aidefense_api_url = getattr(args, 'aidefense_api_url', None) or os.getenv('AI_DEFENSE_API_URL')
                aidefense_detector = AIDefenseEngine(api_key=aidefense_api_key, api_url=aidefense_api_url)
                detectors.append(aidefense_detector)
                status_print('Using AI Defense detector')
            except Exception as e:
                print(f'Warning: Could not initialize AI Defense detector: {e}', file=sys.stderr)
    if hasattr(args, 'use_description') and args.use_description:
        try:
            from ..engines.description import DescriptionEngine
            description_detector = DescriptionEngine()
            detectors.append(description_detector)
            status_print('Using description detector (specificity analysis)')
        except Exception as e:
            print(f'Warning: Could not initialize description detector: {e}', file=sys.stderr)
    meta_detector = None
    enable_meta = hasattr(args, 'meta') and args.meta
    if enable_meta:
        if not META_AVAILABLE:
            print('Warning: Meta detector requested but dependencies not installed.', file=sys.stderr)
            print('Install with: pip install litellm', file=sys.stderr)
        elif len(detectors) < 2:
            print('Warning: Meta-analysis requires at least 2 detectors. Skipping meta-analysis.', file=sys.stderr)
        else:
            try:
                meta_api_key = os.getenv('SG_META_LLM_API_KEY') or os.getenv('SG_LLM_API_KEY')
                meta_model = os.getenv('SG_META_LLM_MODEL') or os.getenv('SG_LLM_MODEL')
                meta_base_url = os.getenv('SG_META_LLM_BASE_URL') or os.getenv('SG_LLM_BASE_URL')
                meta_api_version = os.getenv('SG_META_LLM_API_VERSION') or os.getenv('SG_LLM_API_VERSION')
                meta_detector = MetaEngine(model=meta_model, api_key=meta_api_key, base_url=meta_base_url, api_version=meta_api_version)
                status_print('Using meta detector for false positive filtering and prioritization')
            except Exception as e:
                print(f'Warning: Could not initialize meta detector: {e}', file=sys.stderr)
    scanner = ScanOrchestrator(engines=detectors)
    try:
        check_overlap = hasattr(args, 'check_overlap') and args.check_overlap
        report = scanner.inspect_directory(skills_dir, recursive=args.recursive, check_overlap=check_overlap)
        if report.total_skills_scanned == 0:
            print('No skills found to scan.', file=sys.stderr)
            return 1
        if meta_detector:
            status_print('Running meta-analysis on scan results...')
            total_fp_filtered = 0
            total_new_threats = 0
            for result in report.scan_results:
                if result.findings:
                    try:
                        skill_dir = Path(result.skill_directory)
                        skill = scanner._ingester.ingest(skill_dir)
                        meta_result = asyncio.run(meta_detector.analyze_with_findings(skill=skill, findings=result.findings, engines_used=result.engines_used))
                        original_count = len(result.findings)
                        filtered_findings = apply_meta_filtering(original_findings=result.findings, meta_result=meta_result, skill=skill)
                        fp_count = original_count - len([f for f in filtered_findings if f.engine != 'meta'])
                        new_count = len([f for f in filtered_findings if f.engine == 'meta'])
                        total_fp_filtered += fp_count
                        total_new_threats += new_count
                        result.findings = filtered_findings
                        result.engines_used.append('meta_detector')
                    except Exception as e:
                        print(f'Warning: Meta-analysis failed for {result.skill_name}: {e}', file=sys.stderr)
            status_print(f'Meta-analysis complete: {total_fp_filtered} total false positives filtered, {total_new_threats} new threats detected')
            report.total_findings = sum((len(r.findings) for r in report.scan_results))
            report.critical_count = sum((1 for r in report.scan_results for f in r.findings if f.severity.value == 'CRITICAL'))
            report.high_count = sum((1 for r in report.scan_results for f in r.findings if f.severity.value == 'HIGH'))
            report.medium_count = sum((1 for r in report.scan_results for f in r.findings if f.severity.value == 'MEDIUM'))
            report.low_count = sum((1 for r in report.scan_results for f in r.findings if f.severity.value == 'LOW'))
            report.info_count = sum((1 for r in report.scan_results for f in r.findings if f.severity.value == 'INFO'))
            report.safe_count = sum((1 for r in report.scan_results if r.is_safe))
        if args.format == 'json':
            reporter = JSONReporter(pretty=not args.compact)
            output = reporter.generate_report(report)
        elif args.format == 'markdown':
            reporter = MarkdownReporter(detailed=args.detailed)
            output = reporter.generate_report(report)
        elif args.format == 'table':
            reporter = TableReporter()
            output = reporter.generate_report(report)
        elif args.format == 'sarif':
            reporter = SARIFReporter()
            output = reporter.generate_report(report)
        else:
            output = generate_multi_skill_summary(report)
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(output)
            print(f'Report saved to: {args.output}')
        else:
            print(output)
        if args.fail_on_findings and (report.critical_count > 0 or report.high_count > 0):
            return 1
        return 0
    except Exception as e:
        print(f'Unexpected error: {e}', file=sys.stderr)
        return 1

def list_engines_command(args):
    print('Available Detectors:')
    print('')
    print('1. pattern_detector (Default)')
    print('   - Pattern-based detection using YAML + YARA rules')
    print('   - Scans SKILL.md instructions and scripts')
    print('   - Detects 80+ security patterns across 12+ threat categories')
    print('')
    print('2. dataflow_detector [OK] Available')
    print('   - Static dataflow analysis (AST + taint tracking)')
    print('   - Tracks data from sources to sinks without execution')
    print('   - Detects multi-file exfiltration chains')
    print('   - Cross-file correlation analysis')
    print('   - Usage: --use-dataflow (alias: --use-behavioral)')
    print('')
    print('3. virustotal_detector [OK] Available (optional)')
    print('   - Scans binary files (images, PDFs, archives) using VirusTotal')
    print('   - Hash-based malware detection via VirusTotal API')
    print('   - Excludes code files (.py, .js, .md, etc.)')
    print('   - Requires VirusTotal API key')
    print('   - Usage: --use-virustotal --vt-api-key YOUR_KEY')
    print('')
    print('4. aidefense_detector [OK] Available (optional)')
    print('   - Enterprise-grade threat detection via SkillsGuard AI Defense API')
    print('   - Analyzes prompts, instructions, markdown, and code files')
    print('   - Detects prompt injection, data exfiltration, tool poisoning')
    print('   - Requires SkillsGuard AI Defense API key')
    print('   - Usage: --use-aidefense --aidefense-api-key YOUR_KEY')
    print('')
    if SEMANTIC_AVAILABLE:
        print('5. semantic_detector [OK] Available')
        print('   - Semantic analysis using LLMs as judges')
        print('   - Context-aware threat detection')
        print('   - Understands code intent beyond patterns')
        print('   - Usage: --use-semantic (alias: --use-llm)')
        print('')
    else:
        print('5. semantic_detector [WARNING] Not installed')
        print('   - Install with: pip install litellm anthropic openai')
        print('')
    print('6. description_detector [OK] Available')
    print('   - Detects overly generic skill descriptions')
    print('   - Identifies trigger hijacking risks')
    print('   - Checks description specificity and keyword baiting')
    print('   - Usage: --use-description (alias: --use-trigger)')
    print('')
    if META_AVAILABLE:
        print('7. meta_detector [OK] Available')
        print('   - Second-pass LLM analysis on findings from other detectors')
        print('   - Filters false positives using contextual understanding')
        print('   - Prioritizes findings by actual exploitability')
        print('   - Detects threats other detectors missed')
        print('   - Usage: --enable-meta (requires 2+ detectors)')
        print('')
    else:
        print('7. meta_detector [WARNING] Not installed')
        print('   - Install with: pip install litellm')
        print('')
    print('Future Detectors (not yet implemented):')
    print('  - policy_checker: Organization-specific policy validation')
    print('  - runtime_monitor: Live execution monitoring (sandbox)')
    print('')
    return 0

def list_engines_command(args):
    return list_engines_command(args)

def validate_command(args):
    from ..rules.patterns import RuleLoader
    try:
        if args.rules_file:
            loader = RuleLoader(Path(args.rules_file))
        else:
            loader = RuleLoader()
        rules = loader.load_rules()
        print(f'[OK] Successfully loaded {len(rules)} rules')
        print('')
        print('Rules by category:')
        for category, category_rules in loader.rules_by_category.items():
            print(f'  - {category.value}: {len(category_rules)} rules')
        return 0
    except Exception as e:
        print(f'[FAIL] Error validating rules: {e}', file=sys.stderr)
        return 1

def generate_summary(result) -> str:
    lines = []
    lines.append('=' * 60)
    lines.append(f'Skill: {result.skill_name}')
    lines.append('=' * 60)
    lines.append(f'Status: {('[OK] SAFE' if result.is_safe else '[FAIL] ISSUES FOUND')}')
    lines.append(f'Max Severity: {result.max_severity.value}')
    lines.append(f'Total Findings: {len(result.findings)}')
    lines.append(f'Scan Duration: {result.scan_duration_seconds:.2f}s')
    lines.append('')
    if result.findings:
        from ..models import Severity
        lines.append('Findings Summary:')
        lines.append(f'  Critical: {len(result.filter_by_risk(Severity.CRITICAL))}')
        lines.append(f'  High:     {len(result.filter_by_risk(Severity.HIGH))}')
        lines.append(f'  Medium:   {len(result.filter_by_risk(Severity.MEDIUM))}')
        lines.append(f'  Low:      {len(result.filter_by_risk(Severity.LOW))}')
        lines.append(f'  Info:     {len(result.filter_by_risk(Severity.INFO))}')
    return '\n'.join(lines)

def generate_multi_skill_summary(report) -> str:
    lines = []
    lines.append('=' * 60)
    lines.append('Agent Skills Security Scan Report')
    lines.append('=' * 60)
    lines.append(f'Skills Scanned: {report.total_skills_scanned}')
    lines.append(f'Safe Skills: {report.safe_count}')
    lines.append(f'Total Findings: {report.total_findings}')
    lines.append('')
    lines.append('Findings by Severity:')
    lines.append(f'  Critical: {report.critical_count}')
    lines.append(f'  High:     {report.high_count}')
    lines.append(f'  Medium:   {report.medium_count}')
    lines.append(f'  Low:      {report.low_count}')
    lines.append(f'  Info:     {report.info_count}')
    lines.append('')
    lines.append('Individual Skills:')
    for result in report.scan_results:
        status = '[OK]' if result.is_safe else '[FAIL]'
        lines.append(f'  {status} {result.skill_name} - {len(result.findings)} findings ({result.max_severity.value})')
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description='Skill Scanner - Security scanner for agent skills packages', formatter_class=argparse.RawDescriptionHelpFormatter, epilog='\nExamples:\n  # Scan a single skill\n  skill-scanner scan /path/to/skill\n\n  # Scan with dataflow analysis\n  skill-scanner scan /path/to/skill --use-dataflow\n\n  # Scan with all detectors (pattern + dataflow + semantic)\n  skill-scanner scan /path/to/skill --use-dataflow --use-semantic\n\n  # Scan with JSON output\n  skill-scanner scan /path/to/skill --format json\n\n  # Scan all skills in a directory\n  skill-scanner scan-all /path/to/skills\n\n  # Scan recursively with all detectors\n  skill-scanner scan-all /path/to/skills --recursive --use-dataflow --use-semantic\n\n  # List available detectors\n  skill-scanner list-detectors\n\n  # Validate rule signatures\n  skill-scanner validate-rules\n        ')
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    scan_parser = subparsers.add_parser('inspect', help='Scan a single skill package')
    scan_parser.add_argument('skill_directory', help='Path to skill directory')
    scan_parser.add_argument('--format', choices=['summary', 'json', 'markdown', 'table', 'sarif'], default='summary', help="Output format (default: summary). Use 'sarif' for GitHub Code Scanning integration.")
    scan_parser.add_argument('--output', '-o', help='Output file path')
    scan_parser.add_argument('--detailed', action='store_true', help='Include detailed findings')
    scan_parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    scan_parser.add_argument('--fail-on-findings', action='store_true', help='Exit with error code if critical/high findings exist')
    scan_parser.add_argument('--dataflow', '--use-dataflow, dest='dataflow', action='store_true', help='Enable dataflow detector (alias: --use-behavioral)')
    scan_parser.add_argument('--llm', '--use-semantic, dest='semantic', action='store_true', help='Enable semantic detector (requires API key)')
    scan_parser.add_argument('--use-virustotal', action='store_true', help='Enable VirusTotal detector (requires API key)')
    scan_parser.add_argument('--vt-api-key', help='VirusTotal API key (or set VIRUSTOTAL_API_KEY environment variable)')
    scan_parser.add_argument('--vt-upload-files', action='store_true', help='Upload unknown files to VirusTotal (default: hash-only lookup for privacy)')
    scan_parser.add_argument('--use-aidefense', action='store_true', help='Enable AI Defense detector (requires API key)')
    scan_parser.add_argument('--aidefense-api-key', help='AI Defense API key (or set AI_DEFENSE_API_KEY environment variable)')
    scan_parser.add_argument('--aidefense-api-url', help='AI Defense API URL (optional, defaults to US region)')
    scan_parser.add_argument('--llm-provider', choices=['anthropic', 'openai'], default='anthropic', help='LLM provider (default: anthropic)')
    scan_parser.add_argument('--use-description', '--use-trigger', dest='use_description', action='store_true', help='Enable description detector (detects overly generic descriptions)')
    scan_parser.add_argument('--meta', action='store_true', help='Enable meta-analysis for false positive filtering and finding prioritization (requires 2+ detectors including semantic)')
    scan_parser.add_argument('--yara-mode', choices=['strict', 'balanced', 'permissive'], default='balanced', help='YARA detection mode: strict (max security, more FPs), balanced (default), permissive (fewer FPs, may miss threats)')
    scan_parser.add_argument('--custom-rules', metavar='PATH', help='Path to directory containing custom YARA rules (.yara files) to use instead of built-in rules')
    scan_parser.add_argument('--disable-rule', action='append', metavar='RULE_NAME', dest='disabled_rules', help='Disable a specific rule by name (can be used multiple times). Example: --disable-rule YARA_script_injection')
    scan_all_parser = subparsers.add_parser('inspect-all', help='Scan multiple skill packages')
    scan_all_parser.add_argument('skills_directory', help='Directory containing skills')
    scan_all_parser.add_argument('--recursive', '-r', action='store_true', help='Recursively search for skills')
    scan_all_parser.add_argument('--format', choices=['summary', 'json', 'markdown', 'table', 'sarif'], default='summary', help="Output format (default: summary). Use 'sarif' for GitHub Code Scanning integration.")
    scan_all_parser.add_argument('--output', '-o', help='Output file path')
    scan_all_parser.add_argument('--detailed', action='store_true', help='Include detailed findings')
    scan_all_parser.add_argument('--compact', action='store_true', help='Compact JSON output')
    scan_all_parser.add_argument('--fail-on-findings', action='store_true', help='Exit with error code if any critical/high findings exist')
    scan_all_parser.add_argument('--dataflow', '--use-dataflow, dest='dataflow', action='store_true', help='Enable dataflow detector (alias: --use-behavioral)')
    scan_all_parser.add_argument('--llm', '--use-semantic, dest='semantic', action='store_true', help='Enable semantic detector (requires API key)')
    scan_all_parser.add_argument('--use-virustotal', action='store_true', help='Enable VirusTotal detector (requires API key)')
    scan_all_parser.add_argument('--vt-api-key', help='VirusTotal API key (or set VIRUSTOTAL_API_KEY environment variable)')
    scan_all_parser.add_argument('--vt-upload-files', action='store_true', help='Upload unknown files to VirusTotal (default: hash-only lookup for privacy)')
    scan_all_parser.add_argument('--use-aidefense', action='store_true', help='Enable AI Defense detector (requires API key)')
    scan_all_parser.add_argument('--aidefense-api-key', help='AI Defense API key (or set AI_DEFENSE_API_KEY environment variable)')
    scan_all_parser.add_argument('--aidefense-api-url', help='AI Defense API URL (optional, defaults to US region)')
    scan_all_parser.add_argument('--llm-provider', choices=['anthropic', 'openai'], default='anthropic', help='LLM provider (default: anthropic)')
    scan_all_parser.add_argument('--use-description', '--use-trigger', dest='use_description', action='store_true', help='Enable description detector (detects overly generic descriptions)')
    scan_all_parser.add_argument('--check-overlap', action='store_true', help='Enable cross-skill description overlap detection')
    scan_all_parser.add_argument('--meta', action='store_true', help='Enable meta-analysis for false positive filtering and finding prioritization (requires 2+ detectors including semantic)')
    scan_all_parser.add_argument('--yara-mode', choices=['strict', 'balanced', 'permissive'], default='balanced', help='YARA detection mode: strict (max security, more FPs), balanced (default), permissive (fewer FPs, may miss threats)')
    scan_all_parser.add_argument('--custom-rules', metavar='PATH', help='Path to directory containing custom YARA rules (.yara files) to use instead of built-in rules')
    scan_all_parser.add_argument('--disable-rule', action='append', metavar='RULE_NAME', dest='disabled_rules', help='Disable a specific rule by name (can be used multiple times). Example: --disable-rule YARA_script_injection')
    subparsers.add_parser('engines', help='List available detectors')
    subparsers.add_parser('engines', help='List available analyzers (legacy)')
    validate_parser = subparsers.add_parser('validate-rules', help='Validate rule signatures')
    validate_parser.add_argument('--rules-file', help='Path to custom rules file')
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1
    if args.command == 'inspect':
        return inspect_command(args)
    elif args.command == 'inspect-all':
        return inspect_all_command(args)
    elif args.command == 'engines':
        return list_engines_command(args)
    elif args.command == 'engines':
        return list_engines_command(args)
    elif args.command == 'validate-rules':
        return validate_command(args)
    else:
        parser.print_help()
        return 1
if __name__ == '__main__':
    sys.exit(main())
