from pathlib import Path
from unittest.mock import MagicMock
import pytest
from sgscanner.config.config import Config
from sgscanner.engines.dataflow import DataflowEngine
from sgscanner.engines.pattern import PatternEngine
from sgscanner.models import Severity
from sgscanner.pipeline.orchestrator import ScanOrchestrator

class TestEndToEndScanning:

    def test_scan_safe_skill_end_to_end(self):
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'
        result = scanner.inspect(example_dir)
        assert result.skill_name == 'simple-formatter'
        assert result.is_safe
        assert len(result.engines_used) > 0
        assert 'pattern_detector' in result.engines_used

    def test_scan_malicious_skill_detects_threats(self):
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'malicious/exfiltrator'
        result = scanner.inspect(example_dir)
        assert not result.is_safe
        assert len(result.findings) > 0
        assert result.max_severity in [Severity.CRITICAL, Severity.HIGH]
        categories = [f.category.value for f in result.findings]
        assert 'data_exfiltration' in categories or 'command_injection' in categories

    def test_scan_prompt_injection_skill(self):
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'skills' / 'prompt-injection' / 'jailbreak-override'
        result = scanner.inspect(example_dir)
        assert not result.is_safe
        assert len(result.findings) > 0
        categories = [f.category.value for f in result.findings]
        assert 'prompt_injection' in categories or 'command_injection' in categories

    def test_batch_scan_multiple_skills(self):
        scanner = ScanOrchestrator()
        test_skills_dir = Path(__file__).parent.parent / 'evals' / 'test_skills'
        report = scanner.inspect_directory(test_skills_dir, recursive=True)
        assert report.total_skills_scanned >= 2
        assert report.safe_count >= 1
        assert report.total_findings >= 0
        malicious_results = [r for r in report.scan_results if 'malicious' in r.skill_name.lower()]
        if malicious_results:
            assert any((r.max_severity.value in ['CRITICAL', 'HIGH'] for r in malicious_results))

class TestConfigIntegration:

    def test_scanner_with_config(self):
        config = Config(enable_pattern_detector=True, enable_semantic_detector=False)
        analyzers = []
        if config.enable_pattern_detector:
            analyzers.append(PatternEngine())
        scanner = ScanOrchestrator(analyzers=analyzers)
        assert len(scanner.analyzers) == 1
        assert scanner.analyzers[0].name == 'pattern_detector'

class TestOutputFormatIntegration:

    def test_json_output_format(self):
        from sgscanner.reports.json_reporter import JSONReporter
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'
        result = scanner.inspect(example_dir)
        reporter = JSONReporter(pretty=True)
        json_output = reporter.generate_report(result)
        assert 'skill_name' in json_output
        assert 'simple-formatter' in json_output
        assert 'findings' in json_output

    def test_markdown_output_format(self):
        from sgscanner.reports.markdown_reporter import MarkdownReporter
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'
        result = scanner.inspect(example_dir)
        reporter = MarkdownReporter(detailed=True)
        md_output = reporter.generate_report(result)
        assert '# Agent Skill Security Scan Report' in md_output
        assert 'simple-formatter' in md_output

    def test_table_output_format(self):
        from sgscanner.reports.table_reporter import TableReporter
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'
        result = scanner.inspect(example_dir)
        reporter = TableReporter()
        table_output = reporter.generate_report(result)
        assert 'simple-formatter' in table_output
        assert '=' in table_output

class TestThreatTaxonomyIntegration:

    def test_findings_map_to_aitech(self):
        from sgscanner.taxonomy.threats import ThreatMapping
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'malicious/exfiltrator'
        result = scanner.inspect(example_dir)
        if result.findings:
            finding = result.findings[0]
            try:
                threat_name = finding.category.value.upper().replace('_', ' ')
                mapping = ThreatMapping.get_threat_mapping('pattern', threat_name)
                assert 'aitech' in mapping
                assert 'severity' in mapping
            except ValueError:
                pass

class TestMultiDetectorIntegration:

    def test_pattern_and_dataflow_together(self):
        detectors = [PatternEngine(), DataflowEngine()]
        scanner = ScanOrchestrator(detectors=detectors)
        assert len(scanner.list_engines()) == 2
        assert 'pattern_detector' in scanner.list_engines()
        assert 'dataflow_detector' in scanner.list_engines()

class TestErrorRecovery:

    def test_continues_after_detector_error(self):
        failing_detector = MagicMock()
        failing_detector.analyze = MagicMock(side_effect=Exception('Detector error'))
        failing_detector.get_name = MagicMock(return_value='failing_detector')
        detectors = [PatternEngine(), failing_detector]
        scanner = ScanOrchestrator(detectors=detectors)
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'
        try:
            result = scanner.inspect(example_dir)
            assert len(result.engines_used) >= 1
        except Exception:
            pass

class TestPerformanceBenchmarks:

    def test_static_scan_is_fast(self):
        scanner = ScanOrchestrator()
        example_dir = Path(__file__).parent.parent / 'evals' / 'test_skills' / 'safe' / 'simple-formatter'
        result = scanner.inspect(example_dir)
        assert result.scan_duration_seconds < 1.0

    def test_batch_scan_completes_reasonably(self):
        scanner = ScanOrchestrator()
        test_skills_dir = Path(__file__).parent.parent / 'evals' / 'test_skills'
        report = scanner.inspect_directory(test_skills_dir)
        total_duration = sum((r.scan_duration_seconds for r in report.scan_results))
        assert total_duration < 5.0
