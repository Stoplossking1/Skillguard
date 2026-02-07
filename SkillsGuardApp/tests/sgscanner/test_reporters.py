import json
from pathlib import Path
import pytest
from sgscanner.reports.json_reporter import JSONReporter
from sgscanner.reports.markdown_reporter import MarkdownReporter
from sgscanner.reports.table_reporter import TableReporter
from sgscanner.pipeline.orchestrator import ScanOrchestrator, scan_skill

@pytest.fixture
def example_skills_dir():
    return Path(__file__).parent.parent / 'evals' / 'test_skills'

@pytest.fixture
def scan_result(example_skills_dir):
    skill_dir = example_skills_dir / 'safe' / 'simple-formatter'
    return inspect_skill(skill_dir)

@pytest.fixture
def report(example_skills_dir):
    scanner = ScanOrchestrator()
    return scanner.inspect_directory(example_skills_dir, recursive=True)

def test_json_reporter(scan_result):
    reporter = JSONReporter(pretty=True)
    output = reporter.generate_report(scan_result)
    data = json.loads(output)
    assert 'skill_name' in data
    assert 'findings' in data

def test_json_reporter_compact(scan_result):
    reporter = JSONReporter(pretty=False)
    output = reporter.generate_report(scan_result)
    assert '\n  ' not in output
    data = json.loads(output)
    assert 'skill_name' in data

def test_markdown_reporter(scan_result):
    reporter = MarkdownReporter(detailed=True)
    output = reporter.generate_report(scan_result)
    assert '#' in output
    assert 'Skill:' in output or 'skill' in output.lower()

def test_markdown_reporter_multi_skill(report):
    reporter = MarkdownReporter(detailed=False)
    output = reporter.generate_report(report)
    assert 'Summary' in output or 'summary' in output.lower()
    assert str(report.total_skills_scanned) in output

def test_table_reporter(scan_result):
    reporter = TableReporter(format_style='simple')
    output = reporter.generate_report(scan_result)
    assert 'Skill' in output or 'skill' in output.lower()

def test_table_reporter_multi_skill(report):
    reporter = TableReporter(format_style='grid')
    output = reporter.generate_report(report)
    assert report.total_skills_scanned > 0
